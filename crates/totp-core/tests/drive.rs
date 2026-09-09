//! El backend de Drive contra un doble del `appDataFolder`.
//!
//! El doble habla el mismo dialecto que la API de verdad —multipart para
//! crear, `alt=media` para descargar, `If-Match` para el compare-and-set,
//! `pageToken` para paginar— y permite lo que la API permite y aquí importa:
//! que dos clientes escriban a la vez, que un fichero se duplique de nombre y
//! que el servidor devuelva errores.

use std::cell::RefCell;
use std::rc::Rc;

use totp_core::Error;
use totp_core::crypto::{KdfParams, SecretKey};
use totp_core::http::{HttpClient, Method, Request, Response};
use totp_core::sync::{
    DriveStore, HeadUpdate, HeaderStatus, MemoryStore, ObjectId, ObjectStore, Repo, get_verified,
    sync,
};
use totp_core::vault::{Entry, EntryId, VaultHeader};

const TEST_KDF: KdfParams = KdfParams {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

fn block_on<T>(future: impl Future<Output = T>) -> T {
    pollster::block_on(future)
}

fn master_key() -> SecretKey {
    let (_, mk, _) = VaultHeader::create(b"correct horse", TEST_KDF).unwrap();
    mk
}

fn entry(issuer: &str) -> Entry {
    Entry::new(
        issuer,
        "joshua@germade.es",
        b"12345678901234567890".to_vec(),
    )
}

// --- El doble del appDataFolder --------------------------------------------

#[derive(Clone, Debug)]
struct StoredFile {
    id: String,
    name: String,
    revision: u32,
    content: Vec<u8>,
}

impl StoredFile {
    fn revision_id(&self) -> String {
        format!("r{}", self.revision)
    }

    fn json(&self) -> String {
        format!(
            r#"{{"id":"{}","name":"{}","headRevisionId":"{}"}}"#,
            self.id,
            self.name,
            self.revision_id()
        )
    }
}

#[derive(Debug)]
struct Server {
    files: Vec<StoredFile>,
    next_id: u32,
    /// Cuántas peticiones ha visto. Lo que se mide con esto es el coste en
    /// llamadas, que en Drive es lo que se paga.
    calls: usize,
    /// Un servidor que respeta `If-Match`. Ponerlo a `false` es el escenario
    /// pesimista del roadmap: la API ignora la precondición.
    honours_if_match: bool,
    /// Página pequeña para forzar la paginación.
    page_size: usize,
    /// Error a devolver en la siguiente petición.
    fail_next: Option<(u16, String)>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            next_id: 1,
            calls: 0,
            honours_if_match: true,
            page_size: 100,
            fail_next: None,
        }
    }
}

impl Server {
    fn create(&mut self, name: &str, content: Vec<u8>) -> StoredFile {
        let file = StoredFile {
            id: format!("f{:04}", self.next_id),
            name: name.to_string(),
            revision: 1,
            content,
        };
        self.next_id += 1;
        self.files.push(file.clone());
        file
    }

    fn file(&self, id: &str) -> Option<&StoredFile> {
        self.files.iter().find(|file| file.id == id)
    }

    fn count_named(&self, name: &str) -> usize {
        self.files.iter().filter(|file| file.name == name).count()
    }
}

/// Cliente HTTP que habla con un `Server` compartido. Dos dispositivos usan dos
/// clientes distintos contra el mismo servidor, cada uno con su propio índice.
#[derive(Clone, Debug)]
struct FakeDrive(Rc<RefCell<Server>>);

impl FakeDrive {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(Server::default())))
    }

    fn server(&self) -> std::cell::RefMut<'_, Server> {
        self.0.borrow_mut()
    }

    fn store(&self) -> DriveStore<FakeDrive> {
        DriveStore::new(self.clone())
    }
}

impl HttpClient for FakeDrive {
    async fn send(&self, request: Request) -> totp_core::Result<Response> {
        let mut server = self.0.borrow_mut();
        server.calls += 1;

        if let Some((status, body)) = server.fail_next.take() {
            return Ok(Response::new(status, body.into_bytes()));
        }

        let (path, query) = split_url(&request.url);
        let upload = path.strip_prefix("https://www.googleapis.com/upload/drive/v3/files");
        let files = path.strip_prefix("https://www.googleapis.com/drive/v3/files");

        let response = match (request.method, upload, files) {
            // Crear un fichero con metadatos y contenido en una sola llamada.
            (Method::Post, Some(""), _) => {
                let (name, content) = parse_multipart(
                    request.header_value("Content-Type").expect("content-type"),
                    request.body.as_deref().expect("cuerpo"),
                );
                let file = server.create(&name, content);
                Response::new(200, file.json().into_bytes())
            }

            // Reemplazar el contenido, con precondición.
            (Method::Patch, Some(rest), _) => {
                let id = rest.trim_start_matches('/').to_string();
                let expected = request.header_value("If-Match").map(str::to_string);
                let body = request.body.clone().expect("cuerpo");
                let honours = server.honours_if_match;

                match server.files.iter_mut().find(|file| file.id == id) {
                    None => Response::new(404, b"{}".to_vec()),
                    Some(file) => {
                        if honours && expected.as_deref() != Some(&file.revision_id()) {
                            Response::new(412, br#"{"error":"precondition"}"#.to_vec())
                        } else {
                            file.revision += 1;
                            file.content = body;
                            Response::new(200, file.json().into_bytes())
                        }
                    }
                }
            }

            // Listado, con filtro opcional por nombre y paginación.
            (Method::Get, _, Some("")) => {
                let name = query_value(&query, "q").and_then(|q| {
                    q.split_once("name = '")
                        .map(|(_, rest)| rest.split('\'').next().unwrap_or("").to_string())
                });

                let matching: Vec<StoredFile> = server
                    .files
                    .iter()
                    .filter(|file| name.as_ref().is_none_or(|name| &file.name == name))
                    .cloned()
                    .collect();

                let from: usize = query_value(&query, "pageToken")
                    .and_then(|token| token.parse().ok())
                    .unwrap_or(0);
                let to = (from + server.page_size).min(matching.len());

                let page: Vec<String> = matching[from..to].iter().map(StoredFile::json).collect();
                let next = if to < matching.len() {
                    format!(r#""nextPageToken":"{to}","#)
                } else {
                    String::new()
                };

                Response::new(
                    200,
                    format!("{{{next}\"files\":[{}]}}", page.join(",")).into_bytes(),
                )
            }

            // Contenido o metadatos de un fichero concreto.
            (Method::Get, _, Some(rest)) => {
                let id = rest.trim_start_matches('/');
                match server.file(id) {
                    None => Response::new(404, br#"{"error":"not found"}"#.to_vec()),
                    Some(file) if query_value(&query, "alt").as_deref() == Some("media") => {
                        Response::new(200, file.content.clone())
                    }
                    Some(file) => Response::new(200, file.json().into_bytes()),
                }
            }

            other => panic!("el doble no conoce esta ruta: {other:?} — {}", request.url),
        };

        Ok(response)
    }
}

fn split_url(url: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let params = query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (decode(key), decode(value))
        })
        .collect();
    (path.to_string(), params)
}

fn query_value(query: &[(String, String)], key: &str) -> Option<String> {
    query
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).expect("escape hex"));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("query utf-8")
}

/// Saca el nombre y el contenido de un cuerpo `multipart/related`.
fn parse_multipart(content_type: &str, body: &[u8]) -> (String, Vec<u8>) {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("boundary")
        .to_string();
    let separator = format!("\r\n--{boundary}");

    let json_start = find(body, b"\r\n\r\n").expect("cabeceras de la parte json") + 4;
    let json_end = json_start + find(&body[json_start..], separator.as_bytes()).expect("separador");
    let metadata = std::str::from_utf8(&body[json_start..json_end]).expect("json utf-8");
    let name = metadata
        .split_once(r#""name":""#)
        .expect("nombre")
        .1
        .split('"')
        .next()
        .expect("nombre cerrado")
        .to_string();

    let rest = &body[json_end..];
    let content_start = find(rest, b"\r\n\r\n").expect("cabeceras de la parte binaria") + 4;
    let content_end =
        content_start + find(&rest[content_start..], separator.as_bytes()).expect("cierre");

    (name, rest[content_start..content_end].to_vec())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// --- Tests -----------------------------------------------------------------

#[test]
fn an_object_survives_the_round_trip() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut store = drive.store();
        let id = ObjectId::of(b"un objeto cifrado");

        assert!(!store.contains(&id).await.unwrap());
        store.put(&id, b"un objeto cifrado").await.unwrap();

        assert!(store.contains(&id).await.unwrap());
        assert_eq!(
            get_verified(&store, &id).await.unwrap(),
            b"un objeto cifrado"
        );
        assert_eq!(drive.server().count_named(&id.to_hex()), 1);
    });
}

#[test]
fn an_object_already_there_is_not_uploaded_again() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut store = drive.store();
        let id = ObjectId::of(b"a");

        store.put(&id, b"a").await.unwrap();
        let after_first = drive.server().calls;
        store.put(&id, b"a").await.unwrap();

        // La segunda vez no cuesta ni una llamada: el nombre es el hash.
        assert_eq!(drive.server().calls, after_first);
        assert_eq!(drive.server().count_named(&id.to_hex()), 1);
    });
}

#[test]
fn an_object_the_server_tampered_with_is_rejected() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut store = drive.store();
        let id = ObjectId::of(b"contenido");
        store.put(&id, b"contenido").await.unwrap();

        drive.server().files[0].content[0] ^= 1;

        assert_eq!(get_verified(&store, &id).await, Err(Error::CorruptObject));
    });
}

#[test]
fn the_head_moves_only_with_the_right_revision() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut store = drive.store();
        let a = ObjectId::of(b"a");
        let b = ObjectId::of(b"b");

        assert_eq!(store.head().await.unwrap(), None);

        let HeadUpdate::Updated(token) = store.set_head(None, a).await.unwrap() else {
            panic!("debería haber creado el head");
        };
        assert_eq!(store.head().await.unwrap().unwrap().commit, a);

        // Otro cliente que aún cree que no hay head no lo pisa.
        assert_eq!(store.set_head(None, b).await.unwrap(), HeadUpdate::Conflict);
        // Ni uno con una revisión vieja.
        assert_eq!(
            store.set_head(Some("r0"), b).await.unwrap(),
            HeadUpdate::Conflict
        );
        assert_eq!(store.head().await.unwrap().unwrap().commit, a);

        assert!(matches!(
            store.set_head(Some(&token), b).await.unwrap(),
            HeadUpdate::Updated(_)
        ));
        assert_eq!(store.head().await.unwrap().unwrap().commit, b);
        // Mover el head no crea ficheros nuevos.
        assert_eq!(drive.server().count_named("head"), 1);
    });
}

#[test]
fn a_server_that_ignores_if_match_still_loses_the_race() {
    block_on(async {
        let drive = FakeDrive::new();
        drive.server().honours_if_match = false;

        let mut ana = drive.store();
        let mut bruno = drive.store();
        let first = ObjectId::of(b"primero");
        let second = ObjectId::of(b"segundo");
        let third = ObjectId::of(b"tercero");

        ana.set_head(None, first).await.unwrap();

        // Ana lee el head y, antes de publicar, Bruno lo mueve.
        let token = ana.head().await.unwrap().unwrap().token;
        bruno.head().await.unwrap();
        let bruno_token = bruno.head().await.unwrap().unwrap().token;
        bruno.set_head(Some(&bruno_token), second).await.unwrap();

        // Aunque el servidor no mire el If-Match, la comprobación previa de la
        // revisión evita que Ana pise el commit de Bruno.
        assert_eq!(
            ana.set_head(Some(&token), third).await.unwrap(),
            HeadUpdate::Conflict
        );
        assert_eq!(ana.head().await.unwrap().unwrap().commit, second);
    });
}

#[test]
fn the_log_is_one_file_per_commit_and_never_repeats() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut store = drive.store();
        let a = ObjectId::of(b"a");
        let b = ObjectId::of(b"b");

        store.append_known_commit(a).await.unwrap();
        store.append_known_commit(a).await.unwrap();
        store.append_known_commit(b).await.unwrap();

        let mut commits = store.known_commits().await.unwrap();
        commits.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(commits, expected);

        // Un fichero por línea: nadie reescribe el log, así que dos clientes
        // que anoten a la vez no se pisan.
        assert_eq!(drive.server().files.len(), 2);
    });
}

#[test]
fn a_log_written_by_another_client_is_visible_after_refreshing() {
    block_on(async {
        let drive = FakeDrive::new();
        let ana = drive.store();
        let mut bruno = drive.store();
        let a = ObjectId::of(b"a");

        ana.known_commits().await.unwrap(); // fija el índice de Ana
        bruno.append_known_commit(a).await.unwrap();

        assert_eq!(ana.known_commits().await.unwrap(), vec![]);
        ana.refresh().await.unwrap();
        assert_eq!(ana.known_commits().await.unwrap(), vec![a]);
    });
}

#[test]
fn the_listing_is_paged() {
    block_on(async {
        let drive = FakeDrive::new();
        drive.server().page_size = 2;
        let mut store = drive.store();

        let ids: Vec<ObjectId> = (0..7u8).map(|n| ObjectId::of(&[n])).collect();
        for (n, id) in ids.iter().enumerate() {
            store.put(id, &[n as u8]).await.unwrap();
        }

        let fresh = drive.store();
        for id in &ids {
            assert!(fresh.contains(id).await.unwrap());
        }
    });
}

#[test]
fn a_quota_error_surfaces_as_a_storage_failure() {
    block_on(async {
        let drive = FakeDrive::new();
        let store = drive.store();
        drive.server().fail_next = Some((
            403,
            r#"{"error":{"message":"The user's Drive storage quota has been exceeded."}}"#
                .to_string(),
        ));

        let Err(Error::Storage(detail)) = store.head().await else {
            panic!("un 403 tiene que llegar como fallo del almacén");
        };
        assert!(detail.contains("403"), "{detail}");
        assert!(detail.contains("quota"), "{detail}");
    });
}

#[test]
fn a_duplicated_head_file_is_resolved_the_same_way_by_everyone() {
    block_on(async {
        let drive = FakeDrive::new();
        let a = ObjectId::of(b"a");
        let b = ObjectId::of(b"b");

        // Dos clientes que crearon el head a la vez: Drive admite el nombre
        // repetido y se queda con los dos ficheros.
        drive.server().create("head", a.to_hex().into_bytes());
        drive.server().create("head", b.to_hex().into_bytes());

        let ana = drive.store();
        let bruno = drive.store();
        assert_eq!(
            ana.head().await.unwrap().unwrap().commit,
            bruno.head().await.unwrap().unwrap().commit
        );
        // El de id menor gana, y es el mismo para todos.
        assert_eq!(ana.head().await.unwrap().unwrap().commit, a);
    });
}

#[test]
fn the_header_is_published_once_and_never_overwritten() {
    block_on(async {
        let drive = FakeDrive::new();
        let mut ana = drive.store();
        let mut bruno = drive.store();

        assert_eq!(ana.header().await.unwrap(), None);
        assert_eq!(
            ana.publish_header(b"cabecera de ana").await.unwrap(),
            HeaderStatus::Published
        );
        assert_eq!(
            ana.publish_header(b"cabecera de ana").await.unwrap(),
            HeaderStatus::AlreadyPublished
        );

        // Bruno arranca de cero y la encuentra: es lo que le deja desbloquear
        // con su passphrase en un navegador que no ha visto nunca este vault.
        assert_eq!(
            bruno.header().await.unwrap().as_deref(),
            Some(b"cabecera de ana".as_slice())
        );

        // Y un vault distinto en la misma cuenta no pisa el que había.
        assert_eq!(
            bruno.publish_header(b"otro vault").await.unwrap(),
            HeaderStatus::Foreign
        );
        assert_eq!(
            bruno.header().await.unwrap().as_deref(),
            Some(b"cabecera de ana".as_slice())
        );
        assert_eq!(drive.server().count_named("header"), 1);
    });
}

#[test]
fn two_devices_converge_through_drive() {
    block_on(async {
        let mk = master_key();
        let drive = FakeDrive::new();

        let mut ana = Repo::new(MemoryStore::new());
        let mut bruno = Repo::new(MemoryStore::new());

        // Ana da de alta una entrada y la sube.
        let github = EntryId::generate().unwrap();
        ana.put(&mk, github, &entry("GitHub"), 100).await.unwrap();
        let report = sync(ana.store_mut(), &mut drive.store(), &mk, 100)
            .await
            .unwrap();
        assert!(report.uploaded > 0);

        // Bruno arranca vacío y se la trae.
        sync(bruno.store_mut(), &mut drive.store(), &mk, 110)
            .await
            .unwrap();
        assert_eq!(issuers(&bruno, &mk).await, ["GitHub"]);

        // Cada uno edita por su lado, sin conexión.
        ana.put(&mk, EntryId::generate().unwrap(), &entry("AWS"), 200)
            .await
            .unwrap();
        bruno
            .put(&mk, EntryId::generate().unwrap(), &entry("Fastmail"), 210)
            .await
            .unwrap();

        // Y sincronizan uno detrás de otro.
        sync(ana.store_mut(), &mut drive.store(), &mk, 300)
            .await
            .unwrap();
        sync(bruno.store_mut(), &mut drive.store(), &mk, 310)
            .await
            .unwrap();
        let report = sync(ana.store_mut(), &mut drive.store(), &mk, 320)
            .await
            .unwrap();

        assert_eq!(issuers(&ana, &mk).await, ["AWS", "Fastmail", "GitHub"]);
        assert_eq!(issuers(&bruno, &mk).await, ["AWS", "Fastmail", "GitHub"]);
        assert_eq!(ana.head().await.unwrap(), bruno.head().await.unwrap());

        // Y una vez convergidos, sincronizar otra vez no mueve nada.
        assert!(
            sync(ana.store_mut(), &mut drive.store(), &mk, 330)
                .await
                .unwrap()
                .is_noop(),
            "{report:?}"
        );
    });
}

#[test]
fn the_remote_learns_nothing_about_the_entries() {
    block_on(async {
        let mk = master_key();
        let drive = FakeDrive::new();
        let mut ana = Repo::new(MemoryStore::new());

        ana.put(
            &mk,
            EntryId::generate().unwrap(),
            &entry("Banco Muy Concreto"),
            100,
        )
        .await
        .unwrap();
        sync(ana.store_mut(), &mut drive.store(), &mk, 100)
            .await
            .unwrap();

        let server = drive.server();
        assert!(!server.files.is_empty());
        for file in &server.files {
            let haystack = String::from_utf8_lossy(&file.content).to_lowercase();
            for secreto in ["banco", "joshua", "germade", "12345678901234567890"] {
                assert!(
                    !haystack.contains(secreto) && !file.name.contains(secreto),
                    "«{secreto}» ha llegado a Drive en {}",
                    file.name
                );
            }
        }
    });
}

#[test]
fn a_head_that_another_client_moved_is_merged_on_the_next_sync() {
    block_on(async {
        let mk = master_key();
        let drive = FakeDrive::new();

        let mut ana = Repo::new(MemoryStore::new());
        let mut bruno = Repo::new(MemoryStore::new());

        ana.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100)
            .await
            .unwrap();
        bruno
            .put(&mk, EntryId::generate().unwrap(), &entry("AWS"), 100)
            .await
            .unwrap();

        // Los dos publican sin haberse visto nunca: el segundo se encuentra un
        // head que no esperaba y fusiona.
        sync(ana.store_mut(), &mut drive.store(), &mk, 100)
            .await
            .unwrap();
        sync(bruno.store_mut(), &mut drive.store(), &mk, 110)
            .await
            .unwrap();
        sync(ana.store_mut(), &mut drive.store(), &mk, 120)
            .await
            .unwrap();

        assert_eq!(issuers(&ana, &mk).await, ["AWS", "GitHub"]);
        assert_eq!(issuers(&bruno, &mk).await, ["AWS", "GitHub"]);
        assert_eq!(ana.head().await.unwrap(), bruno.head().await.unwrap());
    });
}

async fn issuers(repo: &Repo<MemoryStore>, mk: &SecretKey) -> Vec<String> {
    let mut issuers: Vec<String> = repo
        .entries(mk)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry.issuer)
        .collect();
    issuers.sort();
    issuers
}
