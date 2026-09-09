//! `ObjectStore` sobre el `appDataFolder` de Google Drive.
//!
//! Drive es aquí un blob store tonto: guarda ficheros por nombre dentro de una
//! carpeta que solo ve esta aplicación, y no entiende nada de lo que hay
//! dentro. Todo lo que sube va cifrado con la MK, incluidos los metadatos, así
//! que lo único que Google llega a saber es cuántos objetos hay y cuándo se
//! escribieron.
//!
//! El mapa de nombres es plano:
//!
//! | Fichero | Contenido |
//! |---|---|
//! | `<hex>` | un objeto inmutable (entrada cifrada o commit), nombrado por su hash |
//! | `head` | el hash del commit vigente, en hex |
//! | `known-<hex>` | una línea del `known-commits.log`, un fichero por commit |
//! | `header` | la cabecera del vault: los envoltorios de la Master Key |
//!
//! El log va como un fichero por línea porque Drive no sabe añadir al final de
//! uno existente: reescribirlo entero convertiría cada `append` en una carrera
//! que puede perder líneas, mientras que crear un fichero nuevo no compite con
//! nadie. Cuesta un listado, que de todas formas hace falta para el índice.
//!
//! ## El compare-and-set del `head`
//!
//! El testigo opaco de [`HeadRef`] es el `headRevisionId` de Drive, que cambia
//! en cada escritura del contenido. `set_head` hace dos cosas antes de escribir:
//! comprueba que la revisión sigue siendo la esperada y manda `If-Match`. Lo
//! primero cierra la carrera larga (la que va desde que se leyó el `head` hasta
//! que se publica); lo segundo, la corta, siempre que la API respete la
//! precondición —cosa que el roadmap deja como punto abierto hasta probarlo
//! contra una cuenta de verdad.
//!
//! Si aun así se pierde una escritura, no se pierde ningún cambio: el commit ya
//! está publicado y anotado en el log, y el siguiente sync lo recoge como una
//! punta más y lo fusiona. Es la misma red de seguridad que hace que perder el
//! compare-and-set sea un reintento y no un error.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::error::{Error, Result};
use crate::http::{HttpClient, Request, Response};

use super::objects::ObjectId;
use super::store::{HeadRef, HeadUpdate, ObjectStore};

const FILES: &str = "https://www.googleapis.com/drive/v3/files";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3/files";
/// La carpeta privada de la aplicación. No aparece en el Drive del usuario y
/// solo la ve esta app, con el scope `drive.appdata`.
const SPACE: &str = "appDataFolder";
const HEAD_NAME: &str = "head";
const HEADER_NAME: &str = "header";
const KNOWN_PREFIX: &str = "known-";
const FILE_FIELDS: &str = "id,name,headRevisionId";
const PAGE_SIZE: u32 = 1000;

/// Un fichero del `appDataFolder`, tal y como lo describe la API.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileMeta {
    id: String,
    name: String,
    /// Cambia con cada escritura del contenido: es el testigo del
    /// compare-and-set. Drive no lo devuelve para todos los tipos de fichero,
    /// de ahí el `Option`.
    #[serde(default)]
    head_revision_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileList {
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    files: Vec<FileMeta>,
}

#[derive(serde::Serialize)]
struct NewFile<'a> {
    name: &'a str,
    parents: [&'a str; 1],
}

/// Índice local de nombre → fichero.
///
/// Drive cobra una llamada por consulta, así que el listado completo se hace
/// una vez y se reutiliza. Se refresca al leer el `head`, que es justo el
/// momento en el que el motor de sync empieza a mirar el remoto.
#[derive(Debug, Default)]
struct Index {
    files: BTreeMap<String, FileMeta>,
    loaded: bool,
}

impl Index {
    /// Anota un fichero. Drive permite dos ficheros con el mismo nombre en la
    /// misma carpeta, cosa que pasa cuando dos clientes crean el `head` a la
    /// vez; se queda el de id menor para que todos los clientes elijan el
    /// mismo. El commit del descartado no se pierde: está en el log.
    fn remember(&mut self, meta: FileMeta) {
        match self.files.get(&meta.name) {
            Some(existing) if existing.id <= meta.id => {}
            _ => {
                self.files.insert(meta.name.clone(), meta);
            }
        }
    }
}

/// Almacén remoto contra el `appDataFolder`.
///
/// El `HttpClient` que se le pasa es quien pone el `Authorization`: este tipo
/// no toca la credencial ni sabe cuándo caduca.
#[derive(Debug)]
pub struct DriveStore<H> {
    http: H,
    index: RefCell<Index>,
}

impl<H: HttpClient> DriveStore<H> {
    pub fn new(http: H) -> Self {
        Self {
            http,
            index: RefCell::new(Index::default()),
        }
    }

    pub fn http(&self) -> &H {
        &self.http
    }

    /// Relee el listado entero de la carpeta. Es una llamada (o varias, si hay
    /// paginación) a cambio de que `contains` y `get` no cuesten ninguna.
    pub async fn refresh(&self) -> Result<()> {
        let files = self.list(None).await?;

        let mut index = self.index.borrow_mut();
        *index = Index::default();
        index.loaded = true;
        for file in files {
            index.remember(file);
        }
        Ok(())
    }

    async fn ensure_index(&self) -> Result<()> {
        if self.index.borrow().loaded {
            return Ok(());
        }
        self.refresh().await
    }

    fn cached(&self, name: &str) -> Option<FileMeta> {
        self.index.borrow().files.get(name).cloned()
    }

    async fn lookup(&self, name: &str) -> Result<Option<FileMeta>> {
        self.ensure_index().await?;
        Ok(self.cached(name))
    }

    /// Como `lookup`, pero si el índice no lo tiene pregunta por el nombre
    /// concreto antes de rendirse. Sale a cuenta donde un falso «no está»
    /// rompería el sync —al bajar un objeto que otro cliente acaba de subir—,
    /// no donde solo cuesta una subida de más.
    async fn lookup_fresh(&self, name: &str) -> Result<Option<FileMeta>> {
        if let Some(meta) = self.lookup(name).await? {
            return Ok(Some(meta));
        }

        let found = self.list(Some(name)).await?.into_iter().next();
        if let Some(meta) = found.clone() {
            self.index.borrow_mut().remember(meta);
        }
        Ok(found)
    }

    async fn list(&self, name: Option<&str>) -> Result<Vec<FileMeta>> {
        let query = match name {
            // Los nombres los ponemos nosotros y son hex, `head` o
            // `known-<hex>`: no hay comillas que escapar.
            Some(name) => format!("name = '{name}' and trashed = false"),
            None => "trashed = false".to_string(),
        };

        let mut files = Vec::new();
        let mut page: Option<String> = None;

        loop {
            let mut url = format!(
                "{FILES}?spaces={SPACE}&pageSize={PAGE_SIZE}&q={}&fields={}",
                encode(&query),
                encode(&format!("nextPageToken,files({FILE_FIELDS})")),
            );
            if let Some(token) = &page {
                url.push_str("&pageToken=");
                url.push_str(&encode(token));
            }

            let response = self.http.send(Request::get(url)).await?;
            if !response.is_success() {
                return Err(failed("listar el appDataFolder", &response));
            }

            let listing: FileList = parse(&response, "listado")?;
            files.extend(listing.files);

            match listing.next_page_token {
                Some(token) if !token.is_empty() => page = Some(token),
                _ => return Ok(files),
            }
        }
    }

    async fn download(&self, file_id: &str) -> Result<Option<Vec<u8>>> {
        let response = self
            .http
            .send(Request::get(format!(
                "{FILES}/{}?alt=media",
                encode(file_id)
            )))
            .await?;

        // Un 404 es un fichero que ya no está —remoto podado, o el índice
        // apuntando a algo borrado—; para el almacén eso es «no lo tengo».
        if response.status == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(failed("descargar un objeto", &response));
        }
        Ok(Some(response.body))
    }

    async fn create(&self, name: &str, content: &[u8]) -> Result<FileMeta> {
        let metadata = serde_json::to_vec(&NewFile {
            name,
            parents: [SPACE],
        })
        .map_err(|_| Error::Storage("no se pudo serializar los metadatos".to_string()))?;

        let (boundary, body) = multipart(&metadata, content);
        let response = self
            .http
            .send(
                Request::post(
                    format!(
                        "{UPLOAD}?uploadType=multipart&fields={}",
                        encode(FILE_FIELDS)
                    ),
                    body,
                )
                .header(
                    "Content-Type",
                    &format!("multipart/related; boundary={boundary}"),
                ),
            )
            .await?;

        if !response.is_success() {
            return Err(failed("subir un fichero", &response));
        }
        parse(&response, "fichero creado")
    }

    /// La revisión que tiene ahora mismo un fichero, preguntando al servidor en
    /// vez de mirar el índice.
    async fn revision(&self, file_id: &str) -> Result<Option<String>> {
        let response = self
            .http
            .send(Request::get(format!(
                "{FILES}/{}?fields={}",
                encode(file_id),
                encode(FILE_FIELDS)
            )))
            .await?;

        if response.status == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(failed("leer la revisión del head", &response));
        }
        let meta: FileMeta = parse(&response, "metadatos")?;
        Ok(meta.head_revision_id)
    }

    async fn overwrite(&self, file_id: &str, expected: &str, content: &[u8]) -> Result<HeadUpdate> {
        let response = self
            .http
            .send(
                Request::patch(
                    format!(
                        "{UPLOAD}/{}?uploadType=media&fields={}",
                        encode(file_id),
                        encode(FILE_FIELDS)
                    ),
                    content.to_vec(),
                )
                .header("Content-Type", "application/octet-stream")
                .header("If-Match", expected),
            )
            .await?;

        // 412 es la precondición fallida; 409 y 428 los devuelven algunos
        // extremos de la API ante el mismo caso. Los tres son «llegué tarde»,
        // que no es un error: el motor reintenta desde el estado nuevo.
        if matches!(response.status, 409 | 412 | 428) {
            return Ok(HeadUpdate::Conflict);
        }
        if !response.is_success() {
            return Err(failed("mover el head", &response));
        }

        let meta: FileMeta = parse(&response, "head actualizado")?;
        Ok(HeadUpdate::Updated(
            meta.head_revision_id.unwrap_or_default(),
        ))
    }
}

/// Qué pasó al publicar la cabecera.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderStatus {
    /// No había ninguna y se subió esta.
    Published,
    /// Ya estaba, byte a byte la misma.
    AlreadyPublished,
    /// Hay una cabecera distinta: esta cuenta de Drive guarda otro vault.
    Foreign,
}

impl<H: HttpClient> DriveStore<H> {
    /// La cabecera del vault publicada en la carpeta, si la hay.
    ///
    /// Sin esto un dispositivo nuevo no puede hacer nada con los objetos: son
    /// entradas cifradas con una MK que solo la cabecera sabe desenvolver. Es
    /// lo único que sube que no es un objeto direccionado por contenido, y sigue
    /// sin decirle nada a Google: para abrirla hace falta la passphrase.
    pub async fn header(&self) -> Result<Option<Vec<u8>>> {
        match self.lookup_fresh(HEADER_NAME).await? {
            Some(meta) => self.download(&meta.id).await,
            None => Ok(None),
        }
    }

    /// Publica la cabecera si la carpeta aún no tiene ninguna.
    ///
    /// Nunca reescribe la que hubiera: una cabecera distinta significa que esta
    /// cuenta de Drive ya guarda otro vault, y pisarla dejaría sus entradas
    /// cifradas con una MK que ya nadie sabría desenvolver. Cuando las fases 2
    /// y 4 añadan envoltorios nuevos habrá que decidir cómo se actualiza; hasta
    /// entonces, el caso no se da.
    pub async fn publish_header(&mut self, bytes: &[u8]) -> Result<HeaderStatus> {
        let Some(meta) = self.lookup_fresh(HEADER_NAME).await? else {
            let meta = self.create(HEADER_NAME, bytes).await?;
            self.index.borrow_mut().remember(meta);
            return Ok(HeaderStatus::Published);
        };

        let existing = self.download(&meta.id).await?.unwrap_or_default();
        if existing == bytes {
            Ok(HeaderStatus::AlreadyPublished)
        } else {
            Ok(HeaderStatus::Foreign)
        }
    }
}

impl<H: HttpClient> ObjectStore for DriveStore<H> {
    async fn contains(&self, id: &ObjectId) -> Result<bool> {
        // Con el índice basta: un falso «no» solo provoca una subida de más de
        // un objeto que ya estaba, y como el nombre es el hash, el duplicado es
        // byte a byte el mismo fichero.
        Ok(self.lookup(&id.to_hex()).await?.is_some())
    }

    async fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>> {
        match self.lookup_fresh(&id.to_hex()).await? {
            Some(meta) => self.download(&meta.id).await,
            None => Ok(None),
        }
    }

    async fn put(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if id.verify(bytes).is_err() {
            return Err(Error::CorruptObject);
        }

        let name = id.to_hex();
        if self.lookup(&name).await?.is_some() {
            // Los objetos son inmutables: si ya está, ya está.
            return Ok(());
        }

        let meta = self.create(&name, bytes).await?;
        self.index.borrow_mut().remember(meta);
        Ok(())
    }

    async fn head(&self) -> Result<Option<HeadRef>> {
        // El sync empieza siempre por aquí, así que es el sitio donde renovar
        // la foto de la carpeta.
        self.refresh().await?;

        let Some(meta) = self.cached(HEAD_NAME) else {
            return Ok(None);
        };
        let Some(bytes) = self.download(&meta.id).await? else {
            return Ok(None);
        };

        let hex = core::str::from_utf8(&bytes)
            .map_err(|_| Error::Format("el head remoto no es texto"))?
            .trim();
        Ok(Some(HeadRef {
            commit: ObjectId::parse_hex(hex)?,
            token: meta.head_revision_id.unwrap_or_default(),
        }))
    }

    async fn set_head(&mut self, expected: Option<&str>, commit: ObjectId) -> Result<HeadUpdate> {
        let content = commit.to_hex().into_bytes();

        match expected {
            // Aún no había head. Se vuelve a preguntar por el nombre antes de
            // crearlo para no duplicarlo si otro cliente se adelantó entre el
            // listado y ahora.
            None => {
                if self.lookup_fresh(HEAD_NAME).await?.is_some() {
                    return Ok(HeadUpdate::Conflict);
                }
                let meta = self.create(HEAD_NAME, &content).await?;
                let token = meta.head_revision_id.clone().unwrap_or_default();
                self.index.borrow_mut().remember(meta);
                Ok(HeadUpdate::Updated(token))
            }
            Some(expected) => {
                let Some(meta) = self.lookup_fresh(HEAD_NAME).await? else {
                    // Esperábamos un head que ya no existe: alguien vació la
                    // carpeta debajo. Reintentar desde cero es lo correcto.
                    return Ok(HeadUpdate::Conflict);
                };

                // Comprobación explícita antes de escribir: cierra la carrera
                // larga incluso si el servidor ignorase el `If-Match`.
                if self.revision(&meta.id).await?.as_deref() != Some(expected) {
                    return Ok(HeadUpdate::Conflict);
                }

                let update = self.overwrite(&meta.id, expected, &content).await?;
                if let HeadUpdate::Updated(token) = &update {
                    self.index.borrow_mut().remember(FileMeta {
                        id: meta.id,
                        name: HEAD_NAME.to_string(),
                        head_revision_id: Some(token.clone()),
                    });
                }
                Ok(update)
            }
        }
    }

    async fn append_known_commit(&mut self, commit: ObjectId) -> Result<()> {
        let name = format!("{KNOWN_PREFIX}{}", commit.to_hex());
        if self.lookup(&name).await?.is_some() {
            return Ok(());
        }

        // El contenido repite el nombre: así una carpeta volcada a mano sigue
        // siendo legible sin conocer el convenio.
        let meta = self.create(&name, commit.to_hex().as_bytes()).await?;
        self.index.borrow_mut().remember(meta);
        Ok(())
    }

    async fn known_commits(&self) -> Result<Vec<ObjectId>> {
        self.ensure_index().await?;

        let mut commits = Vec::new();
        for name in self.index.borrow().files.keys() {
            let Some(hex) = name.strip_prefix(KNOWN_PREFIX) else {
                continue;
            };
            // Una línea ilegible del log es una pista rota, no un almacén
            // roto: el descubrimiento sigue con las demás.
            if let Ok(commit) = ObjectId::parse_hex(hex) {
                commits.push(commit);
            }
        }
        Ok(commits)
    }
}

/// Cuerpo `multipart/related`: los metadatos en JSON y luego el contenido.
///
/// El separador se elige comprobando que no aparezca en el contenido, que es
/// binario y podría contener cualquier cosa.
fn multipart(metadata: &[u8], content: &[u8]) -> (String, Vec<u8>) {
    let mut boundary = String::from("vaultrie");
    let mut suffix = 0u32;
    while content
        .windows(boundary.len())
        .any(|window| window == boundary.as_bytes())
    {
        suffix += 1;
        boundary = format!("vaultrie-{suffix}");
    }

    let mut body = Vec::with_capacity(metadata.len() + content.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
    body.extend_from_slice(metadata);
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (boundary, body)
}

fn parse<T: serde::de::DeserializeOwned>(response: &Response, what: &str) -> Result<T> {
    serde_json::from_slice(&response.body)
        .map_err(|_| Error::Storage(format!("Drive devolvió un {what} ilegible")))
}

/// Error de almacén con lo justo para diagnosticar: el código y el principio
/// del cuerpo, que en Drive es un JSON con el motivo.
fn failed(what: &str, response: &Response) -> Error {
    let mut detail = response.text();
    detail.truncate(200);
    let detail: String = detail
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    Error::Storage(format!(
        "no se pudo {what}: HTTP {} {}",
        response.status,
        detail.trim()
    ))
}

/// Percent-encoding para los parámetros de la query.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boundary_never_appears_inside_the_content() {
        let (boundary, body) = multipart(b"{}", b"vaultrie y mas vaultrie");
        assert_eq!(boundary, "vaultrie-1");
        assert!(body.starts_with(b"--vaultrie-1\r\n"));
    }

    #[test]
    fn query_parameters_are_escaped() {
        assert_eq!(encode("name = 'head'"), "name%20%3D%20%27head%27");
    }

    #[test]
    fn the_smaller_file_id_wins_a_duplicated_name() {
        let mut index = Index::default();
        for id in ["b", "a", "c"] {
            index.remember(FileMeta {
                id: id.to_string(),
                name: HEAD_NAME.to_string(),
                head_revision_id: None,
            });
        }
        assert_eq!(index.files[HEAD_NAME].id, "a");
    }
}
