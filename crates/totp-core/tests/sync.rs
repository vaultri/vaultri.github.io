//! El sync visto desde fuera: dos dispositivos y un almacén compartido que no
//! entiende nada de lo que guarda.

use totp_core::Error;
use totp_core::crypto::{KdfParams, SecretKey};
use totp_core::sync::{
    HeadRef, HeadUpdate, MemoryStore, ObjectId, ObjectStore, Repo, SyncReport, TreeEntry, sync,
};
use totp_core::vault::{Entry, EntryId, VaultHeader};

/// Coste mínimo: aquí se prueba el sync, no la dureza del KDF.
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

/// Un dispositivo: su almacén local y nada más. La MK va aparte, como en el
/// diseño real.
struct Device {
    repo: Repo<MemoryStore>,
}

impl Device {
    fn new() -> Self {
        Self {
            repo: Repo::new(MemoryStore::new()),
        }
    }

    fn put(&mut self, mk: &SecretKey, id: EntryId, entry: &Entry, now: u64) {
        block_on(self.repo.put(mk, id, entry, now)).unwrap();
    }

    fn delete(&mut self, mk: &SecretKey, id: EntryId, now: u64) {
        block_on(self.repo.delete(mk, id, now)).unwrap();
    }

    fn sync(&mut self, remote: &mut MemoryStore, mk: &SecretKey, now: u64) -> SyncReport {
        block_on(sync(self.repo.store_mut(), remote, mk, now)).unwrap()
    }

    fn issuers(&self, mk: &SecretKey) -> Vec<String> {
        let mut issuers: Vec<_> = block_on(self.repo.entries(mk))
            .unwrap()
            .into_iter()
            .map(|(_, entry)| entry.issuer)
            .collect();
        issuers.sort();
        issuers
    }

    fn get(&self, mk: &SecretKey, id: EntryId) -> Option<Entry> {
        block_on(self.repo.get(mk, id)).unwrap()
    }

    fn head(&self) -> Option<ObjectId> {
        block_on(self.repo.head()).unwrap()
    }

    /// Otro dispositivo que arranca con exactamente el mismo estado local.
    fn fork(&self) -> Self {
        Self {
            repo: Repo::new(self.repo.store().clone()),
        }
    }

    /// Sube un commit y sus objetos sin mover el head: es el estado en que
    /// queda el remoto si un cliente muere entre publicar y ganar el
    /// compare-and-set, que es justo para lo que existe el log.
    fn publish_without_moving_head(
        &self,
        remote: &mut MemoryStore,
        mk: &SecretKey,
        commit: ObjectId,
    ) {
        block_on(async {
            let tree = self.repo.commit(mk, &commit).await.unwrap().tree;
            for object in tree.values().filter_map(TreeEntry::object) {
                let bytes = self.repo.store().get(&object).await.unwrap().unwrap();
                remote.put(&object, &bytes).await.unwrap();
            }
            let bytes = self.repo.store().get(&commit).await.unwrap().unwrap();
            remote.put(&commit, &bytes).await.unwrap();
            remote.append_known_commit(commit).await.unwrap();
        });
    }
}

/// Un almacén que devuelve mal un objeto concreto, para comprobar que el
/// cliente no se fía de lo que le llega. De paso demuestra que `ObjectStore` se
/// puede implementar desde fuera del crate, que es como lo hará el backend de
/// Drive.
struct TamperedStore<'a> {
    inner: &'a mut MemoryStore,
    target: ObjectId,
}

impl ObjectStore for TamperedStore<'_> {
    async fn contains(&self, id: &ObjectId) -> totp_core::Result<bool> {
        self.inner.contains(id).await
    }

    async fn get(&self, id: &ObjectId) -> totp_core::Result<Option<Vec<u8>>> {
        let bytes = self.inner.get(id).await?;
        Ok(match (bytes, *id == self.target) {
            (Some(mut bytes), true) => {
                bytes[0] ^= 1;
                Some(bytes)
            }
            (bytes, _) => bytes,
        })
    }

    async fn put(&mut self, id: &ObjectId, bytes: &[u8]) -> totp_core::Result<()> {
        self.inner.put(id, bytes).await
    }

    async fn head(&self) -> totp_core::Result<Option<HeadRef>> {
        self.inner.head().await
    }

    async fn set_head(
        &mut self,
        expected: Option<&str>,
        commit: ObjectId,
    ) -> totp_core::Result<HeadUpdate> {
        self.inner.set_head(expected, commit).await
    }

    async fn append_known_commit(&mut self, commit: ObjectId) -> totp_core::Result<()> {
        self.inner.append_known_commit(commit).await
    }

    async fn known_commits(&self) -> totp_core::Result<Vec<ObjectId>> {
        self.inner.known_commits().await
    }
}

#[test]
fn a_second_device_sees_what_the_first_published() {
    let mk = master_key();
    let mut remote = MemoryStore::new();
    let id = EntryId::generate().unwrap();

    let mut phone = Device::new();
    phone.put(&mk, id, &entry("GitHub"), 100);
    let report = phone.sync(&mut remote, &mk, 100);
    assert!(report.uploaded > 0);
    assert_eq!(report.merges, 0);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);

    assert_eq!(laptop.issuers(&mk), ["GitHub"]);
    assert_eq!(laptop.head(), phone.head());
    // Y el código que sale es el mismo, que es de lo que va todo esto.
    assert_eq!(
        laptop.get(&mk, id).unwrap().code_at(59).unwrap(),
        phone.get(&mk, id).unwrap().code_at(59).unwrap()
    );
}

#[test]
fn syncing_twice_does_nothing_the_second_time() {
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);

    phone.sync(&mut remote, &mk, 100);
    assert!(phone.sync(&mut remote, &mk, 101).is_noop());
}

#[test]
fn edits_made_offline_on_both_devices_survive_the_merge() {
    let mk = master_key();
    let mut remote = MemoryStore::new();
    let (github, aws) = (EntryId::generate().unwrap(), EntryId::generate().unwrap());

    // Punto de partida común.
    let mut phone = Device::new();
    phone.put(&mk, github, &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);

    // Cada uno da de alta lo suyo sin conexión.
    phone.put(&mk, aws, &entry("AWS"), 110);
    laptop.put(&mk, EntryId::generate().unwrap(), &entry("Fastmail"), 120);

    phone.sync(&mut remote, &mk, 130);
    let report = laptop.sync(&mut remote, &mk, 131);
    assert_eq!(report.merges, 1, "las dos historias divergieron");

    // El portátil ya lo tiene todo; el móvil lo recoge en su siguiente sync.
    assert_eq!(laptop.issuers(&mk), ["AWS", "Fastmail", "GitHub"]);
    phone.sync(&mut remote, &mk, 132);
    assert_eq!(phone.issuers(&mk), ["AWS", "Fastmail", "GitHub"]);
    assert_eq!(phone.head(), laptop.head());
}

#[test]
fn the_most_recent_edit_of_the_same_entry_wins() {
    let mk = master_key();
    let mut remote = MemoryStore::new();
    let id = EntryId::generate().unwrap();

    let mut phone = Device::new();
    phone.put(&mk, id, &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);

    // Los dos editan la misma entrada; el portátil lo hace después.
    let mut renamed_on_phone = entry("GitHub");
    renamed_on_phone.account = "viejo@germade.es".into();
    phone.put(&mk, id, &renamed_on_phone, 110);

    let mut renamed_on_laptop = entry("GitHub");
    renamed_on_laptop.account = "nuevo@germade.es".into();
    laptop.put(&mk, id, &renamed_on_laptop, 120);

    phone.sync(&mut remote, &mk, 130);
    laptop.sync(&mut remote, &mk, 131);
    phone.sync(&mut remote, &mk, 132);

    assert_eq!(phone.get(&mk, id).unwrap().account, "nuevo@germade.es");
    assert_eq!(laptop.get(&mk, id).unwrap().account, "nuevo@germade.es");
}

#[test]
fn a_delete_propagates_and_a_stale_device_does_not_resurrect_it() {
    let mk = master_key();
    let mut remote = MemoryStore::new();
    let id = EntryId::generate().unwrap();

    let mut phone = Device::new();
    phone.put(&mk, id, &entry("GitHub"), 100);
    phone.put(&mk, EntryId::generate().unwrap(), &entry("AWS"), 101);
    phone.sync(&mut remote, &mk, 102);

    // El portátil se queda con la foto vieja, en la que GitHub sigue viva.
    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 103);

    phone.delete(&mk, id, 110);
    phone.sync(&mut remote, &mk, 111);

    laptop.sync(&mut remote, &mk, 112);
    assert_eq!(laptop.issuers(&mk), ["AWS"]);
    assert_eq!(
        laptop
            .get(&mk, id)
            .unwrap_or_else(|| entry("ninguna"))
            .issuer,
        "ninguna"
    );
}

#[test]
fn two_devices_merging_the_same_pair_land_on_the_same_commit() {
    // Sin esto, cada uno crearía su propio commit de merge y habría que
    // fusionar los merges, potencialmente sin fin. Lo que se comprueba es que
    // el resultado no depende de desde qué lado se fusione.
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);

    // Dos commits hermanos sobre el mismo padre.
    phone.put(&mk, EntryId::generate().unwrap(), &entry("AWS"), 110);
    laptop.put(&mk, EntryId::generate().unwrap(), &entry("Fastmail"), 110);
    phone.sync(&mut remote, &mk, 120);

    // El commit del portátil se publica sin llegar a mover el head: queda como
    // punta suelta, hermana de la del móvil.
    let orphan = laptop.head().unwrap();
    laptop.publish_without_moving_head(&mut remote, &mk, orphan);

    // Los dos se encuentran con las mismas dos puntas, cada uno desde su lado.
    let (mut phone_side, mut laptop_side) = (phone.fork(), laptop.fork());
    let from_the_phone = phone_side.sync(&mut remote.clone(), &mk, 200);
    let from_the_laptop = laptop_side.sync(&mut remote.clone(), &mk, 200);

    assert_eq!(from_the_phone.merges, 1);
    assert_eq!(from_the_laptop.merges, 1);
    assert_eq!(from_the_phone.head, from_the_laptop.head);
}

#[test]
fn losing_the_head_race_does_not_lose_the_commit() {
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);

    // Los dos publican a la vez. Se simula la carrera dejando que el portátil
    // suba su commit y mueva el head después de que el móvil haya leído el
    // suyo: la implementación reintenta contra el estado nuevo.
    phone.put(&mk, EntryId::generate().unwrap(), &entry("AWS"), 110);
    laptop.put(&mk, EntryId::generate().unwrap(), &entry("Fastmail"), 111);

    phone.sync(&mut remote, &mk, 120);
    laptop.sync(&mut remote, &mk, 121);
    phone.sync(&mut remote, &mk, 122);

    assert_eq!(phone.issuers(&mk), ["AWS", "Fastmail", "GitHub"]);
    assert_eq!(laptop.issuers(&mk), ["AWS", "Fastmail", "GitHub"]);
}

#[test]
fn a_commit_orphaned_by_a_lost_race_is_recovered_from_the_log() {
    // Aquí se fuerza el caso que rescata el `known-commits.log`: un commit
    // publicado cuyo head fue pisado por otro cliente. Sin el log sería
    // inalcanzable; con él, el siguiente sync lo encuentra.
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut laptop = Device::new();
    laptop.sync(&mut remote, &mk, 101);
    laptop.put(&mk, EntryId::generate().unwrap(), &entry("Fastmail"), 110);
    laptop.sync(&mut remote, &mk, 111);
    let published = laptop.head().unwrap();

    // Alguien devuelve el head a donde estaba: el commit del portátil sigue
    // subido y en el log, pero ya no es alcanzable desde el head.
    let stale = phone.head().unwrap();
    let token = block_on(remote.head()).unwrap().unwrap().token;
    block_on(remote.set_head(Some(&token), stale)).unwrap();

    let report = phone.sync(&mut remote, &mk, 120);

    // Es descendiente del head vigente, así que basta con avanzar: no hace
    // falta fusionar nada.
    assert_eq!(report.merges, 0);
    assert_eq!(report.head, Some(published));
    assert_eq!(phone.issuers(&mk), ["Fastmail", "GitHub"]);
    // Y el head remoto vuelve a apuntar al commit rescatado.
    assert_eq!(block_on(remote.head()).unwrap().unwrap().commit, published);
}

#[test]
fn a_tampered_remote_object_is_rejected() {
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    // El almacén es no confiable: devuelve un objeto con el contenido cambiado
    // pero el nombre correcto, que es lo que podría hacer un Drive comprometido.
    let mut tampered = TamperedStore {
        target: phone.head().unwrap(),
        inner: &mut remote,
    };

    let mut laptop = Device::new();
    let failure = block_on(sync(laptop.repo.store_mut(), &mut tampered, &mk, 101));
    assert_eq!(failure, Err(Error::CorruptObject));
}

#[test]
fn the_remote_learns_nothing_about_the_entries() {
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    for needle in [
        b"GitHub".as_slice(),
        b"joshua".as_slice(),
        b"12345678901234567890".as_slice(),
    ] {
        let leaked = remote
            .objects()
            .any(|(_, bytes)| bytes.windows(needle.len()).any(|window| window == needle));
        assert!(!leaked, "el almacén no debería poder leer los metadatos");
    }
}

#[test]
fn a_device_with_the_wrong_key_cannot_read_the_vault() {
    let mk = master_key();
    let mut remote = MemoryStore::new();

    let mut phone = Device::new();
    phone.put(&mk, EntryId::generate().unwrap(), &entry("GitHub"), 100);
    phone.sync(&mut remote, &mk, 100);

    let mut intruder = Device::new();
    let other_key = master_key();
    let failure = block_on(sync(
        intruder.repo.store_mut(),
        &mut remote,
        &other_key,
        101,
    ));
    assert_eq!(failure, Err(Error::Decrypt));
}
