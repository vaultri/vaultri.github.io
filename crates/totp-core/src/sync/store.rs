//! El contrato con el almacén, y una implementación en memoria.
//!
//! El core no sabe nada de Google Drive: solo pide objetos por nombre, mueve un
//! puntero `head` con compare-and-set, y añade líneas a un log. Drive, IndexedDB
//! o el dongle por WebHID implementan lo mismo detrás.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::objects::ObjectId;

/// El `head` remoto junto con el testigo que hace falta para reemplazarlo. El
/// testigo es opaco: el ETag de Drive, el número de revisión, lo que use cada
/// backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRef {
    pub commit: ObjectId,
    pub token: String,
}

/// Resultado de intentar mover el `head`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadUpdate {
    Updated(String),
    /// Otro cliente lo movió primero. No es un error: el sync reintenta desde
    /// el estado nuevo.
    Conflict,
}

/// Almacén de objetos. Las operaciones son `async` porque el backend de verdad
/// es `fetch` contra Drive; no se piden futuros `Send` a propósito, ya que el
/// cliente principal es WASM de un solo hilo.
#[allow(async_fn_in_trait)]
pub trait ObjectStore {
    async fn contains(&self, id: &ObjectId) -> Result<bool>;

    /// Devuelve los bytes tal cual. Quien llame tiene que verificar el hash
    /// —o usar [`get_verified`], que ya lo hace.
    async fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>>;

    /// Guarda un objeto. Los objetos son inmutables y el nombre es su hash, así
    /// que reescribir uno existente con los mismos bytes es un no-op.
    async fn put(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()>;

    async fn head(&self) -> Result<Option<HeadRef>>;

    /// Mueve el `head` solo si sigue en el testigo esperado (`None` = aún no
    /// existe). Sin este compare-and-set, dos clientes que suben a la vez se
    /// pisan y uno pierde su commit.
    async fn set_head(&mut self, expected: Option<&str>, commit: ObjectId) -> Result<HeadUpdate>;

    /// Añade un commit al `known-commits.log`, el registro append-only de todo
    /// lo publicado. Es lo que hace que perder la carrera del `head` no pierda
    /// el commit: sigue estando ahí para que el siguiente sync lo fusione.
    async fn append_known_commit(&mut self, commit: ObjectId) -> Result<()>;

    async fn known_commits(&self) -> Result<Vec<ObjectId>>;
}

/// Lee un objeto comprobando que los bytes son de verdad los suyos. El almacén
/// es un blob store no confiable: todo lo que sale de él pasa por aquí.
pub async fn get_verified<S: ObjectStore + ?Sized>(store: &S, id: &ObjectId) -> Result<Vec<u8>> {
    let bytes = store.get(id).await?.ok_or(Error::MissingObject)?;
    id.verify(&bytes)?;
    Ok(bytes)
}

/// Almacén en memoria. Sirve de doble en los tests y de caché local en el
/// cliente antes de volcar a un almacenamiento persistente.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    objects: BTreeMap<ObjectId, Vec<u8>>,
    head: Option<ObjectId>,
    /// Se incrementa en cada cambio de `head` y hace de ETag.
    generation: u64,
    known: Vec<ObjectId>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Recorre los objetos guardados. Útil para volcar o auditar un almacén;
    /// lo que devuelve son bytes cifrados, no dice nada de su contenido.
    pub fn objects(&self) -> impl Iterator<Item = (&ObjectId, &[u8])> {
        self.objects
            .iter()
            .map(|(id, bytes)| (id, bytes.as_slice()))
    }
}

impl ObjectStore for MemoryStore {
    async fn contains(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.objects.contains_key(id))
    }

    async fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.get(id).cloned())
    }

    async fn put(&mut self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        if id.verify(bytes).is_err() {
            return Err(Error::CorruptObject);
        }
        self.objects.insert(*id, bytes.to_vec());
        Ok(())
    }

    async fn head(&self) -> Result<Option<HeadRef>> {
        Ok(self.head.map(|commit| HeadRef {
            commit,
            token: self.generation.to_string(),
        }))
    }

    async fn set_head(&mut self, expected: Option<&str>, commit: ObjectId) -> Result<HeadUpdate> {
        let current = self.head.map(|_| self.generation.to_string());
        if expected.map(ToString::to_string) != current {
            return Ok(HeadUpdate::Conflict);
        }
        self.head = Some(commit);
        self.generation += 1;
        Ok(HeadUpdate::Updated(self.generation.to_string()))
    }

    async fn append_known_commit(&mut self, commit: ObjectId) -> Result<()> {
        if !self.known.contains(&commit) {
            self.known.push(commit);
        }
        Ok(())
    }

    async fn known_commits(&self) -> Result<Vec<ObjectId>> {
        Ok(self.known.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_moves_only_with_the_right_token() {
        pollster::block_on(async {
            let mut store = MemoryStore::new();
            let a = ObjectId::of(b"a");
            let b = ObjectId::of(b"b");

            assert_eq!(store.head().await.unwrap(), None);

            // Primer head: se espera que no hubiera ninguno.
            let HeadUpdate::Updated(token) = store.set_head(None, a).await.unwrap() else {
                panic!("debería haber creado el head");
            };
            assert_eq!(store.head().await.unwrap().unwrap().commit, a);

            // Un cliente con el testigo viejo no pisa nada.
            assert_eq!(store.set_head(None, b).await.unwrap(), HeadUpdate::Conflict);
            assert_eq!(store.head().await.unwrap().unwrap().commit, a);

            assert!(matches!(
                store.set_head(Some(&token), b).await.unwrap(),
                HeadUpdate::Updated(_)
            ));
            assert_eq!(store.head().await.unwrap().unwrap().commit, b);
        });
    }

    #[test]
    fn objects_are_checked_against_their_id_on_the_way_in_and_out() {
        pollster::block_on(async {
            let mut store = MemoryStore::new();
            let id = ObjectId::of(b"contenido");

            assert_eq!(
                store.put(&ObjectId::of(b"otro"), b"contenido").await,
                Err(Error::CorruptObject)
            );

            store.put(&id, b"contenido").await.unwrap();
            assert_eq!(get_verified(&store, &id).await.unwrap(), b"contenido");
            assert_eq!(
                get_verified(&store, &ObjectId::of(b"nada")).await,
                Err(Error::MissingObject)
            );
        });
    }

    #[test]
    fn the_known_commits_log_does_not_repeat_entries() {
        pollster::block_on(async {
            let mut store = MemoryStore::new();
            let a = ObjectId::of(b"a");

            store.append_known_commit(a).await.unwrap();
            store.append_known_commit(a).await.unwrap();
            assert_eq!(store.known_commits().await.unwrap(), alloc::vec![a]);
        });
    }
}
