//! Operaciones locales sobre un almacén: leer el árbol vigente, dar de alta,
//! editar y borrar entradas. Cada cambio produce un commit.

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::SecretKey;
use crate::error::{Error, Result};
use crate::vault::{EncryptedEntry, Entry, EntryId};

use super::objects::{Commit, ObjectId, Tree, TreeEntry};
use super::store::{HeadUpdate, ObjectStore, get_verified};

/// Vista de trabajo sobre un almacén.
///
/// La MK no se guarda aquí: va como parámetro en cada operación. La extensión
/// de Chrome desbloquea con WebAuthn PRF y confirmación biométrica *en cada
/// uso*, así que un `Repo` que retuviera la clave iría en contra del diseño.
#[derive(Debug)]
pub struct Repo<S> {
    store: S,
}

impl<S: ObjectStore> Repo<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    /// Commit en el que está el almacén, si ya tiene alguno.
    pub async fn head(&self) -> Result<Option<ObjectId>> {
        Ok(self.store.head().await?.map(|head| head.commit))
    }

    pub async fn commit(&self, mk: &SecretKey, id: &ObjectId) -> Result<Commit> {
        Commit::open(mk, &get_verified(&self.store, id).await?)
    }

    /// Árbol del commit vigente. Vacío si el vault aún no tiene historia.
    pub async fn tree(&self, mk: &SecretKey) -> Result<Tree> {
        match self.head().await? {
            Some(head) => Ok(self.commit(mk, &head).await?.tree),
            None => Ok(Tree::new()),
        }
    }

    /// Las entradas vivas, descifradas. Las lápidas no salen.
    pub async fn entries(&self, mk: &SecretKey) -> Result<Vec<(EntryId, Entry)>> {
        let tree = self.tree(mk).await?;
        let mut out = Vec::new();
        for (id, node) in &tree {
            if let Some(object) = node.object() {
                out.push((*id, self.read_entry(mk, *id, &object).await?));
            }
        }
        Ok(out)
    }

    pub async fn get(&self, mk: &SecretKey, id: EntryId) -> Result<Option<Entry>> {
        let tree = self.tree(mk).await?;
        match tree.get(&id).and_then(TreeEntry::object) {
            Some(object) => Ok(Some(self.read_entry(mk, id, &object).await?)),
            None => Ok(None),
        }
    }

    /// Da de alta o reemplaza una entrada. El `updated_at` que se guarda es
    /// `now`, no el que traiga la entrada: es el que usa el merge para decidir,
    /// y tiene que reflejar cuándo se escribió de verdad.
    pub async fn put(
        &mut self,
        mk: &SecretKey,
        id: EntryId,
        entry: &Entry,
        now: u64,
    ) -> Result<ObjectId> {
        let mut stamped = entry.clone();
        stamped.updated_at = now;

        let sealed = EncryptedEntry::seal(mk, id, &stamped)?;
        let bytes = sealed.to_bytes()?;
        let object = ObjectId::of(&bytes);
        self.store.put(&object, &bytes).await?;

        let mut tree = self.tree(mk).await?;
        tree.insert(
            id,
            TreeEntry::Live {
                object,
                updated_at: now,
            },
        );
        self.commit_tree(mk, tree, now).await
    }

    /// Marca una entrada como borrada. Deja lápida en vez de quitar la clave:
    /// si desapareciera del árbol, el primer merge con un peer que aún la
    /// tuviera la resucitaría.
    pub async fn delete(&mut self, mk: &SecretKey, id: EntryId, now: u64) -> Result<ObjectId> {
        let mut tree = self.tree(mk).await?;
        if !tree.contains_key(&id) {
            return Err(Error::InvalidEntry("la entrada no existe"));
        }
        tree.insert(id, TreeEntry::Deleted { at: now });
        self.commit_tree(mk, tree, now).await
    }

    /// Escribe un commit nuevo encima del vigente y mueve el `head`.
    pub async fn commit_tree(&mut self, mk: &SecretKey, tree: Tree, now: u64) -> Result<ObjectId> {
        let current = self.store.head().await?;
        let parents = current
            .as_ref()
            .map(|head| alloc::vec![head.commit])
            .unwrap_or_default();

        let (id, bytes) = Commit::new(parents, tree, now).seal(mk)?;
        self.store.put(&id, &bytes).await?;
        self.store.append_known_commit(id).await?;

        let expected = current.as_ref().map(|head| head.token.as_str());
        match self.store.set_head(expected, id).await? {
            HeadUpdate::Updated(_) => Ok(id),
            // El almacén local tiene un solo escritor; si aun así hay carrera,
            // mejor fallar que pisar un commit ajeno.
            HeadUpdate::Conflict => Err(Error::SyncContention),
        }
    }

    async fn read_entry(&self, mk: &SecretKey, id: EntryId, object: &ObjectId) -> Result<Entry> {
        let bytes = get_verified(&self.store, object).await?;
        let sealed = EncryptedEntry::from_bytes(&bytes)?;
        // El AAD ata el ciphertext a su `EntryId`: si el árbol apuntara a otra
        // entrada, esto falla en vez de devolver el secreto equivocado.
        if sealed.entry_id()? != id {
            return Err(Error::CorruptObject);
        }
        sealed.open(mk)
    }
}
