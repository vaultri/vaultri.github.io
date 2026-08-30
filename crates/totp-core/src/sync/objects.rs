//! Objetos direccionados por contenido: entradas cifradas y commits.
//!
//! Un objeto es inmutable y se nombra por el SHA-256 de sus bytes tal y como se
//! guardan. Editar una entrada no reescribe nada: crea un objeto nuevo y un
//! commit que apunta a él. Eso es lo que hace el sync granular —solo viajan los
//! objetos que el otro lado no tiene— y lo que permite verificar la integridad
//! contra un almacén no confiable sin necesidad de descifrar.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::{self, NONCE_LEN, SecretKey};
use crate::error::{Error, Result};
use crate::vault::{EntryId, FORMAT_VERSION};

const AAD_COMMIT: &[u8] = b"vaultrie/commit/v1";
const NONCE_DOMAIN: &[u8] = b"vaultrie/commit-nonce/v1";

/// Nombre de un objeto: el SHA-256 de sus bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Calcula el id de unos bytes ya serializados.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Nombre del objeto en el almacén remoto.
    pub fn to_hex(self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }

    pub fn parse_hex(s: &str) -> Result<Self> {
        let bytes = data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .map_err(|_| Error::Format("id de objeto no es hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Format("longitud de id de objeto"))?;
        Ok(Self(bytes))
    }

    /// Comprueba que unos bytes recibidos son de verdad este objeto. El almacén
    /// no es confiable: nada de lo que devuelve se usa sin pasar por aquí.
    pub fn verify(self, bytes: &[u8]) -> Result<()> {
        if Self::of(bytes) == self {
            Ok(())
        } else {
            Err(Error::CorruptObject)
        }
    }
}

impl core::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Los primeros bytes bastan para seguir un log; el hex completo estorba.
        write!(f, "ObjectId({}…)", &self.to_hex()[..8])
    }
}

impl serde::Serialize for ObjectId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        crate::byte_array::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ObjectId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        crate::byte_array::deserialize(deserializer).map(Self)
    }
}

/// Qué dice un commit sobre una entrada.
///
/// `updated_at` vive aquí y no solo dentro del ciphertext para que el merge
/// pueda resolver a favor de la versión más reciente sin descifrar ni una sola
/// entrada: al fusionar solo hacen falta los commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TreeEntry {
    /// La entrada existe, con este contenido.
    Live { object: ObjectId, updated_at: u64 },
    /// Lápida. Se conserva en el árbol porque borrar sin más haría que el
    /// siguiente merge con un peer que aún la tuviera la resucitara.
    Deleted { at: u64 },
}

impl TreeEntry {
    /// Momento del cambio, sea alta, edición o borrado.
    pub fn timestamp(&self) -> u64 {
        match self {
            TreeEntry::Live { updated_at, .. } => *updated_at,
            TreeEntry::Deleted { at } => *at,
        }
    }

    pub fn object(&self) -> Option<ObjectId> {
        match self {
            TreeEntry::Live { object, .. } => Some(*object),
            TreeEntry::Deleted { .. } => None,
        }
    }
}

/// El estado completo del vault en un momento dado.
///
/// Cada commit lleva el árbol entero, no un delta. Con las decenas de entradas
/// que tiene un vault real eso cuesta unos cientos de bytes, y a cambio leer no
/// necesita recorrer historia y el merge es una comparación directa.
pub type Tree = BTreeMap<EntryId, TreeEntry>;

/// Un punto del historial.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Commit {
    /// Vacío en el commit raíz, uno en el caso normal, dos o más en un merge.
    pub parents: Vec<ObjectId>,
    pub tree: Tree,
    pub created_at: u64,
}

impl Commit {
    pub fn new(parents: Vec<ObjectId>, tree: Tree, created_at: u64) -> Self {
        Self {
            parents,
            tree,
            created_at,
        }
    }

    /// Cifra el commit y devuelve su id junto con los bytes a guardar.
    pub fn seal(&self, mk: &SecretKey) -> Result<(ObjectId, Vec<u8>)> {
        let mut plaintext = Vec::new();
        ciborium::into_writer(self, &mut plaintext)
            .map_err(|_| Error::Format("serialización de commit"))?;

        let nonce = commit_nonce(mk, &plaintext);
        let ciphertext = crypto::seal(mk, &nonce, AAD_COMMIT, &plaintext)?;
        plaintext.zeroize();

        let stored = StoredCommit {
            version: FORMAT_VERSION,
            nonce: nonce.to_vec(),
            ciphertext,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&stored, &mut bytes)
            .map_err(|_| Error::Format("serialización de commit"))?;

        Ok((ObjectId::of(&bytes), bytes))
    }

    /// Inversa de [`Commit::seal`]. No verifica el hash: eso lo hace quien lee
    /// del almacén, antes de llegar aquí.
    pub fn open(mk: &SecretKey, bytes: &[u8]) -> Result<Self> {
        let stored: StoredCommit =
            ciborium::from_reader(bytes).map_err(|_| Error::Format("commit ilegible"))?;
        if stored.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(stored.version));
        }
        let nonce: [u8; NONCE_LEN] = stored
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("longitud de nonce"))?;

        let mut plaintext = crypto::open(mk, &nonce, AAD_COMMIT, &stored.ciphertext)?;
        let commit = ciborium::from_reader(plaintext.as_slice())
            .map_err(|_| Error::Format("commit ilegible"))?;
        plaintext.zeroize();
        Ok(commit)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredCommit {
    version: u32,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Nonce determinista, derivado del propio contenido del commit.
///
/// Es a propósito: dos peers que fusionan la misma pareja de commits producen
/// el mismo árbol, y con nonce aleatorio saldrían dos objetos distintos que
/// habría que volver a fusionar, potencialmente en bucle. Derivándolo del
/// contenido, un commit idéntico *es* el mismo objeto y la convergencia sale
/// sola. Reutilizar un nonce con el mismo mensaje y la misma clave no debilita
/// nada —el ciphertext es idéntico byte a byte—; lo único que revela es que dos
/// commits son iguales, que es justo lo que aquí interesa.
///
/// Las entradas, en cambio, siguen usando nonce aleatorio: ahí esa filtración
/// no aporta nada y sí diría, por ejemplo, que dos entradas comparten secreto.
fn commit_nonce(mk: &SecretKey, plaintext: &[u8]) -> [u8; NONCE_LEN] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(mk.as_bytes())
        .expect("HMAC acepta claves de cualquier longitud");
    // El prefijo de dominio separa este uso de la MK de cualquier otro.
    mac.update(NONCE_DOMAIN);
    mac.update(plaintext);
    let tag = mac.finalize().into_bytes();
    tag[..NONCE_LEN]
        .try_into()
        .expect("SHA-256 da 32 bytes, de sobra para 24")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_with(id: EntryId, at: u64) -> Tree {
        let mut tree = Tree::new();
        tree.insert(
            id,
            TreeEntry::Live {
                object: ObjectId::of(b"x"),
                updated_at: at,
            },
        );
        tree
    }

    #[test]
    fn commit_roundtrip() {
        let mk = SecretKey::generate().unwrap();
        let commit = Commit::new(Vec::new(), tree_with(EntryId::generate().unwrap(), 7), 100);

        let (id, bytes) = commit.seal(&mk).unwrap();
        id.verify(&bytes).unwrap();
        assert_eq!(Commit::open(&mk, &bytes).unwrap(), commit);
    }

    #[test]
    fn identical_commits_get_the_same_id() {
        let mk = SecretKey::generate().unwrap();
        let id = EntryId::generate().unwrap();

        let (a, _) = Commit::new(Vec::new(), tree_with(id, 7), 100)
            .seal(&mk)
            .unwrap();
        let (b, _) = Commit::new(Vec::new(), tree_with(id, 7), 100)
            .seal(&mk)
            .unwrap();
        let (c, _) = Commit::new(Vec::new(), tree_with(id, 8), 100)
            .seal(&mk)
            .unwrap();

        assert_eq!(a, b, "sin esto dos merges iguales no convergerían");
        assert_ne!(a, c);
    }

    #[test]
    fn a_different_mk_yields_a_different_object() {
        let commit = Commit::new(Vec::new(), Tree::new(), 100);
        let (a, _) = commit.seal(&SecretKey::generate().unwrap()).unwrap();
        let (b, _) = commit.seal(&SecretKey::generate().unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tampered_objects_are_detected() {
        let mk = SecretKey::generate().unwrap();
        let (id, mut bytes) = Commit::new(Vec::new(), Tree::new(), 100).seal(&mk).unwrap();

        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(id.verify(&bytes), Err(Error::CorruptObject));
        assert_eq!(Commit::open(&mk, &bytes), Err(Error::Decrypt));
    }

    #[test]
    fn object_ids_survive_hex_roundtrip() {
        let id = ObjectId::of(b"hola");
        assert_eq!(ObjectId::parse_hex(&id.to_hex()).unwrap(), id);
        assert!(ObjectId::parse_hex("no-hex").is_err());
    }

    #[test]
    fn object_ids_serialize_as_byte_strings() {
        // 32 bytes de hash + la cabecera del byte string, no un array de 32
        // enteros CBOR.
        let mut out = Vec::new();
        ciborium::into_writer(&ObjectId::of(b"hola"), &mut out).unwrap();
        assert_eq!(out.len(), 34);
        assert_eq!(
            ciborium::from_reader::<ObjectId, _>(out.as_slice()).unwrap(),
            ObjectId::of(b"hola")
        );
    }
}
