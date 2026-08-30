//! Sincronización granular contra un almacén no confiable.
//!
//! El modelo es el de un control de versiones diminuto: cada entrada cifrada es
//! un objeto inmutable nombrado por su hash, cada cambio produce un commit con
//! el árbol completo, y los clientes reconcilian sus historias fusionando por
//! el ancestro común. El almacén —el `appDataFolder` de Drive— solo tiene que
//! saber guardar blobs por nombre, mover un puntero con compare-and-set y
//! añadir líneas a un log.
//!
//! Nada de esto depende de la UI ni de Drive: la fase 3 del roadmap reutiliza
//! el mismo motor para hablar con el dongle por WebHID, cambiando solo la
//! implementación de [`ObjectStore`].

mod engine;
mod merge;
mod objects;
mod repo;
mod store;

pub use engine::{SyncReport, sync};
pub use merge::merge_trees;
pub use objects::{Commit, ObjectId, Tree, TreeEntry};
pub use repo::Repo;
pub use store::{HeadRef, HeadUpdate, MemoryStore, ObjectStore, StoreSnapshot, get_verified};
