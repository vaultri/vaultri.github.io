//! El motor de sync: descubrir qué tiene el otro lado, fusionar lo que haga
//! falta y publicar el resultado.
//!
//! No hay servidor: el remoto es un blob store tonto (el `appDataFolder` de
//! Drive) que no puede resolver nada por nosotros. Todo el trabajo —encontrar
//! el ancestro común, fusionar, decidir quién gana— pasa en el cliente, con la
//! MK, sobre objetos que el almacén no puede leer.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::crypto::SecretKey;
use crate::error::{Error, Result};

use super::merge::merge_trees;
use super::objects::{Commit, ObjectId, Tree};
use super::store::{HeadUpdate, ObjectStore, get_verified};

/// Cuántas veces se reintenta si otro cliente mueve el `head` remoto mientras
/// estamos publicando. Más allá de esto, lo sano es rendirse: los commits ya
/// están en el log, así que no se pierde nada esperando al siguiente sync.
const MAX_ATTEMPTS: u32 = 4;

/// Qué hizo un sync.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Commit en el que quedan ambos lados.
    pub head: Option<ObjectId>,
    pub uploaded: usize,
    pub downloaded: usize,
    /// Cuántos commits de merge hubo que crear. Cero es el caso normal.
    pub merges: usize,
}

impl SyncReport {
    /// Si no se subió ni se bajó nada, los dos lados ya estaban igual.
    pub fn is_noop(&self) -> bool {
        self.uploaded == 0 && self.downloaded == 0 && self.merges == 0
    }
}

/// Sincroniza `local` contra `remote` y deja los dos en el mismo commit.
///
/// `now` es el reloj del cliente en segundos Unix; se usa para fechar el commit
/// de merge, no para decidir quién gana (eso ya está en el árbol).
pub async fn sync<L: ObjectStore, R: ObjectStore>(
    local: &mut L,
    remote: &mut R,
    mk: &SecretKey,
    now: u64,
) -> Result<SyncReport> {
    let mut history = History::default();
    let mut report = SyncReport::default();

    for _ in 0..MAX_ATTEMPTS {
        let remote_head = remote.head().await?;
        let remote_head_id = remote_head.as_ref().map(|head| head.commit);
        let local_head = local.head().await?.map(|head| head.commit);

        let tips = discover_tips(
            local,
            remote,
            mk,
            &mut history,
            remote_head_id,
            local_head,
            &mut report,
        )
        .await?;

        let new_head = match tips.split_first() {
            None => None,
            Some((first, [])) => Some(*first),
            Some((first, rest)) => {
                Some(fold_merges(local, mk, &mut history, *first, rest, now, &mut report).await?)
            }
        };

        // Solo hacen falta los objetos del árbol final; las versiones viejas de
        // cada entrada se quedan en el remoto hasta que alguien las pida.
        if let Some(head) = new_head {
            let tree = history.get(local, mk, head).await?.tree;
            report.downloaded += copy_tree_objects(local, remote, &tree).await?;
        }

        // Publicar. Si el head remoto se movió mientras tanto, se reintenta
        // desde cero con el estado nuevo.
        if let Some(head) = new_head
            && Some(head) != remote_head_id
        {
            report.uploaded += push_commits(local, remote, mk, &mut history, head).await?;
            // El log va antes que el head: si perdemos el compare-and-set, el
            // commit sigue siendo descubrible y el siguiente sync lo fusiona.
            remote.append_known_commit(head).await?;

            let expected = remote_head.as_ref().map(|head| head.token.as_str());
            if matches!(remote.set_head(expected, head).await?, HeadUpdate::Conflict) {
                continue;
            }
        }

        if let Some(head) = new_head
            && Some(head) != local_head
        {
            let current = local.head().await?;
            let expected = current.as_ref().map(|head| head.token.as_str());
            if matches!(local.set_head(expected, head).await?, HeadUpdate::Conflict) {
                return Err(Error::SyncContention);
            }
            local.append_known_commit(head).await?;
        }

        report.head = new_head;
        return Ok(report);
    }

    Err(Error::SyncContention)
}

/// Los commits que no son ancestros de ningún otro: las puntas de la historia
/// que hay que reconciliar.
///
/// Se miran el `head` remoto, el local y todo lo que aparezca en el
/// `known-commits.log`. El log es lo que rescata el commit de un cliente que
/// perdió la carrera del `head`: sigue publicado, y aquí se recoge.
async fn discover_tips<L: ObjectStore, R: ObjectStore>(
    local: &mut L,
    remote: &R,
    mk: &SecretKey,
    history: &mut History,
    remote_head: Option<ObjectId>,
    local_head: Option<ObjectId>,
    report: &mut SyncReport,
) -> Result<Vec<ObjectId>> {
    let mut candidates: Vec<ObjectId> = remote_head.into_iter().collect();
    candidates.extend(remote.known_commits().await?);
    candidates.sort();
    candidates.dedup();

    let mut known = Vec::new();
    for candidate in candidates {
        match copy_commit_chain(local, remote, mk, history, candidate).await {
            Ok(downloaded) => {
                report.downloaded += downloaded;
                known.push(candidate);
            }
            // Una línea del log cuyo objeto ya no está es un remoto podado o a
            // medio subir. El log es solo una pista de descubrimiento, así que
            // se ignora — pero si lo que falta es el head, el remoto está roto
            // de verdad y hay que decirlo.
            Err(Error::MissingObject) if Some(candidate) != remote_head => {}
            Err(err) => return Err(err),
        }
    }

    known.extend(local_head);
    known.sort();
    known.dedup();

    let mut ancestries = Vec::with_capacity(known.len());
    for tip in &known {
        ancestries.push(history.ancestors(local, mk, *tip, false).await?);
    }

    Ok(known
        .iter()
        .enumerate()
        .filter(|(i, tip)| {
            !ancestries
                .iter()
                .enumerate()
                .any(|(j, ancestry)| j != *i && ancestry.contains(*tip))
        })
        .map(|(_, tip)| *tip)
        .collect())
}

/// Fusiona las puntas de dos en dos hasta dejar una sola.
///
/// El orden es determinista (las puntas vienen ordenadas por id) y los padres
/// del commit de merge también se ordenan, de modo que dos clientes que
/// fusionen lo mismo produzcan exactamente el mismo objeto y converjan sin dar
/// otra vuelta.
async fn fold_merges<L: ObjectStore>(
    local: &mut L,
    mk: &SecretKey,
    history: &mut History,
    first: ObjectId,
    rest: &[ObjectId],
    now: u64,
    report: &mut SyncReport,
) -> Result<ObjectId> {
    let mut head = first;

    for other in rest {
        let base = match history.common_ancestor(local, mk, head, *other).await? {
            Some(base) => history.get(local, mk, base).await?.tree,
            None => Tree::new(),
        };
        let ours = history.get(local, mk, head).await?.tree;
        let theirs = history.get(local, mk, *other).await?.tree;

        let mut parents = alloc::vec![head, *other];
        parents.sort();
        let commit = Commit::new(parents, merge_trees(&base, &ours, &theirs), now);

        let (id, bytes) = commit.seal(mk)?;
        local.put(&id, &bytes).await?;
        history.remember(id, commit);

        head = id;
        report.merges += 1;
    }

    Ok(head)
}

/// Copia de `remote` a `local` los commits que faltan por debajo de `tip`.
///
/// Se descarga todo antes de escribir nada, y se escribe con los padres
/// primero: así "tengo este commit" sigue implicando "tengo sus ancestros"
/// aunque la copia se corte a la mitad, que es lo que permite podar el recorrido
/// en cuanto se llega a algo ya conocido.
async fn copy_commit_chain<L: ObjectStore, R: ObjectStore>(
    local: &mut L,
    remote: &R,
    mk: &SecretKey,
    history: &mut History,
    tip: ObjectId,
) -> Result<usize> {
    let mut pending: BTreeMap<ObjectId, (Commit, Vec<u8>)> = BTreeMap::new();
    let mut stack = alloc::vec![tip];

    while let Some(id) = stack.pop() {
        if pending.contains_key(&id) || local.contains(&id).await? {
            continue;
        }
        let bytes = get_verified(remote, &id).await?;
        let commit = Commit::open(mk, &bytes)?;
        stack.extend(commit.parents.iter().copied());
        pending.insert(id, (commit, bytes));
    }

    let graph = pending
        .iter()
        .map(|(id, (commit, _))| (*id, commit.parents.clone()))
        .collect();

    let mut copied = 0;
    for id in parents_first(&graph)? {
        let (commit, bytes) = pending.remove(&id).expect("el orden sale del propio grafo");
        local.put(&id, &bytes).await?;
        history.remember(id, commit);
        copied += 1;
    }

    Ok(copied)
}

/// Baja los objetos de entrada que referencia un árbol y que aún no están en
/// local, para poder leer el vault sin conexión.
async fn copy_tree_objects<L: ObjectStore, R: ObjectStore>(
    local: &mut L,
    remote: &R,
    tree: &Tree,
) -> Result<usize> {
    let mut copied = 0;
    for object in tree.values().filter_map(super::objects::TreeEntry::object) {
        if local.contains(&object).await? {
            continue;
        }
        let bytes = get_verified(remote, &object).await?;
        local.put(&object, &bytes).await?;
        copied += 1;
    }
    Ok(copied)
}

/// Sube lo que el remoto no tenga por debajo de `head`: primero los objetos de
/// entrada de cada commit, luego el commit. Nunca se publica un commit cuyos
/// objetos no estén ya arriba.
async fn push_commits<L: ObjectStore, R: ObjectStore>(
    local: &L,
    remote: &mut R,
    mk: &SecretKey,
    history: &mut History,
    head: ObjectId,
) -> Result<usize> {
    let mut pending: BTreeMap<ObjectId, Commit> = BTreeMap::new();
    let mut stack = alloc::vec![head];

    while let Some(id) = stack.pop() {
        if pending.contains_key(&id) || remote.contains(&id).await? {
            continue;
        }
        let commit = history.get(local, mk, id).await?;
        stack.extend(commit.parents.iter().copied());
        pending.insert(id, commit);
    }

    let graph = pending
        .iter()
        .map(|(id, commit)| (*id, commit.parents.clone()))
        .collect();

    let mut uploaded = 0;
    for id in parents_first(&graph)? {
        let commit = pending.remove(&id).expect("el orden sale del propio grafo");

        for object in commit
            .tree
            .values()
            .filter_map(super::objects::TreeEntry::object)
        {
            if remote.contains(&object).await? {
                continue;
            }
            remote
                .put(&object, &get_verified(local, &object).await?)
                .await?;
            uploaded += 1;
        }

        remote.put(&id, &get_verified(local, &id).await?).await?;
        uploaded += 1;
    }

    Ok(uploaded)
}

/// Orden topológico con los padres delante. Los padres que no estén en el grafo
/// se dan por ya presentes en el destino.
fn parents_first(graph: &BTreeMap<ObjectId, Vec<ObjectId>>) -> Result<Vec<ObjectId>> {
    let mut remaining: BTreeSet<ObjectId> = graph.keys().copied().collect();
    let mut order = Vec::with_capacity(graph.len());

    while !remaining.is_empty() {
        let ready: Vec<ObjectId> = remaining
            .iter()
            .filter(|id| graph[id].iter().all(|parent| !remaining.contains(parent)))
            .copied()
            .collect();

        if ready.is_empty() {
            // Imposible con hashes de contenido —un ciclo exigiría que un
            // commit contuviera su propio hash—, así que esto es un almacén
            // manipulado.
            return Err(Error::CorruptObject);
        }

        for id in ready {
            remaining.remove(&id);
            order.push(id);
        }
    }

    Ok(order)
}

/// Caché de commits ya descifrados.
///
/// Va indexada por hash de contenido, así que sirve igual para el almacén local
/// que para el remoto: el mismo id significa exactamente los mismos bytes.
#[derive(Default)]
struct History {
    commits: BTreeMap<ObjectId, Commit>,
}

impl History {
    fn remember(&mut self, id: ObjectId, commit: Commit) {
        self.commits.insert(id, commit);
    }

    async fn get<S: ObjectStore>(
        &mut self,
        store: &S,
        mk: &SecretKey,
        id: ObjectId,
    ) -> Result<Commit> {
        if let Some(commit) = self.commits.get(&id) {
            return Ok(commit.clone());
        }
        let commit = Commit::open(mk, &get_verified(store, &id).await?)?;
        self.commits.insert(id, commit.clone());
        Ok(commit)
    }

    async fn ancestors<S: ObjectStore>(
        &mut self,
        store: &S,
        mk: &SecretKey,
        tip: ObjectId,
        include_self: bool,
    ) -> Result<BTreeSet<ObjectId>> {
        let mut seen = BTreeSet::new();
        let mut stack = alloc::vec![tip];

        while let Some(id) = stack.pop() {
            let commit = self.get(store, mk, id).await?;
            for parent in &commit.parents {
                if seen.insert(*parent) {
                    stack.push(*parent);
                }
            }
        }

        if include_self {
            seen.insert(tip);
        }
        Ok(seen)
    }

    /// Ancestro común más cercano a `b`. Recorre en anchura desde `b` hasta dar
    /// con algo que también sea ancestro de `a`.
    async fn common_ancestor<S: ObjectStore>(
        &mut self,
        store: &S,
        mk: &SecretKey,
        a: ObjectId,
        b: ObjectId,
    ) -> Result<Option<ObjectId>> {
        let from_a = self.ancestors(store, mk, a, true).await?;

        let mut queue = VecDeque::from([b]);
        let mut seen = BTreeSet::from([b]);

        while let Some(id) = queue.pop_front() {
            if from_a.contains(&id) {
                return Ok(Some(id));
            }
            for parent in self.get(store, mk, id).await?.parents {
                if seen.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }

        Ok(None)
    }
}
