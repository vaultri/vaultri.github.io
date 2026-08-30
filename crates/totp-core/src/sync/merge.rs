//! Fusión a tres bandas de árboles de entradas.
//!
//! Es deliberadamente pura y sin I/O: el árbol lleva el `updated_at` de cada
//! entrada, así que fusionar no necesita descifrar ni una sola entrada, solo
//! los commits. Y tiene que ser determinista —dos peers que fusionen la misma
//! pareja han de obtener byte a byte el mismo árbol— o no convergerían nunca.

extern crate alloc;

use alloc::collections::BTreeSet;

use super::objects::{Tree, TreeEntry};

/// Fusiona `ours` y `theirs` sobre su ancestro común `base`.
pub fn merge_trees(base: &Tree, ours: &Tree, theirs: &Tree) -> Tree {
    let ids: BTreeSet<_> = ours.keys().chain(theirs.keys()).copied().collect();
    let mut merged = Tree::new();

    for id in ids {
        // Las claves nunca se quitan del árbol —un borrado deja lápida—, así
        // que que un lado no tenga la entrada significa que no la ha visto, no
        // que la haya quitado.
        let resolved = match (ours.get(&id), theirs.get(&id)) {
            (Some(a), Some(b)) if a == b => *a,
            (Some(a), Some(b)) => {
                let base = base.get(&id);
                if base == Some(a) {
                    *b // solo cambió el otro lado
                } else if base == Some(b) {
                    *a // solo cambiamos nosotros
                } else {
                    *winner(a, b)
                }
            }
            (Some(a), None) => *a,
            (None, Some(b)) => *b,
            (None, None) => unreachable!("el id sale de la unión de ambos árboles"),
        };
        merged.insert(id, resolved);
    }

    merged
}

/// Desempate cuando los dos lados cambiaron la misma entrada.
///
/// Gana el más reciente, borrado incluido: un borrado es una intención del
/// usuario tan explícita como una edición, y como la historia es inmutable y
/// direccionada por contenido, la entrada borrada sigue recuperable desde un
/// commit anterior. En caso de empate exacto gana el que sigue vivo, y si los
/// dos lo están, el de mayor hash: arbitrario, pero igual en todos los peers,
/// que es lo que importa.
fn winner<'a>(a: &'a TreeEntry, b: &'a TreeEntry) -> &'a TreeEntry {
    match a.timestamp().cmp(&b.timestamp()) {
        core::cmp::Ordering::Greater => a,
        core::cmp::Ordering::Less => b,
        core::cmp::Ordering::Equal => match (a.object(), b.object()) {
            (Some(oa), Some(ob)) => {
                if oa.as_bytes() >= ob.as_bytes() {
                    a
                } else {
                    b
                }
            }
            (Some(_), None) => a,
            (None, Some(_)) => b,
            (None, None) => a,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::objects::ObjectId;
    use crate::vault::EntryId;

    fn id(n: u8) -> EntryId {
        EntryId::from_bytes([n; 16])
    }

    fn live(tag: &[u8], at: u64) -> TreeEntry {
        TreeEntry::Live {
            object: ObjectId::of(tag),
            updated_at: at,
        }
    }

    fn tree(items: &[(EntryId, TreeEntry)]) -> Tree {
        items.iter().copied().collect()
    }

    #[test]
    fn takes_the_side_that_changed() {
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), live(b"v2", 20))]);
        let theirs = base.clone();

        assert_eq!(merge_trees(&base, &ours, &theirs), ours);
        assert_eq!(merge_trees(&base, &theirs, &ours), ours);
    }

    #[test]
    fn keeps_additions_from_both_sides() {
        let base = Tree::new();
        let ours = tree(&[(id(1), live(b"a", 10))]);
        let theirs = tree(&[(id(2), live(b"b", 11))]);

        let merged = merge_trees(&base, &ours, &theirs);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[&id(1)], live(b"a", 10));
        assert_eq!(merged[&id(2)], live(b"b", 11));
    }

    #[test]
    fn concurrent_edits_resolve_to_the_most_recent() {
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), live(b"nuestra", 30))]);
        let theirs = tree(&[(id(1), live(b"suya", 20))]);

        assert_eq!(
            merge_trees(&base, &ours, &theirs)[&id(1)],
            live(b"nuestra", 30)
        );
    }

    #[test]
    fn a_later_delete_beats_an_earlier_edit() {
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), live(b"editada", 20))]);
        let theirs = tree(&[(id(1), TreeEntry::Deleted { at: 30 })]);

        assert_eq!(
            merge_trees(&base, &ours, &theirs)[&id(1)],
            TreeEntry::Deleted { at: 30 }
        );
    }

    #[test]
    fn a_later_edit_beats_an_earlier_delete() {
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), TreeEntry::Deleted { at: 20 })]);
        let theirs = tree(&[(id(1), live(b"editada", 30))]);

        assert_eq!(
            merge_trees(&base, &ours, &theirs)[&id(1)],
            live(b"editada", 30)
        );
    }

    #[test]
    fn a_tombstone_is_not_resurrected_by_a_stale_peer() {
        // El otro lado nunca vio el borrado: sigue con la versión del base.
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), TreeEntry::Deleted { at: 20 })]);
        let theirs = base.clone();

        assert_eq!(
            merge_trees(&base, &ours, &theirs)[&id(1)],
            TreeEntry::Deleted { at: 20 }
        );
    }

    #[test]
    fn merging_is_commutative_even_on_ties() {
        // Mismo timestamp en los dos lados: el desempate no puede depender de
        // quién fusiona.
        let base = tree(&[(id(1), live(b"v1", 10))]);
        let ours = tree(&[(id(1), live(b"a", 20))]);
        let theirs = tree(&[(id(1), live(b"b", 20))]);

        assert_eq!(
            merge_trees(&base, &ours, &theirs),
            merge_trees(&base, &theirs, &ours)
        );
    }

    #[test]
    fn without_a_common_ancestor_both_sides_survive() {
        let ours = tree(&[(id(1), live(b"a", 10))]);
        let theirs = tree(&[(id(2), live(b"b", 10))]);

        assert_eq!(merge_trees(&Tree::new(), &ours, &theirs).len(), 2);
    }
}
