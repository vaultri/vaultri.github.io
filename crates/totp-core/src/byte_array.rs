//! Serde para arrays de bytes de longitud fija.
//!
//! La implementación que trae serde para `[u8; N]` lo trata como una tupla, que
//! en CBOR sale como un array de enteros: 32 bytes acaban ocupando más del
//! doble. Aquí van como byte string, que es lo natural para hashes e ids.

use core::fmt;
use core::marker::PhantomData;
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    deserializer.deserialize_bytes(ByteArrayVisitor::<N>(PhantomData))
}

struct ByteArrayVisitor<const N: usize>(PhantomData<[u8; N]>);

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{N} bytes")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
    }

    /// Un decodificador que no dé los bytes prestados (o un formato de texto)
    /// entra por aquí.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(i, &self))?;
        }
        Ok(out)
    }
}
