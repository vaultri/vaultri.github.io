//! Primitivas: XChaCha20-Poly1305 para todo lo que se cifra, Argon2id para
//! derivar KEKs a partir de una passphrase, y el tipo de clave que se limpia
//! de memoria al soltarse.

extern crate alloc;

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Longitud de toda clave simétrica del sistema: MK, KEKs y recovery key.
pub const KEY_LEN: usize = 32;
/// Nonce extendido de XChaCha20: 24 bytes, aleatorio sin riesgo de colisión
/// práctico, lo que evita tener que llevar un contador persistente.
pub const NONCE_LEN: usize = 24;
/// Sal de Argon2id.
pub const SALT_LEN: usize = 16;

/// Clave simétrica de 32 bytes. Se borra de memoria al soltarse, su `Debug` no
/// enseña el contenido y su igualdad es en tiempo constante.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<oculta>)")
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Clave nueva desde la entropía del sistema.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_LEN] = slice
            .try_into()
            .map_err(|_| Error::Format("longitud de clave"))?;
        Ok(Self(bytes))
    }
}

/// Rellena `out` con bytes del CSPRNG del sistema (`getrandom`: `getrandom(2)`
/// en Linux/Android, `SecRandomCopyBytes` en Apple, `crypto.getRandomValues`
/// en WASM).
pub fn fill_random(out: &mut [u8]) -> Result<()> {
    getrandom::getrandom(out).map_err(|_| Error::Entropy)
}

/// Nonce aleatorio de 24 bytes.
pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Cifra `plaintext` autenticando además `aad`, que no viaja en el resultado:
/// quien descifre tiene que reconstruirlo igual (lo usamos para atar cada
/// ciphertext a su identificador y a la versión de formato, de modo que
/// mover un blob de sitio invalide su MAC).
pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// Inversa de [`seal`]. Falla indistintamente si la clave es otra, si el `aad`
/// no coincide o si alguien tocó el ciphertext.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// Parámetros de Argon2id. Se guardan junto al envoltorio en vez de fijarse en
/// el código: así se pueden subir con el tiempo sin romper vaults viejos, y un
/// cliente con menos memoria (el dongle) puede leer los de otro sin adivinar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memoria en KiB.
    pub m_cost: u32,
    /// Iteraciones.
    pub t_cost: u32,
    /// Carriles en paralelo.
    pub p_cost: u32,
}

impl KdfParams {
    /// 64 MiB / 3 pasadas / 1 carril: por encima del mínimo que recomienda el
    /// RFC 9106 para el perfil de segunda opción, y todavía tolerable dentro
    /// de WASM en el navegador.
    pub const INTERACTIVE: Self = Self {
        m_cost: 65_536,
        t_cost: 3,
        p_cost: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::INTERACTIVE
    }
}

/// Deriva la KEK que envuelve la MK a partir de la passphrase del usuario.
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey> {
    let argon_params =
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|_| Error::KeyDerivation)?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| Error::KeyDerivation)?;

    let key = SecretKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SecretKey::generate().unwrap();
        let nonce = random_nonce().unwrap();
        let ct = seal(&key, &nonce, b"aad", b"hola").unwrap();
        assert_eq!(open(&key, &nonce, b"aad", &ct).unwrap(), b"hola");
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let key = SecretKey::generate().unwrap();
        let nonce = random_nonce().unwrap();
        let ct = seal(&key, &nonce, b"entrada-1", b"hola").unwrap();
        assert_eq!(open(&key, &nonce, b"entrada-2", &ct), Err(Error::Decrypt));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = SecretKey::generate().unwrap();
        let nonce = random_nonce().unwrap();
        let mut ct = seal(&key, &nonce, b"aad", b"hola").unwrap();
        ct[0] ^= 1;
        assert_eq!(open(&key, &nonce, b"aad", &ct), Err(Error::Decrypt));
    }

    #[test]
    fn kek_is_deterministic_and_salt_dependent() {
        // Parámetros mínimos: esto solo comprueba el cableado, no el coste.
        let params = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let a = derive_kek(b"correct horse", &[7u8; SALT_LEN], params).unwrap();
        let b = derive_kek(b"correct horse", &[7u8; SALT_LEN], params).unwrap();
        let c = derive_kek(b"correct horse", &[8u8; SALT_LEN], params).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
