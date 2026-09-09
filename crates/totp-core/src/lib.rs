//! Núcleo compartido del gestor TOTP.
//!
//! Aquí vive todo lo que no depende de la plataforma: la generación de códigos,
//! el formato cifrado del vault y la jerarquía de claves. Los clientes —web y
//! extensión vía WASM, móvil vía UniFFI, dongle vía FFI— aportan solo la UI, el
//! almacenamiento y el reloj.
//!
//! ```
//! use totp_core::crypto::KdfParams;
//! use totp_core::vault::{EncryptedEntry, EntryId, VaultHeader};
//!
//! let (header, mk, recovery) = VaultHeader::create(b"correct horse", KdfParams::INTERACTIVE)?;
//! let entry = totp_core::otpauth::parse_uri("otpauth://totp/GitHub:yo?secret=JBSWY3DPEHPK3PXP")?;
//!
//! let sealed = EncryptedEntry::seal(&mk, EntryId::generate()?, &entry)?;
//! let bytes = sealed.to_bytes()?; // esto es lo que sube a Drive
//!
//! // Más tarde, en otro dispositivo, con la recovery key:
//! let mk = VaultHeader::from_bytes(&header.to_bytes()?)?.unlock_with_recovery_key(&recovery)?;
//! let entry = EncryptedEntry::from_bytes(&bytes)?.open(&mk)?;
//! assert_eq!(entry.code_at(59)?.len(), 6);
//! # Ok::<(), totp_core::Error>(())
//! ```

mod byte_array;

pub mod crypto;
pub mod error;
pub mod http;
pub mod otpauth;
pub mod sync;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
