//! Formato del vault: cabecera con los envoltorios de la Master Key, y entradas
//! cifradas de una en una.
//!
//! Cada entrada es un objeto independiente —no un blob único— para que el sync
//! pueda ser granular y direccionado por contenido: cambiar una entrada no
//! reescribe el resto. Se cifran los metadatos junto al secreto: quien tenga el
//! blob no debería poder ni listar qué servicios usa el dueño.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, KdfParams, NONCE_LEN, SALT_LEN, SecretKey};
use crate::error::{Error, Result};
use crate::totp::{self, Algorithm};

/// Versión del formato en disco. Sube cuando cambie algo que un lector viejo no
/// pueda interpretar con seguridad.
pub const FORMAT_VERSION: u32 = 1;

const AAD_HEADER: &[u8] = b"vaultrie/mk/v1";
const AAD_ENTRY: &[u8] = b"vaultrie/entry/v1";

/// Secreto TOTP en claro. Se borra de memoria al soltarse.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct SecretBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Nunca el contenido, ni siquiera en un panic.
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// Identificador estable de una entrada: no cambia cuando la entrada se edita
/// —eso genera un objeto nuevo— y es lo que la identifica a lo largo del
/// historial. Va en el AAD para que un ciphertext no se pueda reasignar a otra
/// entrada sin invalidar su MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId([u8; 16]);

impl serde::Serialize for EntryId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        crate::byte_array::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EntryId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        crate::byte_array::deserialize(deserializer).map(Self)
    }
}

impl EntryId {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        crypto::fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }

    pub fn parse_hex(s: &str) -> Result<Self> {
        let bytes = data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .map_err(|_| Error::Format("id de entrada no es hex"))?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::Format("longitud de id de entrada"))?;
        Ok(Self(bytes))
    }
}

/// Una entrada TOTP en claro.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub issuer: String,
    pub account: String,
    pub secret: SecretBytes,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    /// Momento de la última modificación, en segundos Unix. Lo usa el sync para
    /// ordenar versiones de la misma entrada.
    pub updated_at: u64,
}

impl Entry {
    /// Entrada con los valores por defecto de facto (SHA-1, 6 dígitos, 30 s).
    pub fn new(issuer: impl Into<String>, account: impl Into<String>, secret: Vec<u8>) -> Self {
        Self {
            issuer: issuer.into(),
            account: account.into(),
            secret: SecretBytes::new(secret),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            updated_at: 0,
        }
    }

    /// Código vigente en el instante dado.
    pub fn code_at(&self, unix_time: u64) -> Result<String> {
        totp::totp_at(
            self.secret.as_slice(),
            unix_time,
            self.period,
            self.digits,
            self.algorithm,
        )
    }

    /// Segundos que le quedan al código vigente.
    pub fn seconds_remaining(&self, unix_time: u64) -> u32 {
        totp::seconds_remaining(unix_time, self.period)
    }

    fn validate(&self) -> Result<()> {
        if self.secret.as_slice().is_empty() {
            return Err(Error::InvalidEntry("secreto vacío"));
        }
        if !(totp::MIN_DIGITS..=totp::MAX_DIGITS).contains(&self.digits) {
            return Err(Error::InvalidEntry("número de dígitos fuera de rango"));
        }
        if self.period == 0 {
            return Err(Error::InvalidEntry("periodo cero"));
        }
        Ok(())
    }
}

/// Una entrada tal y como se guarda y se sincroniza.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEntry {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl EncryptedEntry {
    /// Cifra `entry` bajo la MK, atando el ciphertext a `id` y a la versión de
    /// formato mediante el AAD.
    pub fn seal(mk: &SecretKey, id: EntryId, entry: &Entry) -> Result<Self> {
        entry.validate()?;
        let mut plaintext = Vec::new();
        ciborium::into_writer(entry, &mut plaintext)
            .map_err(|_| Error::Format("serialización de entrada"))?;

        let nonce = crypto::random_nonce()?;
        let ciphertext = crypto::seal(mk, &nonce, &entry_aad(id), &plaintext)?;
        plaintext.zeroize();

        Ok(Self {
            version: FORMAT_VERSION,
            id: id.as_bytes().to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    pub fn entry_id(&self) -> Result<EntryId> {
        let bytes: [u8; 16] = self
            .id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Format("longitud de id de entrada"))?;
        Ok(EntryId(bytes))
    }

    pub fn open(&self, mk: &SecretKey) -> Result<Entry> {
        if self.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        let id = self.entry_id()?;
        let nonce = fixed_nonce(&self.nonce)?;
        let mut plaintext = crypto::open(mk, &nonce, &entry_aad(id), &self.ciphertext)?;
        let entry: Entry = ciborium::from_reader(plaintext.as_slice())
            .map_err(|_| Error::Format("entrada ilegible"))?;
        plaintext.zeroize();
        Ok(entry)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Format("serialización de entrada cifrada"))?;
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| Error::Format("entrada cifrada ilegible"))
    }
}

/// Cómo se desenvuelve la MK con un envoltorio concreto.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WrapperKind {
    /// Envoltorio A: passphrase → Argon2id → KEK.
    Passphrase {
        #[serde(with = "serde_bytes")]
        salt: Vec<u8>,
        kdf: KdfParams,
    },
    /// Envoltorio B: recovery key de 32 bytes usada directamente como KEK. No
    /// pasa por KDF porque ya tiene 256 bits de entropía propia.
    RecoveryKey,
    /// Envoltorios C y D: una clave de 32 bytes que resuelve un dispositivo
    /// externo —WebAuthn PRF en la extensión, HMAC-Secret del dongle—. El campo
    /// `credential` guarda lo que haga falta para volver a pedírsela (el
    /// credential id de WebAuthn, por ejemplo); nunca la clave en sí.
    ExternalKey {
        #[serde(with = "serde_bytes")]
        credential: Vec<u8>,
    },
}

/// Un camino independiente para llegar a la misma MK.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Wrapper {
    /// Etiqueta estable y única dentro de la cabecera; identifica el envoltorio
    /// al usuario ("portátil", "recovery") y entra en el AAD.
    pub label: String,
    pub kind: WrapperKind,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_mk: Vec<u8>,
}

impl Wrapper {
    fn wrap(label: String, kind: WrapperKind, kek: &SecretKey, mk: &SecretKey) -> Result<Self> {
        let nonce = crypto::random_nonce()?;
        let aad = wrapper_aad(&label, &kind)?;
        let wrapped_mk = crypto::seal(kek, &nonce, &aad, mk.as_bytes())?;
        Ok(Self {
            label,
            kind,
            nonce: nonce.to_vec(),
            wrapped_mk,
        })
    }

    fn unwrap_mk(&self, kek: &SecretKey) -> Result<SecretKey> {
        let nonce = fixed_nonce(&self.nonce)?;
        let aad = wrapper_aad(&self.label, &self.kind)?;
        let mut mk_bytes = crypto::open(kek, &nonce, &aad, &self.wrapped_mk)?;
        let mk = SecretKey::try_from_slice(&mk_bytes)?;
        mk_bytes.zeroize();
        Ok(mk)
    }
}

/// Cabecera del vault: la lista de envoltorios de la MK. No contiene ningún
/// dato de las entradas, así que puede publicarse tal cual en el almacén remoto.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultHeader {
    pub version: u32,
    pub wrappers: Vec<Wrapper>,
}

impl VaultHeader {
    /// Crea un vault nuevo: MK aleatoria, envuelta a la vez por la passphrase y
    /// por una recovery key recién generada. La recovery key se devuelve una
    /// única vez —hay que enseñársela al usuario en el setup— y no se guarda.
    pub fn create(passphrase: &[u8], kdf: KdfParams) -> Result<(Self, SecretKey, RecoveryKey)> {
        let mk = SecretKey::generate()?;
        let recovery = RecoveryKey::generate()?;

        let mut header = Self {
            version: FORMAT_VERSION,
            wrappers: Vec::new(),
        };
        header.add_passphrase_wrapper(&mk, "passphrase", passphrase, kdf)?;
        header.add_recovery_wrapper(&mk, "recovery", &recovery)?;

        Ok((header, mk, recovery))
    }

    /// Añade un envoltorio de passphrase. Requiere la MK ya desbloqueada: no se
    /// puede añadir un camino nuevo sin poder recorrer uno existente.
    pub fn add_passphrase_wrapper(
        &mut self,
        mk: &SecretKey,
        label: impl Into<String>,
        passphrase: &[u8],
        kdf: KdfParams,
    ) -> Result<()> {
        let mut salt = [0u8; SALT_LEN];
        crypto::fill_random(&mut salt)?;
        let kek = crypto::derive_kek(passphrase, &salt, kdf)?;
        let kind = WrapperKind::Passphrase {
            salt: salt.to_vec(),
            kdf,
        };
        self.push(Wrapper::wrap(label.into(), kind, &kek, mk)?)
    }

    pub fn add_recovery_wrapper(
        &mut self,
        mk: &SecretKey,
        label: impl Into<String>,
        recovery: &RecoveryKey,
    ) -> Result<()> {
        self.push(Wrapper::wrap(
            label.into(),
            WrapperKind::RecoveryKey,
            &recovery.0,
            mk,
        )?)
    }

    /// Registra un dispositivo externo (WebAuthn PRF o el dongle): la clave la
    /// resuelve el dispositivo y solo se usa aquí para envolver la MK.
    pub fn add_external_wrapper(
        &mut self,
        mk: &SecretKey,
        label: impl Into<String>,
        credential: Vec<u8>,
        key: &SecretKey,
    ) -> Result<()> {
        self.push(Wrapper::wrap(
            label.into(),
            WrapperKind::ExternalKey { credential },
            key,
            mk,
        )?)
    }

    fn push(&mut self, wrapper: Wrapper) -> Result<()> {
        if self.wrappers.iter().any(|w| w.label == wrapper.label) {
            return Err(Error::Format("etiqueta de envoltorio duplicada"));
        }
        self.wrappers.push(wrapper);
        Ok(())
    }

    /// Quita un envoltorio por etiqueta. Se niega a dejar el vault sin ninguno,
    /// que equivaldría a tirar la MK a la basura.
    pub fn remove_wrapper(&mut self, label: &str) -> Result<()> {
        if self.wrappers.len() <= 1 {
            return Err(Error::Format("el vault se quedaría sin envoltorios"));
        }
        let before = self.wrappers.len();
        self.wrappers.retain(|w| w.label != label);
        if self.wrappers.len() == before {
            return Err(Error::NoMatchingWrapper);
        }
        Ok(())
    }

    /// Desbloquea con la passphrase. Prueba todos los envoltorios de ese tipo,
    /// porque puede haber más de uno (varias passphrases registradas).
    pub fn unlock_with_passphrase(&self, passphrase: &[u8]) -> Result<SecretKey> {
        self.check_version()?;
        for wrapper in &self.wrappers {
            let WrapperKind::Passphrase { salt, kdf } = &wrapper.kind else {
                continue;
            };
            let salt: [u8; SALT_LEN] = salt
                .as_slice()
                .try_into()
                .map_err(|_| Error::Format("longitud de sal"))?;
            let kek = crypto::derive_kek(passphrase, &salt, *kdf)?;
            if let Ok(mk) = wrapper.unwrap_mk(&kek) {
                return Ok(mk);
            }
        }
        Err(Error::Decrypt)
    }

    pub fn unlock_with_recovery_key(&self, recovery: &RecoveryKey) -> Result<SecretKey> {
        self.check_version()?;
        self.wrappers
            .iter()
            .filter(|w| matches!(w.kind, WrapperKind::RecoveryKey))
            .find_map(|w| w.unwrap_mk(&recovery.0).ok())
            .ok_or(Error::Decrypt)
    }

    /// Desbloquea con la clave que ha resuelto un dispositivo externo. La
    /// etiqueta la elige el llamante porque es él quien sabe con qué credencial
    /// habló.
    pub fn unlock_with_external_key(&self, label: &str, key: &SecretKey) -> Result<SecretKey> {
        self.check_version()?;
        let wrapper = self
            .wrappers
            .iter()
            .find(|w| w.label == label && matches!(w.kind, WrapperKind::ExternalKey { .. }))
            .ok_or(Error::NoMatchingWrapper)?;
        wrapper.unwrap_mk(key)
    }

    /// La credencial guardada de un envoltorio externo, para poder pedirle al
    /// dispositivo que resuelva su clave antes de desbloquear.
    pub fn external_credential(&self, label: &str) -> Option<&[u8]> {
        self.wrappers.iter().find_map(|w| match &w.kind {
            WrapperKind::ExternalKey { credential } if w.label == label => {
                Some(credential.as_slice())
            }
            _ => None,
        })
    }

    fn check_version(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)
            .map_err(|_| Error::Format("serialización de cabecera"))?;
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let header: Self =
            ciborium::from_reader(bytes).map_err(|_| Error::Format("cabecera ilegible"))?;
        header.check_version()?;
        Ok(header)
    }
}

/// Clave de recuperación de 32 bytes: el camino que funciona en cualquier
/// cliente, incluidos los que no pueden con Argon2id.
pub struct RecoveryKey(SecretKey);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretKey::generate()?))
    }

    pub fn from_key(key: SecretKey) -> Self {
        Self(key)
    }

    /// Base32 sin relleno, en grupos de cuatro separados por guiones, que es lo
    /// que hace legible copiarla a mano o a papel.
    pub fn to_display_string(&self) -> String {
        let encoded = data_encoding::BASE32_NOPAD.encode(self.0.as_bytes());
        let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
        for (i, c) in encoded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Acepta la clave con o sin guiones, espacios y en cualquier caja.
    pub fn parse(s: &str) -> Result<Self> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(char::to_uppercase)
            .collect();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| Error::Format("recovery key no es base32"))?;
        Ok(Self(SecretKey::try_from_slice(&bytes)?))
    }
}

fn entry_aad(id: EntryId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_ENTRY.len() + 16);
    aad.extend_from_slice(AAD_ENTRY);
    aad.extend_from_slice(id.as_bytes());
    aad
}

/// El AAD del envoltorio cubre etiqueta y parámetros (sal, coste, credencial):
/// cambiar cualquiera de ellos en el fichero invalida el MAC en vez de provocar
/// un fallo silencioso de derivación.
fn wrapper_aad(label: &str, kind: &WrapperKind) -> Result<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(AAD_HEADER);
    aad.extend_from_slice(label.as_bytes());
    ciborium::into_writer(kind, &mut aad)
        .map_err(|_| Error::Format("serialización de envoltorio"))?;
    Ok(aad)
}

fn fixed_nonce(nonce: &[u8]) -> Result<[u8; NONCE_LEN]> {
    nonce
        .try_into()
        .map_err(|_| Error::Format("longitud de nonce"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Coste ridículo a propósito: los tests comprueban el cableado, no la
    /// dureza del KDF.
    const TEST_KDF: KdfParams = KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn sample_entry() -> Entry {
        Entry::new(
            "GitHub",
            "joshua@germade.es",
            b"12345678901234567890".to_vec(),
        )
    }

    #[test]
    fn entry_roundtrip_through_encryption() {
        let (_, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let id = EntryId::generate().unwrap();
        let entry = sample_entry();

        let sealed = EncryptedEntry::seal(&mk, id, &entry).unwrap();
        assert_eq!(sealed.open(&mk).unwrap(), entry);
    }

    #[test]
    fn encrypted_entry_survives_serialization() {
        let (_, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let id = EntryId::generate().unwrap();
        let sealed = EncryptedEntry::seal(&mk, id, &sample_entry()).unwrap();

        let bytes = sealed.to_bytes().unwrap();
        assert_eq!(EncryptedEntry::from_bytes(&bytes).unwrap(), sealed);
    }

    #[test]
    fn entry_ciphertext_is_bound_to_its_id() {
        let (_, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let mut sealed =
            EncryptedEntry::seal(&mk, EntryId::generate().unwrap(), &sample_entry()).unwrap();

        // Renombrar el objeto en el almacén remoto no debe colar.
        sealed.id = EntryId::generate().unwrap().as_bytes().to_vec();
        assert_eq!(sealed.open(&mk), Err(Error::Decrypt));
    }

    #[test]
    fn entry_metadata_is_not_in_the_clear() {
        let (_, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let sealed =
            EncryptedEntry::seal(&mk, EntryId::generate().unwrap(), &sample_entry()).unwrap();
        let bytes = sealed.to_bytes().unwrap();

        for needle in [
            b"GitHub".as_slice(),
            b"joshua".as_slice(),
            b"12345678901234567890".as_slice(),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "metadato en claro dentro del blob"
            );
        }
    }

    #[test]
    fn invalid_entries_are_rejected_before_encryption() {
        let (_, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let id = EntryId::generate().unwrap();

        let mut empty_secret = sample_entry();
        empty_secret.secret = SecretBytes::new(Vec::new());
        assert!(EncryptedEntry::seal(&mk, id, &empty_secret).is_err());

        let mut zero_period = sample_entry();
        zero_period.period = 0;
        assert!(EncryptedEntry::seal(&mk, id, &zero_period).is_err());
    }

    #[test]
    fn passphrase_and_recovery_key_reach_the_same_mk() {
        let (header, mk, recovery) = VaultHeader::create(b"correct horse", TEST_KDF).unwrap();

        assert_eq!(header.unlock_with_passphrase(b"correct horse").unwrap(), mk);
        assert_eq!(header.unlock_with_recovery_key(&recovery).unwrap(), mk);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let (header, _, _) = VaultHeader::create(b"correct horse", TEST_KDF).unwrap();
        assert_eq!(
            header.unlock_with_passphrase(b"battery staple"),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn external_wrapper_roundtrip() {
        let (mut header, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        let prf_key = SecretKey::generate().unwrap();

        header
            .add_external_wrapper(&mk, "portátil", b"credential-id".to_vec(), &prf_key)
            .unwrap();

        assert_eq!(
            header.external_credential("portátil"),
            Some(b"credential-id".as_slice())
        );
        assert_eq!(
            header
                .unlock_with_external_key("portátil", &prf_key)
                .unwrap(),
            mk
        );
        assert_eq!(
            header.unlock_with_external_key("portátil", &SecretKey::generate().unwrap()),
            Err(Error::Decrypt)
        );
        assert_eq!(
            header.unlock_with_external_key("otro", &prf_key),
            Err(Error::NoMatchingWrapper)
        );
    }

    #[test]
    fn a_second_passphrase_wrapper_also_opens_the_vault() {
        let (mut header, mk, _) = VaultHeader::create(b"primera", TEST_KDF).unwrap();
        header
            .add_passphrase_wrapper(&mk, "segunda", b"segunda", TEST_KDF)
            .unwrap();

        assert_eq!(header.unlock_with_passphrase(b"primera").unwrap(), mk);
        assert_eq!(header.unlock_with_passphrase(b"segunda").unwrap(), mk);
    }

    #[test]
    fn duplicate_labels_are_rejected() {
        let (mut header, mk, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        assert!(
            header
                .add_passphrase_wrapper(&mk, "passphrase", b"otra", TEST_KDF)
                .is_err()
        );
    }

    #[test]
    fn removing_the_last_wrapper_is_refused() {
        let (mut header, _, _) = VaultHeader::create(b"passphrase", TEST_KDF).unwrap();
        header.remove_wrapper("recovery").unwrap();
        assert!(header.remove_wrapper("passphrase").is_err());
        assert_eq!(header.wrappers.len(), 1);
    }

    #[test]
    fn tampering_with_the_kdf_params_invalidates_the_wrapper() {
        let (mut header, _, _) = VaultHeader::create(b"correct horse", TEST_KDF).unwrap();

        if let WrapperKind::Passphrase { kdf, .. } = &mut header.wrappers[0].kind {
            kdf.t_cost += 1;
        }
        assert_eq!(
            header.unlock_with_passphrase(b"correct horse"),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn header_survives_serialization() {
        let (header, mk, _) = VaultHeader::create(b"correct horse", TEST_KDF).unwrap();
        let bytes = header.to_bytes().unwrap();
        let parsed = VaultHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, header);
        assert_eq!(parsed.unlock_with_passphrase(b"correct horse").unwrap(), mk);
    }

    #[test]
    fn recovery_key_display_roundtrip() {
        let recovery = RecoveryKey::generate().unwrap();
        let shown = recovery.to_display_string();

        assert!(shown.contains('-'));
        let parsed = RecoveryKey::parse(&shown).unwrap();
        assert_eq!(parsed.0, recovery.0);

        // Tal y como la teclearía alguien que no respeta guiones ni mayúsculas.
        let sloppy = shown.replace('-', " ").to_lowercase();
        assert_eq!(RecoveryKey::parse(&sloppy).unwrap().0, recovery.0);
    }

    #[test]
    fn entry_generates_the_expected_code() {
        // Mismo secreto y ventana que el vector del RFC 6238.
        let entry = sample_entry();
        assert_eq!(entry.code_at(59).unwrap(), "287082");
        assert_eq!(entry.seconds_remaining(59), 1);
    }
}
