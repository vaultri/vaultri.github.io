//! Puente entre `totp-core` y la web del vault.
//!
//! Aquí no hay lógica propia: solo traducción de tipos y el formato con el que
//! el navegador persiste su copia local. Toda la cripto y todo el sync viven en
//! el core, que es lo que permite que la extensión, el móvil y el dongle
//! hereden exactamente el mismo comportamiento.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use serde::Serialize;
use wasm_bindgen::prelude::*;

use totp_core::crypto::{KdfParams, SecretKey};
use totp_core::otpauth;
use totp_core::sync::{MemoryStore, Repo, StoreSnapshot};
use totp_core::totp::Algorithm;
use totp_core::vault::{Entry, EntryId, RecoveryKey, VaultHeader};

/// Versión del formato con el que se guarda la copia local.
const SNAPSHOT_VERSION: u32 = 1;

#[wasm_bindgen(start)]
pub fn start() {
    // Sin esto un panic en WASM llega a la consola como "unreachable executed".
    console_error_panic_hook::set_once();
}

/// El vault visto desde JavaScript.
///
/// Mientras está desbloqueado guarda la MK en memoria: derivar Argon2id en cada
/// pulsación de tecla sería inviable. Es la diferencia con la extensión de la
/// fase 2, que desbloquea con WebAuthn PRF y confirmación biométrica en cada
/// uso y por tanto no la retiene.
#[wasm_bindgen]
pub struct Vault {
    header: VaultHeader,
    repo: Repo<MemoryStore>,
    master_key: Option<SecretKey>,
    /// La recovery key recién generada, a la espera de que la UI la enseñe. Se
    /// entrega una sola vez y no se persiste en ningún sitio.
    pending_recovery: Option<String>,
}

#[wasm_bindgen]
impl Vault {
    /// Crea un vault nuevo, ya desbloqueado. La recovery key se recoge después
    /// con `takeRecoveryKey`.
    pub fn create(passphrase: &str) -> Result<Vault, JsError> {
        let (header, master_key, recovery) =
            VaultHeader::create(passphrase.as_bytes(), KdfParams::INTERACTIVE).map_err(js)?;

        Ok(Vault {
            header,
            repo: Repo::new(MemoryStore::new()),
            master_key: Some(master_key),
            pending_recovery: Some(recovery.to_display_string()),
        })
    }

    /// Reconstruye el vault desde la copia local. Vuelve bloqueado: los bytes
    /// guardados no incluyen ninguna clave.
    pub fn restore(bytes: &[u8]) -> Result<Vault, JsError> {
        let snapshot: Snapshot =
            ciborium::from_reader(bytes).map_err(|_| JsError::new("la copia local es ilegible"))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(JsError::new("la copia local es de otra versión"));
        }

        Ok(Vault {
            header: VaultHeader::from_bytes(&snapshot.header).map_err(js)?,
            repo: Repo::new(MemoryStore::from_snapshot(snapshot.store).map_err(js)?),
            master_key: None,
            pending_recovery: None,
        })
    }

    /// Los bytes a guardar en el navegador. Todo va cifrado: quien lea el
    /// `localStorage` no ve ni qué servicios hay dados de alta.
    pub fn export(&self) -> Result<Vec<u8>, JsError> {
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            header: self.header.to_bytes().map_err(js)?,
            store: self.repo.store().snapshot(),
        };

        let mut bytes = Vec::new();
        ciborium::into_writer(&snapshot, &mut bytes)
            .map_err(|_| JsError::new("no se pudo serializar la copia local"))?;
        Ok(bytes)
    }

    /// Devuelve la recovery key recién generada y la olvida. La segunda llamada
    /// da `undefined`: si el usuario no la apuntó, hay que crear otra.
    #[wasm_bindgen(js_name = takeRecoveryKey)]
    pub fn take_recovery_key(&mut self) -> Option<String> {
        self.pending_recovery.take()
    }

    #[wasm_bindgen(getter, js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), JsError> {
        self.master_key = Some(
            self.header
                .unlock_with_passphrase(passphrase.as_bytes())
                .map_err(js)?,
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = unlockWithRecoveryKey)]
    pub fn unlock_with_recovery_key(&mut self, key: &str) -> Result<(), JsError> {
        let recovery = RecoveryKey::parse(key).map_err(js)?;
        self.master_key = Some(
            self.header
                .unlock_with_recovery_key(&recovery)
                .map_err(js)?,
        );
        Ok(())
    }

    /// Suelta la MK. `SecretKey` se borra de memoria al soltarse, así que esto
    /// es todo lo que hace falta.
    pub fn lock(&mut self) {
        self.master_key = None;
    }

    /// Da de alta una entrada desde una URI `otpauth://`, que es lo que hay
    /// dentro de un QR. Devuelve el id de la entrada.
    #[wasm_bindgen(js_name = addUri)]
    pub fn add_uri(&mut self, uri: &str, now: f64) -> Result<String, JsError> {
        let entry = otpauth::parse_uri(uri.trim()).map_err(js)?;
        self.insert(entry, now)
    }

    /// Da de alta una entrada desde los campos sueltos del formulario.
    #[wasm_bindgen(js_name = addEntry)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_entry(
        &mut self,
        issuer: &str,
        account: &str,
        secret: &str,
        algorithm: &str,
        digits: u8,
        period: u32,
        now: f64,
    ) -> Result<String, JsError> {
        let entry = Entry {
            issuer: issuer.trim().to_string(),
            account: account.trim().to_string(),
            secret: totp_core::vault::SecretBytes::new(otpauth::decode_secret(secret).map_err(js)?),
            algorithm: Algorithm::parse(algorithm).map_err(js)?,
            digits,
            period,
            updated_at: 0,
        };
        self.insert(entry, now)
    }

    pub fn remove(&mut self, id: &str, now: f64) -> Result<(), JsError> {
        let master_key = self.unlocked()?;
        let id = EntryId::parse_hex(id).map_err(js)?;
        now_or_never(self.repo.delete(&master_key, id, seconds(now))).map_err(js)?;
        Ok(())
    }

    /// Las entradas con su código vigente, listas para pintar.
    pub fn codes(&self, now: f64) -> Result<JsValue, JsError> {
        let master_key = self.unlocked()?;
        let now = seconds(now);

        let mut views = Vec::new();
        for (id, entry) in now_or_never(self.repo.entries(&master_key)).map_err(js)? {
            views.push(CodeView {
                id: id.to_hex(),
                issuer: entry.issuer.clone(),
                account: entry.account.clone(),
                code: entry.code_at(now).map_err(js)?,
                period: entry.period,
                seconds_remaining: entry.seconds_remaining(now),
            });
        }
        // Alfabético por emisor: es como la busca el ojo en una lista larga.
        views.sort_by(|a, b| {
            a.issuer
                .to_lowercase()
                .cmp(&b.issuer.to_lowercase())
                .then_with(|| a.account.cmp(&b.account))
        });

        serde_wasm_bindgen::to_value(&views).map_err(|err| JsError::new(&err.to_string()))
    }

    /// La URI `otpauth://` de una entrada, para exportarla o hacer un QR.
    /// Lleva el secreto en claro, así que solo se llama a petición explícita.
    #[wasm_bindgen(js_name = uriFor)]
    pub fn uri_for(&self, id: &str) -> Result<String, JsError> {
        let master_key = self.unlocked()?;
        let id = EntryId::parse_hex(id).map_err(js)?;
        let entry = now_or_never(self.repo.get(&master_key, id))
            .map_err(js)?
            .ok_or_else(|| JsError::new("esa entrada no existe"))?;
        Ok(otpauth::to_uri(&entry))
    }

    fn insert(&mut self, entry: Entry, now: f64) -> Result<String, JsError> {
        let master_key = self.unlocked()?;
        let id = EntryId::generate().map_err(js)?;
        now_or_never(self.repo.put(&master_key, id, &entry, seconds(now))).map_err(js)?;
        Ok(id.to_hex())
    }

    /// La MK, o un error si el vault está bloqueado.
    ///
    /// Devuelve una copia en vez de un préstamo para no atar el resto de `self`
    /// mientras se opera sobre el repo. La copia se borra de memoria al salir
    /// del ámbito, igual que la original.
    fn unlocked(&self) -> Result<SecretKey, JsError> {
        self.master_key
            .clone()
            .ok_or_else(|| JsError::new("el vault está bloqueado"))
    }
}

/// Lo que se guarda en el navegador.
#[derive(serde::Serialize, serde::Deserialize)]
struct Snapshot {
    version: u32,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    store: StoreSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodeView {
    id: String,
    issuer: String,
    account: String,
    code: String,
    period: u32,
    seconds_remaining: u32,
}

/// Resuelve un futuro que ya está listo.
///
/// El core es `async` porque el backend de la fase siguiente será `fetch`
/// contra Drive, pero contra el almacén en memoria ninguna de estas operaciones
/// llega a suspenderse. Se sondea una vez y ya: nada de bloquear el hilo
/// principal del navegador, que además no se puede.
fn now_or_never<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => {
            unreachable!("el almacén en memoria resuelve sin suspenderse")
        }
    }
}

fn seconds(now: f64) -> u64 {
    now.max(0.0) as u64
}

fn js(err: totp_core::Error) -> JsError {
    JsError::new(&err.to_string())
}
