# vaultrie

Gestor de TOTP multiplataforma con núcleo en Rust, cifrado cliente-side y
sincronización sobre un almacén no confiable.

El plan completo —arquitectura, modelo de cifrado, fases— está en
[`ROADMAP.md`](ROADMAP.md).

## Estado

Fase 1 en curso. Lo que hay hoy:

| Componente | Estado |
|---|---|
| `crates/totp-core` — cripto del vault y generación de códigos | funcional, con tests |
| Sync content-addressed contra Google Drive | pendiente |
| Vault web (WASM) | pendiente |
| Extensión de Chrome, dongle, móvil | fases 2-5 |

## `totp-core`

Todo lo que no depende de la plataforma. Los clientes ponen la UI, el
almacenamiento y el reloj; la cripto y el formato viven aquí una sola vez.

- **`totp`** — HOTP (RFC 4226) y TOTP (RFC 6238) sobre SHA-1/256/512, con los
  vectores de ambos RFCs como tests. La verificación admite desfase de reloj y
  compara en tiempo constante.
- **`otpauth`** — lectura y escritura de URIs `otpauth://totp/…`, las que van
  dentro de los QR. Tolerante al leer (relleno base32, minúsculas, parámetros
  desconocidos, `issuer` duplicado en el label), estricta al escribir.
- **`crypto`** — XChaCha20-Poly1305 para todo lo que se cifra y Argon2id para
  derivar KEKs. Las claves se borran de memoria al soltarse, no se imprimen en
  `Debug` y se comparan en tiempo constante.
- **`vault`** — el formato en disco: cabecera con los envoltorios de la Master
  Key, y entradas cifradas de una en una.

### Cómo se protege el vault

Una única **Master Key** cifra las entradas y se envuelve por varios caminos
independientes; desbloquear por cualquiera de ellos da la misma MK:

| Envoltorio | Mecanismo | Estado |
|---|---|---|
| A | Passphrase → Argon2id → KEK | implementado |
| B | Recovery key de 32 bytes | implementado |
| C | WebAuthn PRF (extensión) | soportado como clave externa |
| D | HMAC-Secret del dongle | soportado como clave externa |

C y D comparten representación (`WrapperKind::ExternalKey`): en ambos casos el
dispositivo resuelve 32 bytes y el vault solo guarda con qué credencial hay que
volver a pedírselos, nunca la clave.

Cada entrada se cifra por separado —secreto **y** metadatos: issuer y cuenta no
viajan en claro— y su ciphertext queda atado a su identificador vía el AAD, así
que renombrar o mover el objeto en el almacén remoto invalida el MAC en vez de
pasar desapercibido. Lo mismo con los envoltorios: el AAD cubre etiqueta, sal y
parámetros del KDF.

Los parámetros de Argon2id se guardan junto al envoltorio en lugar de fijarse en
el código, para poder subirlos con el tiempo sin romper vaults ya creados.

### Uso

```rust
use totp_core::crypto::KdfParams;
use totp_core::vault::{EncryptedEntry, EntryId, VaultHeader};

let (header, mk, recovery) = VaultHeader::create(b"correct horse", KdfParams::INTERACTIVE)?;
println!("guarda esto: {}", recovery.to_display_string());

let entry = totp_core::otpauth::parse_uri("otpauth://totp/GitHub:yo?secret=JBSWY3DPEHPK3PXP")?;
let sealed = EncryptedEntry::seal(&mk, EntryId::generate()?, &entry)?;

let bytes = sealed.to_bytes()?;   // lo que se sube al almacén remoto
let header_bytes = header.to_bytes()?;
```

## Desarrollo

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --target wasm32-unknown-unknown   # el core tiene que seguir yendo a WASM
```

## Licencia

MIT o Apache-2.0, a elección.
