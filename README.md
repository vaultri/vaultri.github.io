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
| Sync granular direccionado por contenido | funcional, con tests |
| Vault web (WASM) | funcional |
| Backend de Google Drive (`appDataFolder`) | funcional, con tests contra un doble |
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
- **`sync`** — un control de versiones diminuto sobre un almacén no confiable:
  objetos inmutables, commits, y fusión por el ancestro común.

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

### El sync

El remoto es un blob store tonto —el `appDataFolder` de Drive— que no puede
resolver nada por nosotros, así que el modelo es el de un control de versiones
diminuto que corre entero en el cliente:

- Cada versión de una entrada es un **objeto inmutable** nombrado por el
  SHA-256 de sus bytes cifrados. Editar no reescribe nada: crea un objeto nuevo.
  Solo viajan los objetos que al otro lado le falten.
- Cada cambio produce un **commit** con el árbol completo y el enlace a su
  padre. El árbol lleva el `updated_at` de cada entrada, de modo que **fusionar
  no descifra ni una sola entrada**: bastan los commits.
- Los clientes reconcilian **fusionando por el ancestro común**. Gana el cambio
  más reciente, borrado incluido; como la historia es inmutable, lo que pierde
  el desempate sigue recuperable desde un commit anterior. Un borrado deja
  lápida, para que un peer desactualizado no resucite la entrada.
- El merge es **determinista**: dos clientes que fusionen las mismas dos puntas
  producen el mismo objeto byte a byte y convergen sin dar otra vuelta. Para eso
  el nonce de un commit se deriva de su propio contenido en vez de ser aleatorio.
- El `head` se mueve con **compare-and-set**, y todo lo publicado se anota antes
  en un **`known-commits.log`** append-only. Perder la carrera del `head` no
  pierde el commit: sigue siendo descubrible y el siguiente sync lo recoge.
- Todo lo que sale del almacén se **verifica contra su hash** antes de usarse.

El almacén está detrás de un trait de siete métodos (`ObjectStore`), así que la
fase 3 puede reutilizar el mismo motor para hablar con el dongle por WebHID
cambiando solo esa implementación. `MemoryStore` la implementa en memoria y
`DriveStore` sobre el `appDataFolder` de Google Drive.

```rust
use totp_core::sync::{sync, MemoryStore, Repo};

let mut local = Repo::new(MemoryStore::new());
local.put(&mk, id, &entry, now).await?;          // commit local
sync(local.store_mut(), &mut remote, &mk, now).await?;
```

### El backend de Drive

`DriveStore` guarda cada objeto como un fichero de la carpeta privada de la
aplicación, nombrado por su hash. Además del `head` y los objetos, la carpeta
lleva la **cabecera del vault**: sin ella un dispositivo nuevo tendría objetos
que nadie sabe abrir. Sigue sin decirle nada a Google —para desenvolverla hace
falta la passphrase—, y no se reescribe nunca: si la cuenta ya guarda otro
vault, el sync se para en vez de dejar sus entradas ilegibles.

| Fichero | Contenido |
|---|---|
| `<hex>` | un objeto inmutable, nombrado por su hash |
| `head` | el hash del commit vigente |
| `known-<hex>` | una línea del `known-commits.log` |
| `header` | los envoltorios de la Master Key |

Dos decisiones que impone la API:

- **El log va como un fichero por línea.** Drive no sabe añadir al final de un
  fichero existente, y reescribirlo entero convertiría cada anotación en una
  carrera que puede perder líneas. Crear un fichero nuevo no compite con nadie.
- **El compare-and-set se apoya en el `headRevisionId`.** Antes de mover el
  `head` se comprueba que la revisión sigue siendo la esperada y se manda además
  `If-Match`. Lo primero cierra la carrera larga aunque la API ignorase la
  precondición; lo segundo, la corta, si la respeta. Y si aun así se pierde una
  escritura, el commit ya está en el log y lo recoge el siguiente sync.

El core no hace peticiones: quien las hace es un `http::HttpClient` que aporta
la plataforma, y que es también quien pone el `Authorization`. Ni el core ni el
puente WASM llegan a ver un token.

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

## La web

`web/` es el vault en el navegador y `crates/totp-web` el puente WASM que lo
conecta con el core. En el puente no hay lógica propia: solo traducción de tipos
y el formato de la copia local, porque todo lo que toca claves tiene que ser el
mismo código que usarán la extensión, el móvil y el dongle.

Funciona entero: crear el vault, apuntar la clave de recuperación, dar de alta
entradas pegando una URI `otpauth://` o a mano, ver los códigos con su cuenta
atrás, copiarlos, bloquear —a mano o solo, tras cinco minutos de inactividad— y
sincronizar con Drive. El vault cifrado se guarda en el `localStorage` del
navegador; sin conectar Drive vive solo ahí, y borrar los datos del sitio lo
borra.

### Conectar Drive

Todo lo que sabe de Google está en `web/drive.js`, y el client id en
`web/config.js`. No hay secreto que esconder —esto es una web estática— así que
el flujo es el de cliente público: Google Identity Services da un access token
de vida corta que se renueva en silencio y no se guarda en disco. El script de
Google se carga la primera vez que se conecta la cuenta, no antes: quien no
sincronice no pide nada a Google.

Para levantar tu propia copia con sync hace falta un client id de OAuth
—«aplicación web», con el scope `drive.appdata` y tu origen autorizado— puesto
en `web/config.js`. Vacío, la web funciona igual pero solo contra este
navegador.

Un dispositivo nuevo arranca desde **«Traerlo desde Drive»**: se baja la
cabecera del vault, se desbloquea con la passphrase de siempre y el primer sync
trae las entradas.

Mientras está desbloqueado, la MK vive en memoria del WASM: derivar Argon2id en
cada pulsación sería inviable. Es la diferencia con la extensión de la fase 2,
que desbloqueará con WebAuthn PRF y confirmación biométrica en cada uso y por
tanto no la retendrá.

```sh
cargo install wasm-pack   # o el binario de las releases del proyecto
wasm-pack build crates/totp-web --target web --out-dir ../../web/pkg --release
python3 -m http.server -d web 8765    # http://127.0.0.1:8765
```

El despliegue va a GitHub Pages desde Actions (`.github/workflows/pages.yml`),
que compila el WASM y sube `web/` en cada push a `main`. Requiere tener puesto
**Settings → Pages → Source: GitHub Actions** una vez.

## Desarrollo

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --target wasm32-unknown-unknown   # el core tiene que seguir yendo a WASM
```

Las pruebas de navegador cubren lo que Rust no puede: el puente WASM, el OAuth y
el pintado, contra un doble del `appDataFolder` que habla el mismo dialecto que
la API de verdad. Necesitan el WASM ya compilado en `web/pkg`:

```sh
npm ci
npx playwright install chromium
npx playwright test
```

## Licencia

MIT o Apache-2.0, a elección.
