# Estado actual — 2026-09-09

Medido sobre la rama `claude/intelligent-ride-htpyc7`, después de conectar el
sync con Drive. El trabajo arrancó el 2026-08-30.

## Resumen

| Componente | Estado |
|---|---|
| `crates/totp-core` — cripto del vault y generación de códigos | **funcional, con tests** |
| Sync granular direccionado por contenido | **funcional, con tests** |
| Vault web (WASM) | **funcional, sincronizando** |
| Backend de Google Drive (`appDataFolder`) | **funcional, probado contra un doble** |
| Extensión de Chrome, dongle, móvil | fases 2–5 |

## Verificación de hoy

`cargo test` en limpio: **88 tests en verde, 0 fallos**, más **4 de navegador**
con Playwright.

| Suite | Tests |
|---|---|
| Unitarios de `totp-core` | 62 |
| Integración `tests/sync.rs` (almacén en memoria) | 11 |
| Integración `tests/drive.rs` (doble del `appDataFolder`) | 14 |
| Doctests | 1 |
| Navegador — `tests/vault.spec.js` | 4 |

No hay ningún `TODO`, `FIXME`, `todo!()` ni `unimplemented!()` en el árbol.

## `crates/totp-core` — 3792 líneas

| Módulo | Líneas | Contenido |
|---|---|---|
| `sync/` | 1813 | `drive` (592), `engine` (442), `store` (312), `objects` (305), `merge` (185), `repo` (151), `mod` (26) |
| `vault` | 726 | Cabecera con envoltorios de la MK, entradas cifradas de una en una, recovery key |
| `otpauth` | 323 | Lectura/escritura de URIs `otpauth://totp/…` |
| `totp` | 242 | HOTP (RFC 4226) y TOTP (RFC 6238) sobre SHA-1/256/512 |
| `crypto` | 220 | XChaCha20-Poly1305 y Argon2id |
| `http` | 119 | Los tipos de una petición y el trait que la ejecuta; ninguna implementación |
| `error`, `byte_array`, `lib` | 149 | Tipos de apoyo |

`sync/drive` implementa el mismo `ObjectStore` sobre el `appDataFolder`: un
fichero por objeto nombrado por su hash, el `head` con compare-and-set sobre el
`headRevisionId`, el `known-commits.log` como un fichero por línea y la cabecera
del vault, que es lo que permite arrancar un dispositivo nuevo. El core no hace
peticiones: las hace quien implemente `http::HttpClient`, que es también quien
pone el `Authorization` — ni el core ni el puente ven un token.

Detalles que ya están resueltos y conviene no volver a discutir:

- La verificación de códigos admite desfase de reloj y compara en tiempo
  constante.
- `otpauth` es **tolerante al leer** (relleno base32, minúsculas, parámetros
  desconocidos, `issuer` duplicado en el label, parámetros vacíos tratados como
  ausentes) y **estricta al escribir**. Los vectores de ambos RFCs corren como
  tests.
- La API pública del vault cubre el ciclo entero: `create`,
  `add_passphrase_wrapper`, `add_recovery_wrapper`, `add_external_wrapper`,
  `remove_wrapper`, los tres `unlock_with_*`, y `to_bytes` / `from_bytes`.
- El `Repo` expone `put`, `get`, `delete`, `entries`, `tree`, `commit` y
  `commit_tree`; `sync()` devuelve un `SyncReport` que sabe decir si no hizo
  nada.

## `crates/totp-web` — 524 líneas

El puente WASM. **Sin lógica propia**: traducción de tipos y formato de la copia
local, porque todo lo que toca claves tiene que ser el mismo código que usarán
la extensión, el móvil y el dongle.

Métodos expuestos a JS: `create`, `restore`, `fromHeader`, `export`,
`takeRecoveryKey`, `isUnlocked`, `unlock`, `unlockWithRecoveryKey`, `lock`,
`addUri`, `addEntry`, `remove`, `codes`, `uriFor`, `sync`, y la función suelta
`fetchHeader`.

`sync` recibe de JS la función que hace las peticiones —con el token dentro— y
sincroniza sobre una copia del almacén: el préstamo del objeto no puede cruzar
un `await`, y así un sync que falle a medias no deja la copia local a medio
escribir. Por lo mismo todo el estado va en `RefCell` y todos los métodos toman
`&self`: si no, el reloj que pide los códigos cada segundo reventaría en mitad
de un sync.

## `web/` — 1331 líneas

`app.js` (521), `style.css` (440), `index.html` (183), `drive.js` (176),
`config.js` (11).

Funciona de punta a punta: crear el vault, apuntar la clave de recuperación, dar
de alta entradas pegando una URI `otpauth://` o a mano, ver los códigos con su
cuenta atrás, copiarlos, bloquear —a mano o solo, tras cinco minutos de
inactividad— y sincronizar con Drive. El vault cifrado se guarda en el
`localStorage` del navegador; sin conectar Drive vive solo ahí.

Todo lo que sabe de Google está en `drive.js`: el token, cómo se pide y cómo se
renueva. Es OAuth de cliente público con Google Identity Services —no hay
backend donde esconder un secreto—, el token es de vida corta y no se guarda en
disco, y el script de Google se carga la primera vez que se conecta la cuenta,
no antes. El client id vive en `config.js` y va vacío en el repo: cada
despliegue pone el suyo.

Mientras está desbloqueado, la MK vive en memoria del WASM: derivar Argon2id en
cada pulsación sería inviable. Es la diferencia deliberada con la extensión de
la fase 2, que desbloqueará con WebAuthn PRF y biometría en cada uso y por tanto
no la retendrá.

## CI y despliegue

`.github/workflows/ci.yml`, en cada push a `main` y en cada PR:

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo build --target wasm32-unknown-unknown` — el core tiene que seguir
  yendo a WASM
- Un job aparte reproduce **exactamente la build del despliegue** con
  `wasm-pack`, comprueba que `web/` queda completa y corre las pruebas de
  navegador con Playwright. Sin esto, que la web no se pueda construir solo se
  descubriría al llegar a `main`, que es donde despliega Pages.

`.github/workflows/pages.yml` publica en GitHub Pages en cada push a `main`.
Requiere tener puesto **Settings → Pages → Source: GitHub Actions** una vez.

## Lo que falta para cerrar la fase 1

Detallado en [`04-fase-1-vault-web.md`](04-fase-1-vault-web.md). En corto:
probarlo contra Drive de verdad. Todo lo que hay está verificado contra dobles
que hablan el mismo dialecto que la API, no contra la API — falta confirmar el
`If-Match` del `head`, medir cuota y llamadas, y poner un client id en un
despliegue real.
