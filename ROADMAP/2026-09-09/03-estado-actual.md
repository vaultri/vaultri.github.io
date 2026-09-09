# Estado actual — 2026-09-09

Medido sobre el commit `8554ba4` de la rama `claude/epic-pasteur-oywl28`. El
trabajo arrancó el 2026-08-30.

## Resumen

| Componente | Estado |
|---|---|
| `crates/totp-core` — cripto del vault y generación de códigos | **funcional, con tests** |
| Sync granular direccionado por contenido | **funcional, con tests** |
| Vault web (WASM) | **funcional, sin sincronizar** |
| Backend de Google Drive (`appDataFolder`) | pendiente |
| Extensión de Chrome, dongle, móvil | fases 2–5 |

## Verificación de hoy

`cargo test` en limpio: **71 tests en verde, 0 fallos**.

| Suite | Tests |
|---|---|
| Unitarios de `totp-core` | 59 |
| Integración `tests/sync.rs` | 11 |
| Doctests | 1 |

No hay ningún `TODO`, `FIXME`, `todo!()` ni `unimplemented!()` en el árbol.

## `crates/totp-core` — 2807 líneas

| Módulo | Líneas | Contenido |
|---|---|---|
| `vault` | 726 | Cabecera con envoltorios de la MK, entradas cifradas de una en una, recovery key |
| `sync/` | 1207 | `objects` (305), `engine` (442), `store` (312), `repo` (151), `merge` (185), `mod` (24) |
| `otpauth` | 323 | Lectura/escritura de URIs `otpauth://totp/…` |
| `totp` | 242 | HOTP (RFC 4226) y TOTP (RFC 6238) sobre SHA-1/256/512 |
| `crypto` | 220 | XChaCha20-Poly1305 y Argon2id |
| `error`, `byte_array` | 114 | Tipos de apoyo |

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

## `crates/totp-web` — 271 líneas

El puente WASM. **Sin lógica propia**: traducción de tipos y formato de la copia
local, porque todo lo que toca claves tiene que ser el mismo código que usarán
la extensión, el móvil y el dongle.

Métodos expuestos a JS: `create`, `restore`, `export`, `take_recovery_key`,
`is_unlocked`, `unlock`, `unlock_with_recovery_key`, `lock`, `add_uri`,
`add_entry`, `remove`, `codes`, `uri_for`.

Internamente ya monta un `Repo<MemoryStore>` y serializa un `StoreSnapshot`, así
que el motor de sync está enganchado aunque el remoto todavía no exista. Lo que
**no** expone todavía: ninguna operación de sincronización.

## `web/` — 946 líneas

`index.html` (169), `app.js` (373), `style.css` (404).

Funciona de punta a punta contra el almacén en memoria: crear el vault, apuntar
la clave de recuperación, dar de alta entradas pegando una URI `otpauth://` o a
mano, ver los códigos con su cuenta atrás, copiarlos, y bloquear —a mano o solo,
tras cinco minutos de inactividad—. El vault cifrado se guarda en el
`localStorage` del navegador; **el sync con Drive todavía no está conectado**,
así que borrar los datos del sitio borra el vault.

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
  `wasm-pack` y comprueba que `web/` queda completa. Sin esto, que la web no se
  pueda construir solo se descubriría al llegar a `main`, que es donde despliega
  Pages.

`.github/workflows/pages.yml` publica en GitHub Pages en cada push a `main`.
Requiere tener puesto **Settings → Pages → Source: GitHub Actions** una vez.

## Lo que falta para cerrar la fase 1

Detallado en [`04-fase-1-vault-web.md`](04-fase-1-vault-web.md). En corto: el
backend de Drive, OAuth, exponer el sync en WASM, la UI de sync, y los tests de
esa capa.
