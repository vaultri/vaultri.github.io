# Fase 1 — Vault en web + sync con Google Drive

**Estado: en curso.** Es la fase que valida todo lo demás: si la cripto, el
formato de entrada y el modelo de sync aguantan aquí, las fases 2 a 5 son
clientes nuevos sobre piezas ya probadas.

## Objetivo

Un vault usable en el navegador que sincronice contra el `appDataFolder` de
Google Drive, con el módulo de sync desacoplado de la UI para poder reutilizarlo
en la fase 3 como puente WebHID con el dongle.

## Hecho

- [x] `totp` — HOTP y TOTP con los vectores de ambos RFCs como tests
- [x] `otpauth` — lectura y escritura de URIs, tolerante al leer
- [x] `crypto` — XChaCha20-Poly1305 y Argon2id, claves que se borran al soltarse
- [x] `vault` — cabecera con envoltorios, entradas cifradas por separado
- [x] Envoltorio A (passphrase) y B (recovery key)
- [x] Representación de los envoltorios C y D como `ExternalKey`
- [x] `sync` — objetos inmutables, commits, merge por ancestro común, `head` con
      compare-and-set, `known-commits.log`
- [x] `ObjectStore` como trait de siete métodos, con `MemoryStore` de referencia
- [x] Puente WASM `totp-web` con las 13 operaciones del ciclo de vida del vault
- [x] Web funcional: alta, códigos con cuenta atrás, copia, bloqueo manual y por
      inactividad, persistencia en `localStorage`
- [x] CI con fmt, clippy, tests, build a WASM y reproducción de la build de
      despliegue
- [x] Despliegue a GitHub Pages desde Actions

## Pendiente

### 1. Backend de Google Drive (`appDataFolder`)

Implementar `ObjectStore` sobre `fetch` contra la API de Drive. Hoy no existe ni
una línea: «Drive» solo aparece en comentarios del código.

Puntos a resolver:

- **`set_head` con compare-and-set.** El testigo opaco será el ETag de Drive.
  Hay que confirmar que la API respeta `If-Match` en el update del fichero de
  `head` y qué código devuelve al fallar, para distinguir «perdí la carrera» de
  «error de red».
- **`known_commits`.** El log es append-only; Drive no tiene append nativo, así
  que hay que decidir entre reescribir el fichero entero o un objeto por línea.
- **Listado y `contains`.** Cuántas llamadas cuesta y si conviene cachear el
  índice de objetos localmente.
- **Cuotas y tamaño.** `appDataFolder` tiene límite; medir cuánto ocupa un vault
  real con historia.

### 2. OAuth con Google

Obtención y refresco del token con el scope `drive.appdata`. Sin empezar. En una
web estática sobre GitHub Pages no hay backend donde esconder un client secret,
así que va con el flujo implícito/PKCE de cliente público.

### 3. Exponer el sync en el puente WASM

`totp-web` no publica ninguna operación de sincronización. Hay que sacar `sync()`
a JS y decidir el manejo de errores de red y de conflicto de `head`.

### 4. UI de sync en `web/`

Conectar cuenta, estado de la última sincronización, y qué se le enseña al
usuario cuando el merge descarta un cambio: sigue recuperable desde un commit
anterior, pero hay que contarlo.

### 5. Tests del backend remoto

El `ObjectStore` de Drive necesita sus propios tests contra un doble. Los 11 de
`tests/sync.rs` solo ejercitan `MemoryStore`. Tampoco hay ninguna prueba
automatizada de la capa JS.

## Criterio de cierre

La fase 1 está hecha cuando dos navegadores distintos, con la misma cuenta de
Google y la misma passphrase, convergen al mismo conjunto de entradas después de
editar cada uno por su lado estando desconectados — y el remoto no ha aprendido
nada sobre el contenido. Los tests de `tests/sync.rs` ya comprueban ambas cosas
contra `MemoryStore`; falta que sea cierto contra Drive de verdad.
