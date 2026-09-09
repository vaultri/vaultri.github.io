# Fase 1 — Vault en web + sync con Google Drive

**Estado: funcional de punta a punta; falta probarla contra Drive de verdad.**
Es la fase que valida todo lo demás: si la cripto, el formato de entrada y el
modelo de sync aguantan aquí, las fases 2 a 5 son clientes nuevos sobre piezas
ya probadas.

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
- [x] `DriveStore` — el mismo trait sobre el `appDataFolder` de Google Drive
- [x] OAuth de cliente público con Google Identity Services
- [x] `Vault.sync()` en el puente WASM, con el transporte HTTP inyectado desde JS
- [x] UI de sync: conectar, estado, y qué se cuenta cuando hubo fusión
- [x] Arranque de un dispositivo nuevo bajando la cabecera del vault de Drive
- [x] Web funcional: alta, códigos con cuenta atrás, copia, bloqueo manual y por
      inactividad, persistencia en `localStorage`
- [x] CI con fmt, clippy, tests, build a WASM y reproducción de la build de
      despliegue
- [x] Pruebas de navegador con Playwright contra un doble del `appDataFolder`
- [x] Despliegue a GitHub Pages desde Actions

### Cómo quedó el backend de Drive

Los puntos que esta fase tenía que decidir, decididos:

- **`set_head` con compare-and-set.** El testigo opaco es el `headRevisionId`
  del fichero `head`. Antes de escribir se comprueba que la revisión sigue
  siendo la esperada, y además se manda `If-Match`; se tratan 409, 412 y 428
  como «llegué tarde». La comprobación previa cierra la carrera larga aunque la
  API ignorase la precondición — que es justo lo que falta por confirmar contra
  una cuenta de verdad.
- **`known_commits`.** Un fichero por línea (`known-<hex>`). Drive no sabe
  añadir al final de un fichero existente, y reescribirlo entero convertiría
  cada anotación en una carrera que puede perder líneas.
- **Listado y `contains`.** Un índice de nombre → fichero que se relee al leer
  el `head`, que es cuando el motor de sync empieza a mirar el remoto. `contains`
  y `put` se fían del índice —un falso «no está» solo cuesta una subida de más
  de un objeto idéntico—; `get` pregunta por el nombre concreto antes de
  rendirse, porque ahí un falso «no está» sí rompería el sync.
- **La cabecera del vault.** No estaba en el plan y hacía falta: sin ella, un
  navegador nuevo se encuentra objetos que nadie sabe abrir. Va como un fichero
  más de la carpeta y no se reescribe nunca; si la cuenta ya guarda otro vault,
  el sync se para en vez de dejar sus entradas ilegibles.

## Pendiente

### Antes de dar la fase por cerrada del todo

1. **Probarlo contra Drive de verdad.** Todo lo de arriba está verificado contra
   dobles que hablan el mismo dialecto, no contra la API. Queda por confirmar
   con una cuenta real: que `If-Match` se respeta en el update del `head` y con
   qué código falla, que el `headRevisionId` cambia en cada escritura de
   contenido, y cómo se comporta el listado con muchos objetos.
2. **Cuotas y tamaño.** Medir cuánto ocupa un vault con historia y cuántas
   llamadas cuesta un sync típico. El `appDataFolder` tiene límite y cada
   listado cuenta.
3. **Client id del despliegue.** `web/config.js` va vacío en el repo: el sync
   solo se enciende en un despliegue que ponga el suyo.

### Fuera del criterio de cierre, pero pedido por el uso

- Editar una entrada ya dada de alta (hoy solo alta y baja).
- Poda del historial: nada borra objetos viejos todavía.

## Criterio de cierre

La fase 1 está hecha cuando dos navegadores distintos, con la misma cuenta de
Google y la misma passphrase, convergen al mismo conjunto de entradas después de
editar cada uno por su lado estando desconectados — y el remoto no ha aprendido
nada sobre el contenido.

**Cumplido contra un doble del `appDataFolder`**, tanto en Rust
(`crates/totp-core/tests/drive.rs`) como en el navegador de verdad
(`tests/vault.spec.js`, con Playwright: dos contextos distintos, la misma cuenta
de mentira, y la comprobación de que a Drive no llega nada en claro). Falta
repetirlo contra la API real.
