# Riesgos y puntos abiertos

## Puntos abiertos heredados del roadmap

### WebHID y el bloqueo de dispositivos FIDO

Chrome bloquea el acceso por WebHID a dispositivos FIDO. **Hay que confirmar con
un prototipo que ese bloqueo actúa por interfaz (top-level collection) y no por
dispositivo completo.**

- Si actúa por interfaz: el diseño de la fase 3 se sostiene — interfaz FIDO
  siempre presente y canal de sync vendor-specific conviviendo en el mismo USB.
- Si actúa por dispositivo: no se puede sincronizar por WebHID un dongle que
  además sea llave FIDO. Habría que separar los dos papeles, usar otro
  transporte, o renunciar a sincronizar desde el navegador.

Es el riesgo con peor relación entre coste de comprobarlo (días) y coste de
descubrirlo tarde (rediseño de dos fases). Va lo primero de la fase 3.

### PIN por botón en el dongle

Falta definir el mecanismo de PIN para el desbloqueo local (envoltorio D), si se
decide no depender únicamente de la posesión física. Con un solo botón y una
pantalla pequeña, introducir un PIN es un problema de UI real, no un detalle.

## Riesgos técnicos de la fase 1

**Compare-and-set sobre Drive.** Sigue abierto, pero acotado. El testigo acabó
siendo el `headRevisionId`, y `set_head` comprueba la revisión antes de escribir
además de mandar `If-Match`: la comprobación previa cierra la carrera larga
aunque la API ignorase la precondición, y hay un test con un servidor que la
ignora a propósito. Falta confirmar contra una cuenta de verdad si la respeta y
con qué código falla. Mitigación ya incorporada al diseño: el
`known-commits.log` append-only hace que perder la carrera **no pierda el
commit**.

**Argon2id en WASM.** 64 MiB y 3 pasadas es tolerable en escritorio; en móvil de
gama baja dentro de un navegador está por medir. Los parámetros van guardados
junto al envoltorio precisamente para poder ajustarlos sin romper vaults
existentes, pero bajarlos debilita el envoltorio A.

**Cuota del `appDataFolder`.** La historia es inmutable y nunca se reescribe, así
que crece de forma monótona, y ahora además cada línea del `known-commits.log`
es un fichero. Falta medir cuánto ocupa un vault real con uso prolongado, cuánto
cuesta en llamadas un sync típico, y decidir si hará falta alguna forma de poda.

**OAuth sin backend.** La web es estática sobre GitHub Pages: no hay dónde
esconder un client secret. Resuelto con el flujo de cliente público de Google
Identity Services: token de vida corta, renovado en silencio y nunca guardado en
disco. La limitación que queda es que, si Google no renueva sin preguntar, hay
que volver a pulsar «Conectar» — los navegadores bloquean los popups que no
salen de un clic.

## Riesgos de producto

**La MK en memoria en la web.** Es una concesión consciente —derivar Argon2id en
cada pulsación sería inviable— y una diferencia real de postura de seguridad
frente a la extensión. Conviene que quede explicada en la propia UI, no solo en
el README.

**`localStorage` como única copia si no se conecta Drive.** Con el sync
conectado hay una segunda copia y un dispositivo nuevo puede recuperar el vault
entero con la passphrase. Sin conectarlo, borrar los datos del sitio sigue
borrando el vault, y la recovery key es lo único que salva al usuario — solo si
la apuntó.

**Soporte de navegador desigual.** WebAuthn PRF maduro solo en Chrome/Edge;
WebHID solo en Chrome/Edge/Opera de escritorio. El envoltorio A (passphrase)
tiene que seguir siendo el camino universal, sin degradarse a ciudadano de
segunda.

## Deuda conocida

- **La capa JS se prueba contra dobles.** Los cuatro tests de navegador cubren
  el camino entero, pero Google y Drive los pone un doble: nada de esto ha
  hablado todavía con la API real.
- **El puente WASM no tiene tests propios.** Lo que ejercita `Vault.sync` es el
  test de navegador; no hay nada a nivel de `wasm-bindgen-test`.
- **Nada poda la historia.** Ni objetos viejos ni líneas del log: todo lo que se
  publica se queda.
