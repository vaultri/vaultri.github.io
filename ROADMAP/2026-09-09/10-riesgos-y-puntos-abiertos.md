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

**Compare-and-set sobre Drive.** Todo el modelo de sync descansa en poder mover
el `head` condicionalmente. Si `If-Match` sobre el ETag no se comporta como se
espera, o no distingue bien «perdí la carrera» de «error de red», hay que
rediseñar esa parte. Mitigación ya incorporada al diseño: el
`known-commits.log` append-only hace que perder la carrera **no pierda el
commit**.

**Argon2id en WASM.** 64 MiB y 3 pasadas es tolerable en escritorio; en móvil de
gama baja dentro de un navegador está por medir. Los parámetros van guardados
junto al envoltorio precisamente para poder ajustarlos sin romper vaults
existentes, pero bajarlos debilita el envoltorio A.

**Cuota del `appDataFolder`.** La historia es inmutable y nunca se reescribe, así
que crece de forma monótona. Falta medir cuánto ocupa un vault real con uso
prolongado y decidir si hará falta alguna forma de poda.

**OAuth sin backend.** La web es estática sobre GitHub Pages: no hay dónde
esconder un client secret. Flujo de cliente público con PKCE, con las
limitaciones que eso trae.

## Riesgos de producto

**La MK en memoria en la web.** Es una concesión consciente —derivar Argon2id en
cada pulsación sería inviable— y una diferencia real de postura de seguridad
frente a la extensión. Conviene que quede explicada en la propia UI, no solo en
el README.

**`localStorage` como única copia hoy.** Mientras el sync no esté conectado,
borrar los datos del sitio borra el vault. La recovery key es lo único que salva
al usuario, y solo si la apuntó. Es el argumento más fuerte para no dejar la
fase 1 a medias mucho tiempo.

**Soporte de navegador desigual.** WebAuthn PRF maduro solo en Chrome/Edge;
WebHID solo en Chrome/Edge/Opera de escritorio. El envoltorio A (passphrase)
tiene que seguir siendo el camino universal, sin degradarse a ciudadano de
segunda.

## Deuda conocida

- **Ningún test automatizado de la capa JS.** Las 946 líneas de `web/` se
  comprueban a mano.
- **`totp-web` sin tests propios.** Hoy es traducción de tipos, así que el
  riesgo es bajo; cuando exponga el sync dejará de serlo.
- **Un solo backend de `ObjectStore`.** Hasta que exista un segundo (Drive), no
  hay prueba real de que la abstracción de siete métodos sea la correcta.
