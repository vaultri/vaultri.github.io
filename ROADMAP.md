# App TOTP multiplataforma en Rust — Roadmap

## Visión general

Gestor de TOTP con core compartido en Rust, sincronización cifrada contra Google
Drive, y clientes en extensión de navegador, web, Android/iOS, y un dongle
hardware (T-Dongle-S3) que además funciona como llave de seguridad FIDO2.

## Arquitectura

```
                    totp-core (Rust)
                    Lógica compartida
                            |
        ┌───────────────────┼───────────────────┐
        v                   v                   v
   Extensión           Android / iOS        T-Dongle-S3
 (wasm-bindgen)        (UniFFI bindings)   (pico-fido C + FFI)
        |                   |
        └─────────┬─────────┘
                   v
             Google Drive
          (appDataFolder cifrado)
```

El dongle no sincroniza directo con Drive: recibe hora y datos vía USB
(HID vendor-specific), típicamente desde la web del vault.

## Modelo de cifrado

- Cada entrada TOTP se cifra por separado (no un blob único) con
  **XChaCha20-Poly1305**, incluyendo metadatos (issuer, cuenta) — no solo el
  secreto.
- Sync granular content-addressed, en línea con el modelo ya diseñado en
  `cloudauthn` (commits + `known-commits.log` para negociar el ancestro común
  entre peers).
- Se guarda en el `appDataFolder` de Google Drive: invisible en la UI normal
  de Drive, pero **no sustituye al cifrado cliente-side** — Drive es un blob
  store no confiable, la clave nunca sale del dispositivo del usuario.

### Jerarquía de claves

Una única **Master Key (MK)** cifra las entradas. Puede desenvolverse por
cuatro caminos independientes:

| Envoltorio | Mecanismo | Disponible en |
|---|---|---|
| A | Passphrase → Argon2id → KEK | Todos los clientes con recursos suficientes |
| B | Recovery key (32 bytes, generada y confirmada en el setup) | Fallback universal |
| C | WebAuthn PRF, con confirmación biométrica en cada uso | Extensión (Chrome/Edge) |
| D | HMAC-Secret de pico-fido + PIN, resuelto en el propio chip | T-Dongle-S3 (standalone) |

Añadir un dispositivo nuevo siempre requiere passphrase o recovery key la
primera vez — no hay "login" solo con la cuenta de Google, esta solo da
acceso a los bytes cifrados.

## Extensión de Chrome

- Autofill de OTP en la página abierta, además de consulta de otros
  servicios desde el popup.
- Desbloqueo vía WebAuthn PRF con confirmación biométrica **en cada uso**
  (descifrado bajo demanda, sin cachear la MK descifrada), disparado desde
  el popup (el service worker de MV3 no puede invocar WebAuthn).
- CSP de extensión necesita `'wasm-unsafe-eval'` para instanciar el WASM.
- Solo Chrome/Edge tienen soporte maduro de PRF — Firefox va por detrás.

## T-Dongle-S3

### Navegación (un solo botón + pantalla)

- Pulsación corta: cambia de elemento (issuer + label, sin descifrar aún);
  selección tras ~2s de dwell.
- Pulsación larga: vuelve atrás.
- Pulsación larga desde home, **con una petición CTAP pendiente**: confirma
  presencia física para completar la autenticación FIDO2. Sin petición
  pendiente, no hace nada especial — no hay "modo llave" activable a
  voluntad ni cambio de descriptor USB.

### Parte TOTP (firmware propio, sin CTAP)

- Descifrado bajo demanda: se descifra solo el secreto de la entrada
  seleccionada, se calcula el código, se descarta la clave inmediatamente.
- RTC con batería de respaldo; hora sincronizada por USB al conectarse a un
  host (evita depender de WiFi/NTP).
- Emparejamiento inicial también por USB, transfiriendo el envoltorio de la
  MK desde un cliente ya desbloqueado.
- Canal de sync: interfaz **HID vendor-specific** separada de la interfaz
  FIDO, para poder usarse desde una web con **WebHID** (solo Chrome/Edge/
  Opera de escritorio — sin soporte en Firefox, Safari, ni móvil).
- Entregable útil por sí solo, sin depender de la parte FIDO.

### Parte FIDO (pico-fido + FFI)

- Se reutiliza **pico-fido** (C, mbedTLS) en vez de reimplementar CTAP2.1
  desde cero — ya soporta ESP32-S3, HMAC-Secret, PIN, OATH, y "Secure Lock"
  (MK protegida en región OTP/eFuses del propio chip).
- El core Rust se conecta a pico-fido vía una capa FFI delgada (Opción C):
  pico-fido resuelve el protocolo FIDO2/CTAP2, el core Rust resuelve la
  lógica TOTP/sync.
- Testing del protocolo con el crate `ctap-hid-fido2` (no `authenticator-rs`,
  pensado para embeberse en Firefox, no como herramienta standalone).
- Interfaz FIDO siempre presente en el descriptor USB (no se activa/
  desactiva dinámicamente) — la confirmación de presencia por botón hace
  las veces de gate de seguridad, como en cualquier llave FIDO2 estándar.

## Roadmap de fases

1. **Vault en web + sync con Google Drive.** Valida cripto (MK, KEK/Argon2id,
   recovery key), formato de entrada cifrada, y modelo de sync. El módulo
   de sync se diseña desacoplado de la UI para reutilizarlo después como
   puente WebHID con el dongle. *Funcional de punta a punta, verificado contra
   dobles del `appDataFolder`; falta probarlo contra Drive de verdad.*
2. **Extensión de Chrome.** Autofill + popup, desbloqueo vía WebAuthn PRF.
3. **Dongle — parte TOTP.** Firmware propio: pantalla, navegación, RTC,
   sync vendor-HID reutilizando la web de la fase 1.
4. **Dongle — parte FIDO.** Integración de pico-fido vía FFI, interfaz FIDO
   siempre presente, HMAC-Secret para autodesbloqueo.
5. **Android / iOS.** Bindings UniFFI sobre el mismo `totp-core`, una vez
   validado el modelo en web y dongle.

## Puntos abiertos / a verificar con prototipo

- Confirmar contra una cuenta de Google real que el update del fichero `head`
  respeta `If-Match` y con qué código falla la precondición. El diseño ya no
  depende de ello —se comprueba la revisión antes de escribir, y el
  `known-commits.log` hace que perder la carrera no pierda el commit—, pero
  hasta probarlo no se sabe cuál de los dos mecanismos está trabajando.
- Confirmar en la práctica que el bloqueo de WebHID a dispositivos FIDO
  (Chrome) actúa por interfaz (top-level collection) y no por dispositivo
  completo — condiciona el diseño del canal de sync del dongle.
- Definir el mecanismo de PIN por botón para el desbloqueo local del dongle
  (envoltorio D) si se decide no depender únicamente de "posesión física".
