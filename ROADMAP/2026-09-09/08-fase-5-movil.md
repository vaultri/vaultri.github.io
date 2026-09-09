# Fase 5 — Android / iOS

**Estado: sin empezar.** Depende de la fase 1; se hace *después* de validar el
modelo en web y dongle, no en paralelo desde el principio.

## Objetivo

Clientes nativos sobre el mismo `totp-core`, mediante bindings **UniFFI**.

## Por qué va al final

No es una cuestión de dificultad, sino de orden: cada plataforma nueva congela
un poco más el formato del vault y la API del core. Conviene que web y dongle
—que son los que más tensan el diseño, uno por el sync y otro por trabajar con
recursos mínimos— hayan encontrado ya lo que hubiera que cambiar.

## Trabajo previsto

- Definir la interfaz UniFFI sobre la API pública que ya existe: `VaultHeader`,
  `EncryptedEntry`, `Repo`, `sync`.
- Almacenamiento de la copia local en cada plataforma (Keychain / Keystore para
  lo que haga falta proteger a nivel de SO).
- Desbloqueo biométrico: en móvil no hay WebAuthn PRF, así que el envoltorio
  correspondiente se apoyará en el almacén de claves del sistema, previsiblemente
  también como `ExternalKey`.
- Sync contra Drive reutilizando el mismo motor; solo cambia la implementación
  de `ObjectStore` (cliente HTTP nativo en lugar de `fetch`).
- Lectura de QR para el alta de entradas — la única pieza de UI que no tiene
  equivalente en la web.

## Lo que no hay que rehacer

Nada de cripto, nada de formato, nada de merge. Si algo de eso hiciera falta
tocarlo aquí, sería señal de que el core no estaba tan desacoplado como se
pensaba.
