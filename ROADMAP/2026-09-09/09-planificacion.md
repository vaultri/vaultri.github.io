# Planificación

> **Las fechas futuras son una estimación, no un compromiso.** El repositorio no
> tiene ningún calendario acordado: lo único fechado de verdad es lo ya hecho
> (arranque el 2026-08-30, instantánea el 2026-09-09). Las duraciones de aquí en
> adelante salen del tamaño aparente de cada bloque y sirven para ver el orden y
> las dependencias, no para prometer una entrega.

## Gantt

```mermaid
gantt
    title Roadmap de vaultrie (estimación desde 2026-09-09)
    dateFormat YYYY-MM-DD
    axisFormat %b %Y
    todayMarker stroke-width:2px,stroke:#b45309

    section Fase 1 · Vault web
    Núcleo cripto y formato del vault    :done,   f1a, 2026-08-30, 2026-09-05
    Motor de sync y ObjectStore          :done,   f1b, 2026-08-30, 2026-09-05
    Puente WASM y web funcional          :done,   f1c, 2026-09-01, 2026-09-09
    CI y despliegue a Pages              :done,   f1d, 2026-09-01, 2026-09-09
    OAuth con Google (drive.appdata)     :active, f1e, 2026-09-09, 14d
    Backend ObjectStore sobre Drive      :crit,   f1f, after f1e, 21d
    Exponer sync en el puente WASM       :        f1g, after f1f, 7d
    UI de sync en la web                 :        f1h, after f1g, 10d
    Tests del backend remoto             :        f1i, after f1f, 14d

    section Fase 2 · Extensión
    Esqueleto MV3 y CSP para WASM        :        f2a, after f1h, 10d
    WebAuthn PRF y envoltorio C          :        f2b, after f2a, 14d
    Autofill y popup                     :        f2c, after f2b, 14d

    section Fase 3 · Dongle TOTP
    Prototipo WebHID vs interfaz FIDO    :crit,   f3a, after f1h, 7d
    Firmware base, pantalla y botón      :        f3b, after f3a, 21d
    RTC y sincronización de hora         :        f3c, after f3b, 10d
    Canal vendor-HID y emparejamiento    :        f3d, after f3b, 21d

    section Fase 4 · Dongle FIDO
    Integración de pico-fido por FFI     :        f4a, after f3d, 28d
    HMAC-Secret y envoltorio D           :        f4b, after f4a, 14d
    Pruebas CTAP con ctap-hid-fido2      :        f4c, after f4a, 14d

    section Fase 5 · Móvil
    Bindings UniFFI sobre totp-core      :        f5a, after f2c, 21d
    Clientes Android e iOS               :        f5b, after f5a, 42d
```

## Camino crítico

Dos tareas marcadas como críticas, por motivos distintos:

**Backend de `ObjectStore` sobre Drive.** Bloquea el cierre de la fase 1 y, con
ella, absolutamente todo lo demás. Es además donde más incógnitas quedan: si el
compare-and-set sobre ETag no se comporta como se espera, hay que rediseñar
cómo se mueve el `head`.

**Prototipo de WebHID contra la interfaz FIDO.** Son unos pocos días de trabajo
que pueden invalidar el diseño entero del canal de sync del dongle. Va lo antes
posible dentro de la fase 3 justamente por eso: es barato de hacer y caro de
descubrir tarde.

## Dependencias entre fases

```mermaid
graph LR
    F1["Fase 1<br/>Vault web + Drive"]
    F2["Fase 2<br/>Extensión"]
    F3["Fase 3<br/>Dongle TOTP"]
    F4["Fase 4<br/>Dongle FIDO"]
    F5["Fase 5<br/>Móvil"]

    F1 -->|"formato del vault<br/>validado"| F2
    F1 -->|"motor de sync<br/>+ web como puente"| F3
    F1 -->|"API del core<br/>estable"| F5
    F3 -->|"hardware<br/>funcionando"| F4

    style F1 fill:#fde68a,stroke:#b45309,color:#000
```

Las fases 2, 3 y 5 solo dependen de la 1, así que podrían solaparse si hubiera
manos. El Gantt de arriba las encadena porque asume un único desarrollador.

La 5 se coloca después de la 2 a propósito y no por dependencia técnica: cada
plataforma nueva congela un poco más la API del core, y conviene que la
extensión —que es la que estresa el desbloqueo con clave externa— haya
encontrado antes lo que hubiera que cambiar.

## Hitos

| Hito | Qué significa |
|---|---|
| **M1 — Fase 1 cerrada** | Dos navegadores con la misma cuenta y passphrase convergen tras editar cada uno offline, y el remoto no aprende nada del contenido |
| **M2 — Extensión usable** | Autofill funcionando con desbloqueo biométrico en cada uso, sin retener la MK |
| **M3 — Dongle standalone** | Genera códigos con su propio RTC y sincroniza por USB. Entregable útil sin nada de FIDO |
| **M4 — Llave FIDO2** | El mismo dongle pasa como autenticador CTAP2 y se autodesbloquea con HMAC-Secret |
| **M5 — Móvil** | El mismo vault, sin una línea de cripto reescrita |
