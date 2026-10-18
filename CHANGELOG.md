# Cambios

Formato: una sección por versión, la más reciente arriba. Las decisiones de diseño de cada versión están en
[docs/adr/](docs/adr/README.md); las versiones anteriores a 1.4.6, en la sección «Fases» de [docs/SPEC.md](docs/SPEC.md).

## 1.5.0 — 2026-10-18

Analizador 1.17.0 (sin cambios) · schema de reporte 1.11.0 · protocolo de visita 1 ·
[ADR 038](docs/adr/038-protocolo-de-visita-condiciones-y-cobertura.md). No hace falta reanalizar: el protocolo se aplica a
los scans nuevos; los guardados se presentan «sin protocolo».

### Agregado
- Protocolo de visita fijo (`data/visit_protocol.yaml`): carga → espera 3 s → scroll hasta el final (máx. 8 s) → espera 3 s →
  cierre de la pestaña con 3 s de observación. El reporte registra si cada etapa se completó, su hora de inicio y de fin, el
  motivo si no se completó y sus requests. La captura sigue activa durante el cierre y de esa etapa se registran solo los
  envíos efectivamente observados; el reporte aclara que el cierre no garantiza capturar todos los beacons de salida.
- `protocol_version` en el reporte. El Panel avisa si su ranking mezcla scans con distinto protocolo (o sin protocolo); la
  comparación scan ↔ HAR indica el protocolo del scan.
- Condiciones de la medición en cada reporte (Resumen, JSON, HTML y PDF): Chromium y su versión, headful/headless, fecha y
  hora de la visita, versiones del analizador y de las listas y país de la IP de salida.
- País de la IP de salida: una consulta por scan a `EGRESS_IP_SERVICE_URL` (por defecto ipify) por el egress-proxy, fuera
  del tráfico analizado; la IP se geolocaliza con DB-IP Lite y se descarta. Si falla, o con la variable vacía (no se
  consulta nada), «desconocido». Nunca se deduce del idioma ni de la zona horaria. Documentado en el README.
- Auditoría de cobertura reproducible (`worker/tests/v150/test_coverage_audit.py`, `data/coverage.yaml`): instrumentación,
  APIs observadas y tráfico por frame principal, iframe del mismo origen, iframe de tercero, dedicated worker y service
  worker, y beacons del cierre. La tabla va en «Límites de la medición»; lo no cubierto (workers sin instrumentación, service
  workers bloqueados, beacons de `visibilitychange`/`pagehide`) se declara, no se corrige.

### Cambiado
- `SCAN_TIMEOUT_S` por defecto 90 s (antes 60): el protocolo añade hasta 17 s tras la carga. Actualice su `.env`.
- Cabeceras, storage y service workers se vuelcan antes de cerrar la pestaña (con la pestaña cerrada Chromium ya no los
  entrega).
- Con scroll y cierre se capturan más requests: el índice de un sitio puede diferir del de un scan anterior aunque el puntaje
  y la clasificación no cambien.
- «Límites de la medición»: el texto fijo sobre Web Workers se reemplaza por lo medido en la auditoría.
- `scripts/test.sh` apunta `EGRESS_IP_SERVICE_URL` al sitio de fixtures: los tests no consultan servicios externos.
- El worker incluye `maxminddb` (misma versión que la api).

### Corregido (tests)
- `test_reanalyze_queues_without_touching_the_capture` usa un scan propio: si el worker real alcanzaba a reanalizar el scan
  compartido del módulo (lo toma en menos de 1 s), reemplazaba su análisis con las listas reales y
  `test_fingerprinting_endpoint` fallaba de forma intermitente (`no_disponible` en vez de la organización).
- `test_flow`: el máximo de la barra de progreso es el nuevo `SCAN_TIMEOUT_S` (90).

## 1.4.10 — 2026-10-17

Analizador 1.17.0 · schema de reporte 1.10.0 · [ADR 037](docs/adr/037-linker-de-google-cookie-que-coincide-y-aviso-de-consentimiento.md).
Actualizar los scans guardados con `./scripts/reanalyze.sh --all`.

### Corregido
- Cookie en la URL o el cuerpo de una request: el texto dice «el valor enviado coincide con la cookie «X»». «Un script
  copió el valor…» solo aparece si se registró que el mismo script que inició la request leyó esa cookie o ese ítem de
  storage; la captura actual no registra esas lecturas.
- `docs/SPEC.md`: la tabla del índice coincide con `data/scoring.yaml` (`tracker_domains` 26 y `first_party_telemetry` 4).
  Un test del frontend falla si vuelven a diferir.

### Agregado
- Linker de Google (`_gl`) en las URL de navegación y redirección, también en las páginas de la captura interactiva que
  no quedaron como request (pestaña nueva). Registra origen, destino, dominios y cadena de redirección. Decodifica solo el
  formato reconocido y muestra los campos extraídos enmascarados; si no puede decodificarlo, registra solo la presencia.
  El destino se clasifica como el resto del análisis (propio, misma organización, tercero u «Organización no disponible»)
  y el hallazgo dice con qué criterio (dominio registrable, mapa de entidades o alias). Solo un tercero suma (señal
  `linker_transfer` de la request, peso 15). No duplica una transferencia ya informada como sincronización o identificador
  persistente. Panel «Linker de Google (_gl)» en el Resumen.
- Glosario: Linker de Google (_gl).

### Cambiado
- `consent.user_interaction` → `consent.banner_interaction`; en la interfaz y en el HTML, «Interacción con el aviso de
  consentimiento». Los reportes y análisis anteriores se leen con el nombre anterior.
- `scripts/test.sh` monta `docs/` en el contenedor de tests del frontend.

## 1.4.9 — 2026-10-15

Analizador 1.16.0 · schema de reporte 1.9.0 · [ADR 036](docs/adr/036-client-hints-redirecciones-y-puntaje-por-nivel.md).
Actualizar los scans guardados con `./scripts/reanalyze.sh --all`.

### Corregido
- Detalle de request: la «Coincidencia con lista de filtros» decía «0 requests en esta visita» (p. ej. AliExpress #244,
  Appier). Usa el conteo del scan: «N en esta visita, incluida esta».
- Identificador igual a una cookie en una request que no envió cookies: el texto dice que un script copió el valor de
  la cookie en la URL o el cuerpo de la request.
- El frontend ya no repite la lista de bandas: la lee de la api (`data/scoring.yaml`).

### Agregado
- Client Hints en tres hechos: solicitud (Accept-CH; nunca se presenta como recepción), envío (solo con la cabecera
  Sec-CH-UA-* observada) y delegación del sitio (Permissions-Policy o meta delegate-ch: detectada, sin delegación
  detectada o no determinado). Puntos separados: solicitud baja, envío confirmado mayor.
- Cadena de redirección 3xx en el detalle de request (Location → request siguiente) y sincronización por redirección
  como Evidencia cuando un salto lleva el mismo identificador a otra organización.
- Desglose «Evidencia X + Inferencia Y» en el puntaje de cada request y en el índice del sitio.
- «Límites de la medición»: aviso de que los candidatos ICE por STUN no son observables, si la página creó conexiones
  WebRTC.
- Glosario: Client Hints, Accept-CH, Delegación de Client Hints y Cadena de redirección.

### Cambiado
- Appier se clasifica como publicidad también por la organización.

## 1.4.8 — 2026-10-15

Analizador 1.15.0 · schema de reporte 1.8.0 · [ADR 035](docs/adr/035-accept-ch-scans-fallidos-y-parciales.md).
Actualizar los scans guardados con `./scripts/reanalyze.sh --all`.

### Corregido
- music.youtube.com, www.youtube.com y www.google.com fallaban con `NAVIGATION_TIMEOUT` y una request (también en
  la captura interactiva): el frame ACCEPT_CH de Google reiniciaba la navegación y Chromium abortaba el reinicio.
  El worker arranca Chromium con `--disable-features=AcceptCHFrame`.
- Un scan fallido mostraba índice 0, «Nada observado» y la alerta de navegador automatizado. Ahora es «Sin
  medición», con el código `net::ERR_*` real del navegador y las requests capturadas antes del fallo.
- La banda 21–40 se llamaba «Posible», como el nivel de evidencia (ome.tv, índice 37). Ahora es «Bajo-moderado» y la
  api toma las bandas solo de `data/scoring.yaml`.
- «Servicios de terceros sin señales de rastreo» ya no lista organizaciones de publicidad ni de analítica.
- Fuga de búsqueda: no se informa si el valor es el título, la meta description o una meta keyword de la página.
- Fuga de URL: solo si el valor contiene la URL de la página entera, no una coincidencia parcial.
- Un servidor de Conversions API de Meta inferido (host on.aws u otra nube) ya no cuenta como una organización
  distinta de Meta en la sincronización ni en el índice; se muestra «Meta (vía servidor CAPI, inferencia)».
- Cookies `l` y `cna`: se clasifican por el nombre solo si son de un dominio de Alibaba.
- Test e2e de consentimiento intermitente: espera a que cargue la imagen del banner.

### Cambiado
- La alerta «el sitio pudo detectar el navegador automatizado» exige una señal dura (403/429/503, título de desafío,
  firma antibot en la URL). Pocas requests o rastreo anómalo solos dejan una nota Posible y el scan sigue en el
  ranking. Nunca en scans fallidos ni en capturas interactivas.

### Agregado
- Scan parcial: si la navegación agota el tiempo con respuestas ya recibidas, se analiza lo capturado con aviso.
- WebRTC (grupo 2, Evidencia): la página creó conexiones RTCPeerConnection o recibió candidatos ICE con IP local o
  pública (solo se registra el tipo de dirección). Glosario: WebRTC y Candidato ICE.
- Catálogo: Liferay (plataforma CMS/analítica), Podscribe (publicidad/atribución) y el alias INACAP (inacapmovil.cl).

## 1.4.7 — 2026-10-15

Analizador 1.14.0 · [ADR 034](docs/adr/034-fugas-a-cdn-y-cookies-por-organizacion.md). Actualizar los scans guardados con
`./scripts/reanalyze.sh --all`.

### Corregido
- Fugas hacia un CDN público: se verificó que la fuga por Referer de laserena.cl hacia cdnjs seguía informada y
  contando en el índice, pero su frase nombraba a la librería como receptora. Ahora las fugas (URL y Referer) nombran
  al CDN que recibió la request («CDN público cdnjs (Cloudflare)»), nunca a la librería.

### Cambiado
- Propósito de cookies en dos pasos: por el nombre conocido y, si no está, por el tipo de servicio de la organización
  que la creó (adtech/publicidad → publicidad; analítica → analítica; CDN/antibot → funcional). Siempre Inferencia, con
  su base; el Resumen indica cuántas se clasificaron de cada forma.

### Agregado
- Nombres de cookies de Alibaba/AliExpress (aep_usuc_f, intl_locale, xman_us_f, _m_h5_tk, isg, tfstk, l, cna,
  ali_apache_id) y de adtech común (cto_bundle, MUID, _uetsid, _uetvid, tuuid, A3).
- `docker-compose.release.yml` y `scripts/release-images.sh` en la versión 1.4.7 (sin publicar imágenes); ahora también
  en el repo privado, para que la sincronización privado → libre no los desactualice.

## 1.4.6 — 2026-10-14

Analizador 1.13.0 · [ADR 033](docs/adr/033-atribucion-cdn-sincronizacion-alias-y-cookies.md). Los scans guardados se
actualizan sin volver a navegar con `./scripts/reanalyze.sh`.

### Cambiado
- **Librerías en CDN público:** los recursos de jsDelivr, cdnjs y unpkg se atribuyen a la librería leída de la ruta
  («librería bootstrap en CDN público (jsDelivr)»), no a la empresa del CDN (p. ej. Prospect One). Si la ruta no lo
  permite: «librería en CDN público (<cdn>)». Las que figuran en `data/benign_libraries.yaml` se marcan como librería
  conocida.
- **Sincronización de identificadores** (grupo 5) solo cuando el mismo identificador llega a 2 o más organizaciones
  distintas del sitio; el propio sitio ya no cuenta como segunda organización. Con una sola organización, el hallazgo
  pasa al grupo 1: «Identificador persistente enviado a <org>».
- **Índice de exposición:** las cookies funcionales no suman (`stored_items` = cookies no funcionales + storage).

### Agregado
- `data/org_aliases.yaml`: alias de organización (dominios del mismo dueño). Primero: Municipalidad de La Serena
  (laserena.cl, munilaserena.cl).
- `data/cookie_purposes.yaml`: propósito de cada cookie por su nombre conocido (funcional, analítica, publicidad), también
  las del propio dominio, como Inferencia. Panel «Cookies por propósito» en Resumen y hallazgos en Hallazgos.
- UserWay en el catálogo de organizaciones, con el tipo de servicio «widget de accesibilidad».
- Glosario: «Librería en CDN público», «Propósito de una cookie», «Alias de organización».
