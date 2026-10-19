# Cambios

Formato: una sección por versión, la más reciente arriba. Las decisiones de diseño de cada versión están en
[docs/adr/](docs/adr/README.md); las versiones anteriores a 1.4.6, en la sección «Fases» de [docs/SPEC.md](docs/SPEC.md).

## 1.5.3 — 2026-10-19

Solo seguridad. Analizador 1.18.0 · schema de reporte 1.11.0 (sin cambios) ·
[ADR 041](docs/adr/041-cabeceras-del-proxy-fuera-de-la-captura.md). Migración 0017 (irreversible).

### Seguridad
- La captura guardaba `Proxy-Authorization` y `Proxy-Connection` en las requests `http://`: cabeceras del navegador con el
  egress-proxy, la primera con el usuario del scan y `PROXY_SCAN_SECRET` en base64. Salían en el detalle de request con
  «Mostrar identificadores completos» y en el HAR exportado con `include_sensitive=true`. Ahora:
  - el worker no las guarda (tampoco el HAR importado);
  - la migración 0017 las borra de las capturas ya guardadas y del staging de HAR importados;
  - la api las filtra en el detalle de request, el HAR exportado y la comparación de visitas (el JSON, el HTML y el PDF
    del reporte no llevan cabeceras).
- Test con el sitio de fixtures (http) y el worker real: ni la cabecera ni `PROXY_SCAN_SECRET`, en claro o en base64,
  aparecen en ninguna salida de la api ni en los reportes exportados.

### Al actualizar
- Si escaneó sitios `http://` con una versión anterior, rote `PROXY_SCAN_SECRET` (`./scripts/rotate-secrets.sh`): los HAR
  y reportes ya descargados y los respaldos previos pueden contenerlo.

## 1.5.2 — 2026-10-19

Analizador 1.18.0 (sin cambios) · schema de reporte 1.11.0 (sin cambios) · protocolo de visita 1 (sin cambios) ·
[ADR 040](docs/adr/040-comparacion-de-visitas.md). Migración 0016 (tabla nueva y dos columnas nullables en `jobs`): los
scans existentes no cambian y no hace falta reanalizarlos.

### Agregado
- Comparación de visitas (**Analizar un sitio → Comparar visitas**, `POST /api/comparisons`): tres visitas a la misma URL
  con el protocolo de la v1.5.0 —(1) perfil A limpio, (2) el mismo perfil A tras cerrar el navegador, conservar su estado
  en disco y esperar un intervalo, (3) perfil B limpio de control—. Cada visita es un scan normal, con su puntaje y su
  reporte. Es una comparación reproducible, no un detector de retargeting.
- Intervalo configurable (`interval_s`, 0–86 400; por defecto `VISIT_COMPARISON_INTERVAL_S=300`): se registran el
  configurado y el real.
- Verificación del estado: huellas sha256 del perfil A y de sus cookies persistentes (nunca los valores). Si el estado de A
  se perdió o cambió, o un perfil limpio no estaba vacío, la comparación se marca **no válida** con su motivo.
- Condiciones de cada visita (URL, Chromium, headful/headless, idioma, zona horaria, instrumentación, protocolo, límites,
  país de salida…) y lista de las que difieren.
- Comparación de valores exactos en su contexto (mismo destino y mismo campo): requests, destinos, organizaciones, cookies,
  identificadores en cookies, storage, URL, cabeceras y cuerpos, con textos fijos: «se observó un identificador persistente
  entre dos visitas con el mismo perfil; el perfil limpio de control mostró un resultado distinto», «cambio observado en el
  perfil persistente que no apareció en los perfiles limpios», «también observado en el control» y «no observado en esta
  captura». Descarta valores estáticos, de sesión, constantes conocidas y sin forma de identificador, e informa cuántos.
  Advertencia fija: tres visitas no prueban causalidad. Valores enmascarados salvo «Mostrar identificadores completos».
- Historial: sección «Comparaciones de visitas» (`GET /api/comparisons`); borrar las visitas borra la comparación.
- Glosario: Comparación de visitas, Perfil persistente, Perfil limpio de control, Identificador persistente.

### Cambiado
- Solo las visitas de una comparación usan un contexto persistente de Chromium; los scans normales e interactivos siguen
  con el contexto efímero (un test e2e compara un scan normal con la huella de la v1.5.1).
- Las visitas de una comparación no entran en el ranking del Panel ni en el historial con que se compara un scan con los
  anteriores del mismo sitio.
- Volumen nuevo `profiles`, solo del worker (uid 1001, 0700), fuera de respaldos y exportes; los perfiles se borran al
  terminar cada comparación. Docker no permite `noexec`/`nosuid` en ese volumen (docs/THREAT-MODEL.md).
- Cola: los jobs pueden esperar una hora (`jobs.not_before`); solo lo usan las visitas 2 y 3.

### Corregido
- El frontend (nginx) resolvía el nombre de la api una sola vez al arrancar: si la api se recreaba con otra IP, la interfaz
  respondía 502 a todo `/api/` hasta reiniciar el frontend. Ahora la resuelve con el DNS de Docker en cada request
  (`frontend/api_upstream.conf`).
- `scripts/purge-test-scans.sh` borra también las comparaciones de visitas de prueba.

### Límites conocidos
- La caché HTTP no interviene: Playwright la desactiva en todos los scans por la autenticación contra el egress-proxy, así
  que la caché como vía de persistencia no se observa.
- Las tres visitas salen por la misma IP.

## 1.5.1 — 2026-10-18

Analizador 1.18.0 · schema de reporte 1.11.0 (sin cambios) ·
[ADR 039](docs/adr/039-detalle-enmascarado-marca-y-subdominios-publicitarios.md). Para ver la regla concreta y la nueva
categoría en scans ya guardados, reanalícelos.

### Agregado
- Detalle de request enmascarado: con «Mostrar identificadores completos» desactivado (por defecto, y de nuevo al pasar a
  otra request), la URL, la tabla de parámetros, las cookies recibidas y enviadas, las cabeceras, la cadena de redirección,
  las decodificaciones y el cuerpo muestran los valores con forma de identificador como prefijo y largo. Lo enmascara la api
  (`GET /api/scans/{id}/requests/{rid}`; `?reveal=true` para los valores completos), con las mismas reglas que el reporte.
- Marca y dueño: «LinkedIn (Microsoft)» cuando difieren (`data/brands.yaml`). Solo presentación: la organización que agrupa
  y entra en el análisis sigue siendo el dueño. Campo `brand` en requests, detalle, redirecciones, rastreadores y dominios;
  el HTML/PDF lo muestra en rastreadores y destinos.

### Cambiado
- Subdominios publicitarios de una organización (`ads.`, `adservice.`, `adserver.`, `adsystem.`; p. ej. px.ads.linkedin.com)
  se categorizan como Publicidad aunque la organización sea de redes sociales (`data/host_categories.yaml`). Puntaje, banda
  e índice no cambian.
- Regla de lista: se informa la regla concreta que coincidió, no el bloque de reglas unidas por « <+> ».
- El título de la página se lee de `document.title`: `page.title()` devolvía, si la pestaña estaba navegando, el título
  provisional de Chromium («Loading <URL>»).

### Corregido
- Captura interactiva: podía fallar al terminar (`KeyError: 'built'`) si la pestaña seguía generando tráfico mientras se
  volcaba la captura. Regresión de 1.5.0.
- Captura interactiva y scans parciales: el título podía quedar como «Loading <URL>».

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
