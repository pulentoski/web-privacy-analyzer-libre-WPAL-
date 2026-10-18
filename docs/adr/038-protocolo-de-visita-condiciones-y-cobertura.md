# ADR 038 — Protocolo de visita, condiciones de la medición y cobertura por contexto

Estado: aceptada · Versión: 1.5.0 · Analizador 1.17.0 (sin cambios) · Schema de reporte 1.11.0

## Contexto

1. Un scan terminaba con load + red en calma: no había scroll ni cierre de pestaña, así que no se veía lo que un sitio
   carga al desplazarse ni lo que envía al salir, y dos scans podían visitar el sitio de forma distinta sin que constara.
2. El reporte no decía con qué navegador, en qué modo ni desde qué país se midió. El país no se puede deducir del idioma
   o la zona horaria del perfil base (es-CL / America/Santiago son configuración, no ubicación).
3. «La instrumentación no cubre Web Workers» era una afirmación sin prueba, y de los iframes de terceros y los service
   workers no había nada medido.

## Decisión

### Protocolo de visita fijo (`data/visit_protocol.yaml`, protocol_version 1)
carga (load + red en calma, como antes) → espera 3 s → scroll hasta el final del documento (rueda del mouse, un viewport cada
400 ms, máx. 8 s; si la rueda no mueve el documento, `scrollTop`) → espera 3 s → cierre de la pestaña con 3 s de observación.

- Los tiempos viven en el YAML, que se valida al cargar (etapas exactas, claves cerradas, rangos). Cambiar una etapa o un
  tiempo es otro protocolo: `protocol_version` sube y un test lo exige (`VERSIONS` en `test_visit_protocol.py`).
- Cada etapa registra si se completó y por qué no, hora de inicio y de fin (UTC, ms) y las requests que empezaron en ella
  (por `seq`, que crece con la llegada). Las etapas son contiguas: toda request queda en una etapa. Una etapa cortada
  (SCAN_TIMEOUT_S, MAX_REQUESTS, la página se cerró sola) deja las siguientes como «no se ejecutó». Si el volcado previo al
  cierre termina pasado SCAN_TIMEOUT_S, el cierre no empieza.
- El escenario de consentimiento del Privacy Test va al final de la primera espera (sus requests cuentan ahí).
- `SCAN_TIMEOUT_S` sube de 60 a 90 s: las etapas con tiempo propio suman 17 s y la carga conserva al menos 60 s.

### Cierre de la pestaña
`page.close(run_before_unload=True)` con la captura activa; un aviso `beforeunload` se acepta para que no retenga la pestaña.
Medido con el sitio de fixtures (página `/v150/close/`, el servidor registra qué beacons llegan):

| Evento | Llega al servidor | Queda en la captura |
|---|---|---|
| beforeunload | sí | sí, siempre |
| visibilitychange | sí | a veces (1 de 7 corridas) |
| pagehide | a veces | no |

Con la pestaña cerrada Playwright tampoco entrega las cabeceras reales (`TargetClosedError`): todo lo que depende de la
pestaña (cabeceras, tamaños, storage, service workers) se vuelca antes de cerrar (`NetworkMonitor.prepare_close`), al final de
la segunda espera; después del cierre solo se construyen las requests nuevas o que cambiaron, con lo que aún se pueda leer.
De la etapa de cierre se registran solo los envíos efectivamente observados (`closing_sends`) y el reporte dice siempre que el
cierre no garantiza capturar todos los beacons de salida. Se descartó usar el log del proxy como segundo observador: Squid
registra los túneles HTTPS al cerrarse (con el navegador) y un beacon que reutiliza un túnel abierto no deja línea.

### Condiciones de la medición
`jobs.result.measurement`: Chromium y su versión (`browser.version`), headful/headless (`HEADLESS`), hora de inicio de la
visita y el país de la IP de salida; el reporte añade las versiones del analizador y de las listas del análisis.

País de la IP de salida: una consulta por scan a `EGRESS_IP_SERVICE_URL` (por defecto `https://api.ipify.org`), **por el
egress-proxy** (regla 3), desde el worker con urllib y no desde el navegador, y con un usuario de proxy `scan-<uuid>` nuevo:
no entra en la captura ni en los destinos del scan. Respuesta acotada a 64 bytes y validada como IP pública; se geolocaliza con
DB-IP Lite (`data/ipdb`, maxminddb en el worker) y se descarta: no se devuelve, no se guarda y de un error solo se registra el
tipo. Falla, respuesta inválida, IP no pública, base ausente o variable vacía → «desconocido» con su motivo. Variable definida y
vacía = no se consulta nada (`${EGRESS_IP_SERVICE_URL-…}` en compose, sin «:»). Es la única consulta a un servicio externo
fuera del tráfico analizado; el servicio ve la IP de salida y la hora de cada scan, no la URL analizada. `scripts/test.sh` la
apunta a una ruta de control del sitio de fixtures (`/__egress-ip`, responde 8.8.8.8 y no se registra como tráfico del sitio).

HAR importado: navegador y país «no aplica»/«desconocido» (la red es la del usuario). Captura interactiva: condiciones sin
protocolo. Scans anteriores: «no_disponible» y sin protocolo; la hora es la del job.

### Cobertura por contexto (auditoría reproducible)
`worker/tests/v150/test_coverage_audit.py` visita `/v150/coverage/` con el Chromium y la configuración de un scan. En cada
contexto se llaman las mismas APIs de prueba (canvas.fillText, canvas.toDataURL, navigator.hardwareConcurrency,
navigator.userAgent) y se envía un marcador propio; el servidor dice qué contextos corrieron. Tres columnas independientes:
instrumentación instalada (el init script envió su informe inicial desde ese frame: `fingerprinting.frames_reporting`), APIs
observadas (filas del monitor de ese frame/script) y tráfico capturado (el marcador está en la captura).

| Contexto | Instrumentación instalada | APIs observadas | Tráfico capturado |
|---|---|---|---|
| Frame principal | sí | las 4 | sí |
| Iframe del mismo origen | sí | las 4 | sí |
| Iframe de tercero | sí | las 4 | sí |
| Dedicated worker | no | ninguna | sí (a nombre de la página) |
| Service worker | no | ninguna | no (registro bloqueado; `register()` resuelve sin error y no registra nada) |

El resultado está en `data/coverage.yaml`; el test falla si lo medido deja de coincidir, y cada fila no cubierta lleva el
texto que va a «Límites de la medición». No se corrige nada de lo no cubierto en esta versión.

### protocol_version en el Panel y la comparación
El Panel avisa si su ranking junta scans con distinto `protocol_version` (o sin protocolo). La comparación scan ↔ HAR dice qué
protocolo siguió el scan: el HAR es navegación libre del usuario, así que siempre son dos formas de visitar.

## Consecuencias

- Puntaje y clasificación no cambian (analizador 1.17.0). Con scroll y cierre se capturan más requests: el índice de un sitio
  puede diferir del de un scan anterior a v1.5.0 aunque las reglas sean las mismas. Por eso existe el aviso del Panel.
- Cada scan dura unos 17 s más.
- Una consulta a un servicio externo por scan, desactivable.
- Pendiente (declarado, no implementado): instrumentación en workers, service workers no bloqueados, capturar los beacons de
  `visibilitychange`/`pagehide` (p. ej. ocultando la pestaña antes de cerrarla).
