# ADR 023 — Claridad y precisión (v1.2)

Estado: aceptada · Fecha: 2026-10-09

## Contexto
La herramienta analiza cómo los sitios recopilan información de sus visitantes, con qué
métodos y hacia quién la envían. En la versión 1.1.2 el menú mezclaba ese propósito con sus
herramientas («Privacy Test», «Mi exposición»), las vistas explicaban en párrafos lo que ya
decía el glosario y dos resultados inducían a error: una URL pegada desde un anuncio se
escaneaba con sus identificadores de clic, y los IDs de cuenta del sitio (ID de medición,
contenedor, pixel) aparecían como «identificadores que persisten» o como «sincronización
entre organizaciones» aunque son iguales para cualquier visitante.

## Decisión
1. **Menú por tarea:** Panel · Analizar un sitio · Historial · Glosario.
   - «Privacy Test» pasa a ser la sección desplegable «Opciones avanzadas» de «Analizar un
     sitio». La selección por defecto (sin interacción, navegador real, 1 corrida) es un
     scan simple; cualquier otra crea un grupo. `#/privacy` redirige a
     `#/analyze?advanced=1`; `#/privacy/<id>` sigue siendo el resultado de un grupo.
   - «Mi exposición» sale del menú: tarjeta en el Panel con «Ver detalle» (`#/exposure`).
   - Las cinco pestañas del scan no cambian.
2. **Panel sobre el scan más reciente de cada sitio** (`GET /api/panel`). Un sitio es el
   host de la URL sin «www.». Así un sitio escaneado diez veces (o un grupo de diez corridas)
   no pesa diez veces y «presente en k de N sitios» significa siempre lo mismo. No entran los
   scans de fixtures ni los de tests (`app/testscans.py`). El parámetro `include_tests` solo
   tiene efecto con `ALLOW_FIXTURES=1` (stack de pruebas): las E2E necesitan ver datos
   hostiles en el Panel; en una instalación normal se ignora.
3. **«Mi exposición» muestra solo el navegador del visitante.** El cruce con los scans deja
   de sumarse en cada fila; es opcional y explícito («Comparar con un scan») y usa
   `GET /api/exposure/scan-usage?job_id=…`. La misma consulta (`app/attribute_usage.py`)
   alimenta la tabla «Atributos de su navegador que leyó este sitio» de la pestaña
   Fingerprinting y los rankings del Panel, con los nombres del catálogo de «Mi exposición».
4. **URL de entrada.** Se detectan `gclid`, `gclsrc`, `gbraid`, `wbraid`, `dclid`, `fbclid`,
   `msclkid`, `ttclid`, `yclid`, `_gl`, `mc_eid` y `utm_*` (`app/url_cleaning.py`). Por
   defecto se escanea la URL limpia; `clean_url: false` la mantiene. Se guardan las dos
   (`jobs.url` = escaneada, `jobs.original_url` = recibida; migración 0011). Solo se quita lo
   listado: el resto de la query queda byte a byte igual. La detección la hace el servidor
   (`POST /api/scans/inspect-url`, la URL viaja en el cuerpo) para que la interfaz y la
   creación del scan usen la misma lista.
5. **IDs de cuenta del sitio** (`data/account_ids.yaml`, `analyzer/account_ids.py`,
   `ANALYZER_VERSION` 1.5.0). Una regla exige host del proveedor + parámetro + forma del
   valor (o un patrón de ruta). Lo reconocido se informa en `site.summary.account_ids`
   (con nivel INFERENCIA y `evidence_refs`) y su valor se excluye, en todo el scan, de
   `id_sync` y de `persistent_id`; en un grupo, de «identificadores que persisten».
   Los scans existentes se reanalizan sin navegar (`scripts/reanalyze.sh`).
6. **Opciones avanzadas: conclusión de una línea**, por plantilla y con su nivel
   (`privacy._conclusion`): rechazo («Al rechazar: A → B requests de rastreo; K
   organizaciones siguieron recibiendo datos»), banner no reconocido, perfiles o medición.
   Las cifras son las de la tabla (medianas). El motivo de los scans fallidos se agrupa por
   `error_code` y mensaje, por combinación y en total.
7. **Modo compacto.** Título + subtítulo de una línea; las explicaciones van al ⓘ y al
   Glosario. «Límites de la medición» queda plegado.
8. **Texto suelto al pie de todas las páginas.** Origen: Recharts agrega al `<body>` un
   `<span id="recharts_measurement_span">` para medir los rótulos del gráfico «Requests por
   organización» del Resumen y no lo quita; como la aplicación navega sin recargar, el span
   seguía ahí en todas las rutas con el último texto medido (la última palabra de un rótulo,
   p. ej. el dominio de «(sin organización) pdscrb.co»). Corrección: el gráfico retira el
   span al desmontarse y una regla CSS lo deja `visibility: hidden` (se puede medir, no se
   pinta ni entra en el texto de la página).
9. **Logo.** `branding/logo-fuente.jpeg` (original) → `scripts/build-logo.py` genera PNG con
   el exterior transparente (el interior del anillo queda blanco: sobre fondo oscuro el
   dibujo se ve dentro de su círculo blanco), 256 px para la interfaz, favicon 32/16,
   apple-touch-icon 180 y 128 px para los reportes. Todo se sirve desde el propio origen: la
   CSP no cambia. En los reportes es la marca por defecto; `REPORT_BRAND_*` la reemplaza.
   El logo no se licencia con el código (ver `NOTICE`).

## Alternativas descartadas
- **Sumar todos los scans en el Panel:** un grupo de corridas inflaría requests y presencia.
- **Detectar los parámetros de seguimiento solo en el navegador:** dos listas que mantener.
- **Marcar los IDs de cuenta por la forma del valor únicamente:** `id=1234567` en un host
  cualquiera no es un pixel; sin el host del proveedor habría falsos positivos que ocultarían
  identificadores reales.
- **Ocultar el span de Recharts con `display: none`:** la librería mediría 0 px y los rótulos
  del eje se cortarían.

## Consecuencias
- El reporte JSON no cambia de schema (1.4.0): `site.summary` y `result` del grupo admiten
  claves nuevas. La URL original no entra en el reporte exportable.
- Un valor reconocido como ID de cuenta deja de contar como identificador aunque un tercero
  lo reutilizara para otra cosa; por eso se muestra siempre aparte, con su evidencia.
- La conclusión de una línea resume; el detalle y sus límites siguen en las tablas.
