# ADR 006 — Arquitectura del análisis y desviaciones de F3

Estado: aceptado · Fase: F3

## Decisiones
1. **Analizador puro, puente aparte.** `worker/app/analyzer/` son funciones puras
   (`analyze(captura, listas, config) -> dict`): sin red, sin DB, sin estado. No
   ejecuta ni evalúa nada del sitio. `worker/app/analysis.py` lee las tablas
   `scan_*`, llama a `analyze()` y reemplaza el análisis anterior en una transacción.
2. **El análisis es una cola sobre `jobs.analysis_status`** (`queued → running →
   completed | failed`). Al guardar una captura queda `queued`; `POST
   /reanalyze` vuelve a ponerlo `queued`. El worker lo toma con `FOR UPDATE SKIP
   LOCKED`. Es un único camino para el análisis automático y el re-análisis, y la
   api no necesita las listas ni el motor. Si el worker muere a mitad, se reencola
   a los 5 minutos. El `status` del scan no cambia: re-analizar no navega.
3. **Un solo hilo de análisis**, fuera del event loop (exigencia de `adblock`, y
   para no frenar heartbeat ni scans).
4. **Todo lo ajustable vive en `data/`** (montado de solo lectura en el worker):
   pesos y bandas (`scoring.yaml`), nombres de parámetros (`param_names.yaml`),
   categorías por dominio (`domain_categories.yaml`), listas (`lists/`).
5. **`analyzer_version` y `lists_version`** se guardan en cada resultado
   (`request_analysis`, `findings`, `site_analysis`) y salen en el reporte.
6. **Límites frente a datos hostiles**: decodificación sin expresiones regulares;
   entrada ≤ 64 KiB, salida ≤ 16 KiB por valor, profundidad ≤ 3, ≤ 40 resultados
   por valor, gzip con salida acotada; ≤ 150 parámetros por request; ≤ 500
   hallazgos; límite de tiempo de 25 s, tras el cual el resto de requests se
   puntúa sin parámetros y el análisis queda marcado `partial`.
7. **Los claims no reproducen valores completos** (solo los primeros 6 caracteres
   y el largo) y los de nivel EVIDENCIA solo describen lo observado: "el mismo
   valor se envió a…", "coincide con la cookie…", nunca de quién es un dato.

## Desviaciones respecto del prompt de F3
- **"Schema de F0"**: F0 no dejó ningún schema de reporte. Se creó
  `api/app/schemas/report-1.0.0.schema.json` (JSON Schema 2020-12). Versionado por
  nombre de archivo y por el campo `schema_version`; un reporte que no valida no
  se entrega (HTTP 500 `REPORT_INVALID`).
- **"Listas de la SPEC" y "SPEC §9"**: la SPEC no tenía listas de nombres de
  parámetros ni secciones numeradas. Se definieron en `data/param_names.yaml` y se
  documentaron en docs/SPEC.md (§Análisis).
- **Mapa de categorías**: EasyList/EasyPrivacy no dicen si algo es analítica o
  publicidad. La categoría sale de un mapa propio y corto por dominio
  (`domain_categories.yaml`) y, si no, de la lista que coincidió (EasyList →
  advertising, EasyPrivacy → analytics). Siempre es INFERENCIA.
- **Sincronización entre organizaciones**: se exige que el mismo valor llegue a
  dominios de dos organizaciones distintas. Con solo "dominios distintos", los
  identificadores de propiedad (p. ej. `G-XXXX` de Google Analytics) compartidos
  entre dominios del mismo dueño contaban como sincronización.
- **Etiquetas de banda de los fixtures**: se derivan de los pesos de
  `scoring.yaml`, no al revés. El caso JWT queda en "Muy alto" (85) porque además
  del token lleva un `sub` con forma de identificador.

## Limitaciones conocidas
- "Mismo valor en varios dominios" no distingue un identificador de usuario de uno
  de configuración (clave de sitio, hash de versión) si llega a dos organizaciones.
- first/third party es por dominio registrable: un dominio del mismo dueño que el
  sitio (p. ej. un CDN propio con otro nombre) cuenta como tercero.
- La cabecera `Referer` no se analiza como parámetro; solo se cuenta su envío a
  terceros en las categorías de datos.
- No se inspeccionan los cuerpos de respuesta (no se capturan) ni los frames de
  WebSocket: el mecanismo websocket solo se cuenta a nivel de sitio.
- Fingerprinting solo por listas y por el mapa de dominios (instrumentación: F4).
- Cookies: se describen (nombre, forma), pero una cookie enviada a su propio
  dominio no genera señal por sí sola.
