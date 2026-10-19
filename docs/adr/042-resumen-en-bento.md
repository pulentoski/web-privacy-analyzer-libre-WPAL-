# ADR 042 — Resumen en bento y «Quién recibió más datos»

Estado: aceptada · Versión: 1.6.0 · Analizador 1.18.0 (sin cambios) · Schema de reporte 1.11.0 (sin cambios)

## Contexto

El Resumen había crecido por capas: avisos, consentimiento, límites, condiciones, la tarjeta del índice con su tabla,
ocho cifras, varios paneles y al final los gráficos, el mapa y los datos expuestos. Lo más importante quedaba abajo y el
índice no mostraba cómo había cambiado respecto de la visita anterior. Se pidió reordenarlo como un bento sin quitar
información (solo reordenar o plegar), en los dos temas, sin tocar captura, análisis, puntaje ni reportes.

## Decisión

- **Orden.** Encabezado (dominio, ID, URL final, fecha, validez de la medición con la regla antibot del analizador,
  Exportar) → bento de 3 (índice · lo más relevante · condiciones y consentimiento) → 8 cifras con una línea de color
  por tipo → mapa de relaciones → los dos gráficos → «Quién recibió más datos» y «Datos expuestos a terceros» → plegados
  (cookies por propósito, servicios sin señales, niveles de evidencia, Client Hints/linker/misma organización y
  «Límites de la medición»). Lo que antes estaba a la vista y ahora va plegado: el desglose del índice («Cómo se
  calculó»), el protocolo de visita con sus etapas, el detalle de cada categoría de datos y esos paneles finales.
- **Índice.** Medidor semicircular 0–99 con el número y la banda, barra «Evidencia + Inferencia» (`score_by_level`) y
  «↑/↓ N vs scan anterior» solo si existe un scan anterior del mismo sitio (host sin «www.», como el Panel), del mismo
  origen y con el mismo `protocol_version`. Si el inmediatamente anterior es de otro protocolo no se compara (ni se salta
  a uno más viejo): los índices no son comparables.
- **«Lo más relevante».** Una frase con 3 cifras que ya existen (dominios de terceros con rastreo y terceros que
  recibieron la URL, del desglose del índice; empresas con el mismo identificador, del hallazgo `id_sync`) y hasta 3
  alertas, solo si existen: consentimiento sin interacción, sincronización entre empresas, rastreo del lado del servidor,
  fingerprinting. Cada alerta lleva el nivel del hallazgo que la sostiene.
- **«Quién recibió más datos»** (`GET /api/scans/{id}/overview`, `app/overview.py`): por organización (tercero), los
  tipos de dato que muestra algún hallazgo cuya evidencia incluye una request a esa organización — identificador
  (`id_sync`, `redirect_sync`, `sync_wave`, `persistent_id*`, `identifier_param`, `session_token_third_party`), URL
  (`url_leak`, `referer_leak`), consentimiento (`consent_mode_state`, `tcf*`), dispositivo (`client_hints_sent` y
  exfiltraciones del fingerprinting) y búsqueda (`search_leak`) —, ordenado por cantidad de tipos y luego por requests
  de tracking, con la duración de su cookie más larga (hallazgo `persistent_cookie`). Se calcula al leer; sin
  organización conocida no se juntan dominios distintos (mismo criterio que Rastreadores).
- **Estilo y temas.** Todo por variables CSS (`--c-tracking`, `--c-fp`, `--c-own`, `--c-third`, `--c-exfil`, `--c-valid`,
  `--card-radius`…). Clásico: tarjetas blancas, radio de 16 px y sombra suave. Unidad Púrpura: superficie oscura con el
  mismo radio de 16 px y una sombra suave (en el Resumen no se dibujan las esquinas cortadas del tema),
  sin imágenes, con los mismos significados de color. Títulos de sección en mayúsculas pequeñas,
  contenedor de 1200 px, bento apilado en móvil sin scroll horizontal (el mapa se desplaza dentro de su caja). Íconos SVG
  de trazo.

## Consecuencias

- Pruebas: `frontend/src/views/v160.test.jsx` (orden, alertas, «vs scan anterior», ranking, variables y contraste ≥ 4,5:1
  de los colores con significado en ambos temas y en modo presentación), `api/tests/test_v160_api.py` (ranking, scan
  anterior, el reporte no cambia) y `e2e/tests/test_v160.py` (ambos temas y modo presentación sin errores de consola,
  orden, móvil y contraste AA). No se corrió la regresión completa: no se tocó captura ni análisis.
- La validez «No aplica» cubre la captura interactiva y el HAR importado, donde la regla antibot no se aplica.
