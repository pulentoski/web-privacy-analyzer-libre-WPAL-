# ADR 028 — Telemetría propia (v1.3.4)

Estado: aceptada · Fecha: 2026-10-10

## Contexto
mercadolibre.cl: el scan dio 3 requests de rastreo en 238 y quedó «posiblemente bloqueado»; el HAR
del navegador real dio 0. Pero ambas capturas traen decenas de envíos de eventos a dominios de la
misma organización (`api.mercadolibre.com/melidata/tracks/…`, `print1.mercadoclics.com/…/count`,
`o11y-proxy-otel-frontend.meli.com/v1/metrics`, `http2.mlstatic.com/cdn/ping.gif`) y scripts de
analítica propia (melidata, adn, viewability). Desde v1.2.1 «tercero» es otra organización, así que
esa recolección no aparecía en ninguna cifra y un sitio que mide «en casa» parecía bloqueado.

## Decisiones
1. **Categoría aparte, no terceros.** Solo se evalúan requests del propio sitio o de la misma
   organización. No cambian el `tracking_score` de la request, las «requests de rastreo» ni los
   terceros: se cuentan en `summary.first_party_telemetry`.
2. **Reglas en YAML** (`data/first_party_telemetry.yaml`): segmento exacto de ruta, 204 a un envío
   con datos, y patrones conocidos. No aplican a documentos ni a assets estáticos (un script solo
   cuenta si es analítica propia conocida) ni a preflights OPTIONS.
3. **Niveles**: los envíos de eventos son INFERENCIA (se reconoce el patrón, no el contenido); la
   carga de un script de analítica conocido es EVIDENCIA de la carga.
4. **Índice**: componente `first_party_telemetry` (tope 4, k 6). Los topes deben sumar 100, así que
   `tracker_domains` pasa de 30 a 26: los índices de todos los scans bajan como mucho 4 puntos por
   ese lado y suben hasta 4 por telemetría propia. El tope es bajo a propósito: medir en casa expone
   menos que repartir datos entre terceros.
5. **Anomalía**: rastreo de terceros bajo + título normal + sin firma + sin otra señal + telemetría
   propia ≥ `min_requests_for_note` (3) → nota informativa en vez de la marca. Con título vacío, firma
   o cualquier otra señal, la marca se mantiene.

## Consecuencias
- Falsos positivos posibles de la regla de ruta: un endpoint funcional llamado `/events` o `/log`
  (p. ej. una API de calendario). Por eso el nivel es INFERENCIA y el peso en el índice es bajo.
- La lista de analítica propia conocida es corta y se mantiene a mano.
- Analizador 1.10.0: los scans anteriores necesitan `scripts/reanalyze.sh`.
