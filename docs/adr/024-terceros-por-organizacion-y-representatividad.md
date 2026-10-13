# ADR 024 — Terceros por organización, representatividad y contexto (v1.2.1)

Estado: aceptada · Fecha: 2026-10-09

## Contexto
Escaneos reales de AliExpress, Airbnb, BioBioChile y Amazon mostraron cinco imprecisiones:

1. **Terceros por dominio, no por organización.** El CDN propio de un sitio contaba como
   tercero: en `airbnb.cl`, `muscache.com` (CDN de Airbnb) sumaba 219 de 250 «terceros»; igual
   `alicdn.com` y `aliexpress-media.com` en AliExpress. El número no describía la exposición a
   otras organizaciones.
2. **Fuga al mismo dueño.** Enviar la URL o el Referer a un dominio de la misma organización
   (p. ej. `amazon.com` → `ssl-images-amazon.com`) se marcaba como fuga a terceros.
3. **Visitas no representativas.** El scan de Amazon dio 3 requests (el sitio detectó el
   navegador automatizado) y aun así entró al ranking del Panel con un índice «Bajo».
4. **Lista de parámetros de seguimiento incompleta** (faltaban `gad_source`, `srsltid`, `spm`,
   `igshid`, `mkt_tok`…) y embebida en el código.
5. **Sin el giro del servicio.** No se decía a qué se dedica cada organización o script
   (grabación de sesión, antifraude/antibot, publicidad…), contexto útil para leer el resultado.

Y una mejora de redacción: la conclusión de consentimiento se describía caso por caso, sin una
frase técnica uniforme con su nivel de evidencia.

## Decisión
1. **Clasificación por organización** (`app/analyzer/engine.py`). Cada request es `first_party`
   (mismo dominio), `same_org` (otro dominio del mismo dueño según el mapa de entidades) o
   `third_party` (otra organización o desconocida). Solo `third_party` cuenta como «tercero» en
   el resumen, el índice de exposición, el Panel y los reportes. La columna `request_analysis.party`
   (migración 0012) persiste la clasificación; las filas anteriores (NULL) caen al criterio por
   dominio hasta que se reanalizan. «Misma organización» se muestra aparte, nunca como tercero.
2. **Fuga al mismo dueño = dato informativo.** Una URL o un Referer completo hacia un dominio
   `same_org` se registra en `site.summary.same_org`, no como hallazgo de fuga ni en el índice.
3. **Alerta de visita posiblemente bloqueada** (`site.summary.blocking`, umbrales en
   `data/scoring.yaml §blocking`): pocas requests (`< min_requests`, por defecto 20), texto de
   verificación antibot en el título (captcha, «unusual traffic», desafío de Cloudflare…) o
   estado 403/429/503 en la navegación. Banner en Resumen, Historial, Panel y reportes; estos
   scans se excluyen del ranking del Panel por no ser representativos.
4. **`data/tracking_params.yaml`**: la lista de parámetros de seguimiento de la URL de entrada
   sale del código a `data/` (con respaldo embebido) y suma los 17 parámetros nuevos.
5. **`data/service_types.yaml`**: giro de cada organización o producto conocido. Se muestra junto
   a la organización en Rastreadores, Fingerprinting, Panel y reportes. Es CONTEXTO (Inferencia),
   no evidencia del uso concreto; si no está en la lista, «tipo no identificado».
6. **Conclusión de consentimiento por plantilla** (`data/consent_mode.yaml §conclusions`), con su
   nivel, en Resumen, Hallazgos y reportes: `gcs` con `ad_storage`/`analytics_storage=granted` sin
   interacción con banner; `gcs` sin estado (`G1--`); TCF presente pero no mostrado
   (`gdprApplies=false` y `displayStatus` disabled/hidden). Sin juicio legal.

## Consecuencias
- Subió `ANALYZER_VERSION` a 1.6.0; `scripts/reanalyze.sh` reescribe los análisis existentes sin
  volver a navegar. Tras reanalizar: airbnb.cl pasó a 10 terceros + 2 de la misma organización;
  aliexpress a 22 + 5; el scan de Amazon quedó marcado como bloqueado (3 requests).
- El schema del reporte `report-1.4.0` añade campos opcionales (`service_type`/`service_label` en
  trackers y scripts, `conclusions` en consent); `site.summary` ya era de forma libre.
- El giro es contexto: no afirma qué hizo una organización en una visita concreta.
