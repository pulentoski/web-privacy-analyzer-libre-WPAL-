# ADR 026 — Antibot que responde 200 e índice parcial del HAR (v1.3.1)

Estado: aceptada · Fecha: 2026-10-10

## Contexto
- El scan de `https://es.aliexpress.com/item/1005012085176766.html` capturó 152 requests y solo 2 de
  rastreo (un HAR del navegador real, 67), sin quedar marcado: la pantalla de castigo de Alibaba
  (`…/_____tmd_____/punish?x5secdata=…`) carga en un iframe, responde 200, no cambia el título y la
  página supera el mínimo de requests. Ninguna de las tres señales de v1.2.1 la ve.
- El índice de exposición de un HAR importado no incluye cookies, storage ni fingerprinting: mostrarlo
  junto al de un scan, o rankearlo, compara cosas distintas.

## Decisiones
1. **Firmas de desafío solo en documentos y frames.** Se buscan en la URL de requests `document`, de
   navegación y en `frame_url`. En los HAR reales de AliExpress `o.alicdn.com/baxia/…` se carga como
   script en visitas normales: buscar en cualquier URL marcaría todo scan del sitio. Los iframes de
   widgets incrustados (reCAPTCHA, hCaptcha, Turnstile) se ignoran: un formulario de login con captcha
   no es una visita desafiada.
2. **Anomalía de rastreo relativa al total.** Con historial (hasta 5 scans anteriores del mismo host,
   no marcados; los HAR importados cuentan) se marca si el rastreo es < 25 % de lo esperado según la
   mediana de la proporción histórica, siempre que esa mediana tenga ≥ 10 requests de rastreo. Si el
   historial rastrea poco (sitio que de verdad rastrea poco, o visitas bloqueadas sin marcar) no sirve
   de referencia y se aplica el umbral sin historial: ≥ 100 requests, ≥ 1 de rastreo y ≤ 1,5 %.
   Exigir al menos una request de rastreo evita marcar sitios como wikipedia (0 de rastreo).
3. **El historial se lee al analizar** (`worker/app/analysis.py::site_history`, solo scans anteriores
   al job): reanalizar no navega y da el mismo resultado mientras exista ese historial. Si se borra el
   historial, la señal histórica deja de aplicar; la de firma no depende de él.
4. **Índice parcial**: no se recalcula ni se oculta; se rotula «índice parcial (sin cookies ni
   fingerprinting)» y se saca del ranking del Panel (lista aparte `partial_sites`). El JSON del reporte
   no cambia de schema: `scan.source` ya distingue la captura.
5. **Selector de archivo**: `<input type=file>` oculto y un `<button>` propio que lo abre; el nombre
   del archivo se muestra como texto (dato no confiable).

## Consecuencias
- Analizador 1.8.0: los scans anteriores necesitan `scripts/reanalyze.sh` para las señales nuevas.
- Las dos señales son heurísticas: el aviso dice «posiblemente». Falso positivo conocido: una página
  grande con una o dos requests de rastreo. Falso negativo: un desafío servido como script en la
  propia página, sin frame ni historial.

## Ajuste v1.3.2 — bloqueo parcial
La portada `https://es.aliexpress.com/` quedó marcada con 121 requests de rastreo de 427 e índice 91:
la firma (`_____tmd_____/punish`) estaba en el iframe de un solo componente (recomendaciones) y el
resto de la página cargó. Desde el analizador 1.9.0 la firma por sí sola no marca la visita:
- firma + rastreo normal (umbrales `blocking.challenge_partial` en `data/scoring.yaml`), sin otra señal
  y sin que la firma esté en la dirección de la propia página → `blocking.partial = true`, aviso
  «Bloqueo parcial: un componente mostró verificación antibot», informativo; no excluye del ranking;
- firma + rastreo por debajo de esos umbrales, firma en la propia página, o cualquier otra señal
  (pocas requests, título, estado HTTP, rastreo anómalo) → «visita posiblemente bloqueada», como antes.

