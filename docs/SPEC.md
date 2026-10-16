# SPEC — Web Privacy & Tracker Analyzer

## Propósito
Analizar dinámicamente sitios web y explicar, con evidencia, qué recursos
cargan, a qué terceros se comunican, qué datos parecen enviarse y con qué
nivel de confianza. EVIDENCIA > SUPOSICIÓN.

## Módulos
1. Mi exposición: colector JS en el navegador del usuario; los valores se quedan
   en el navegador (no hay endpoint que los reciba ni tabla que los guarde, ver
   §Mi exposición). El servidor solo informa lo que llegó en la request
   (`GET /api/exposure/server`): IP tomada del request (X-Forwarded-For solo desde
   TRUSTED_PROXIES). Nunca inventar IP LAN. Estado por atributo en el navegador:
   DISPONIBLE | NO_DISPONIBLE; en los scans (F4): además OBSERVADO | UTILIZADO.
2. Analizar sitio: worker Playwright captura requests, responses, post_data,
   websockets y la cadena de redirects; analiza parámetros y payloads,
   decodifica (URL, Base64, JSON, hex, JWT, query anidado: raw_value,
   decoded_value, encoding_detected, confidence) y clasifica con listas
   (EasyPrivacy/EasyList + entidades de DDG Tracker Radar o, en el perfil
   comercial, de AdGuard companiesdb; versionadas en data/lists con LICENSES.md)
   y heurísticas.
3. Instrumentación de fingerprinting: init script envuelve APIs (canvas,
   WebGL, audio, measureText, navigator.*) y atribuye la llamada al script
   por stack. Los datos del binding son no confiables: validar tipo y tamaño.
4. Escenarios: consentimiento (sin_interaccion | aceptar | rechazar) y
   perfiles de spoofing coherentes y predefinidos (UA, Client Hints por CDP,
   viewport, timezone, locale, hardwareConcurrency, deviceMemory, WebGL).
   El consistency_checker alerta de combinaciones incoherentes.
   IMPORTANTE: el perfil "base" es el Chromium del worker, NO el navegador
   del usuario. Spoofing ≠ anonimato.
5. Inteligencia: IP/ASN/organización/país con bases offline (DB-IP Lite). No se
   consulta ningún servicio externo (el respaldo por RDAP previsto en F0 no se
   implementó: todo es offline). Dato faltante = "no_disponible", con su motivo.
6. Reporte: JSON validado por schema; exportación a HTML autocontenido y PDF (F8).

## Scores
Ambos son estimaciones, no verdades. Todos los pesos están en `data/scoring.yaml`.

### tracking_score (por request, 0–100)
`score = clamp(0, 100, Σ peso de las señales presentes)`. Cada señal presente se
guarda como razón `{signal, weight, level, evidence_ref, detail}`; una request con
score > 20 siempre tiene al menos una razón.

Bandas (`data/scoring.yaml`, única fuente): 0–20 Bajo · 21–40 Bajo-moderado (v1.4.8; antes «Posible», que es
un nivel de evidencia) · 41–60 Moderado · 61–80 Alto · 81–100 Muy alto. Las mismas bandas valen para el índice del sitio.
"Tracker" = request en banda ≥ Moderado.

Señales positivas: coincidencia con una lista (solo cuenta la de mayor peso),
third-party (peso mínimo: por sí solo no hace tracker), mismo valor enviado a
dominios de varias organizaciones, valor igual a una cookie o ítem de storage,
valor que contiene la URL de la página, Set-Cookie de un tercero, parámetro con
nombre y forma de identificador, token de sesión o JWT hacia un tercero, pixel,
beacon, cuerpo codificado hacia un tercero.
Señales negativas: asset estático first-party sin parámetros; asset estático de
terceros sin parámetros, cookies ni cuerpo y sin coincidencia de listas.

### site_exposure_score (por sitio, 0–99; mayor = más expuesto)
Asintótico, para que no sature:

    componente_i = cap_i · (1 − e^(−n_i / k_i))
    score = floor(Σ componente_i)

Cada componente tiende a su tope sin alcanzarlo. Los topes suman 100, así que el
score nunca llega a 100. `k` es la cantidad de ítems con la que el componente
alcanza ~63 % de su tope.

| Componente | n | cap | k |
|---|---|---|---|
| tracker_domains | dominios registrables de terceros con ≥ 1 request tracker | 30 | 8 |
| id_sync | valores distintos enviados a dominios de 2 o más organizaciones distintas del sitio | 15 | 3 |
| url_leak_recipients | terceros que recibieron la URL de la página (parámetro o Referer completo) | 12 | 4 |
| persistent_id_recipients | terceros que recibieron un valor igual a una cookie/storage | 13 | 4 |
| third_party_domains | dominios de terceros contactados | 5 | 15 |
| stored_items | cookies no funcionales (v1.4.6) + ítems de storage que deja el sitio | 5 | 10 |
| fp_scripts | scripts con patrón compatible con fingerprinting | 10 | 2 |
| fp_exfiltration | APIs cuyos valores leídos aparecen en requests | 10 | 2 |

El desglose (n y puntos de cada componente) se guarda y se entrega en el reporte.

## Análisis (F3)
- Categorías de parámetro por nombre: identity, session, advertising, location,
  navigation, time, device (`data/param_names.yaml`). Es INFERENCIA: un nombre no
  prueba qué contiene el valor.
- Formas de valor: uuid, hex, base64, jwt, timestamp, numeric, ip, url, email, version. Se
  detecta la forma, nunca a quién pertenece.
- Decodificación recursiva (profundidad 3): url, base64, hex, json, jwt, query,
  gzip. Se guarda raw_value intacto, decoded_value, encoding_chain y confidence.
- Mecanismo por request: pixel, beacon, fetch/xhr, script, iframe, document,
  image, static, other. A nivel de sitio además: websocket, cookie, storage.
- Categoría por request: analytics, advertising, social, fingerprinting, session,
  telemetry, cross-site, third-party (genérico), first-party.
- Categorías de datos del sitio: DEVICE, IDENTIFIERS, BEHAVIOR, NETWORK, LOCATION,
  ADVERTISING, SESSION; cada ítem es observado | inferido | potencial.
- Cada resultado guarda analyzer_version. El análisis se puede repetir sobre una
  captura guardada sin volver a navegar.
- Reporte: `GET /api/scans/{id}/report`, validado contra
  `api/app/schemas/report-<versión>.schema.json`.
- Referer: por cada request a un tercero se clasifica la cabecera efectivamente
  enviada: full_url | origin_only | absent.

## Fingerprinting (F4)
- Instrumentación por init script (docs/adr/007): canvas, WebGL, audio, WebRTC,
  navigator, screen, Intl, matchMedia y otras. Agregada por (api, script).
- Heurísticas (umbrales en `data/scoring.yaml`), todas INFERENCIA: canvas (texto o
  ≥ 2 colores + lectura de ≥ 16x16), fuentes (≥ 50 distintas con measureText),
  audio (contexto offline + oscilador + compresor + lectura), WebGL (lectura de
  UNMASKED_VENDOR/RENDERER; la lectura en sí es EVIDENCIA), WebRTC (canal u oferta
  + onicecandidate), barrido (≥ 8 propiedades de navigator/screen).
- Estado por atributo: NO_DISPONIBLE | DISPONIBLE | UTILIZADO | OBSERVADO.
- Exfiltración: un valor leído, o su hash, aparece en una request → EVIDENCIA con
  referencias a la llamada y a la request.
- Nunca se afirma que haya fingerprinting confirmado ni la identidad de nadie.
- `GET /api/scans/{id}/fingerprinting` y sección `fingerprinting` del reporte.

## Hallazgos
Todo hallazgo es {claim, level, evidence_refs[]} con level ∈
EVIDENCIA | INFERENCIA | POSIBLE | DESCONOCIDO. Un recurso third-party no es
tracker por sí solo. Un nombre de parámetro no prueba que contenga datos
personales.

## Arquitectura
frontend (nginx + Vite build, :8080) → /api proxy → api (FastAPI,
127.0.0.1:8000) ↔ postgres (tabla jobs con FOR UPDATE SKIP LOCKED) ↔ worker
(Playwright; también analiza, renderiza los PDF y aplica la retención) → egress-proxy
(Squid) → Internet.
Redes: public (frontend, api), internal (api, db, worker), sandbox
(internal: true; worker, egress-proxy), egress (egress-proxy).
El worker solo sale a internet a través del egress-proxy.

## Interfaz (F5)
- Todo dato capturado se muestra como texto; las URLs capturadas no son enlaces.
- Badge único de nivel de evidencia en toda la aplicación; aviso fijo con los
  límites de la medición; modo presentación.
- nginx: Content-Security-Policy sin `unsafe-inline`, `X-Content-Type-Options`,
  `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`.
- Solo en 127.0.0.1; exposición en LAN únicamente con `DEMO_MODE=1`
  (`scripts/demo.sh`). En modo demo no se puede borrar el historial.
- `POST /api/scans`: límite por IP y tope de jobs en cola.

## Privacy Test (F7)
- Grupo de scans: escenarios de consentimiento × perfiles × corridas (1–5).
  Agregados por grupo: mediana y rango; por dominio, "apareció en k de N".
- Consentimiento: sin_interaccion | aceptar | rechazar, solo con CMP reconocidos
  (`data/cmp_selectors.yaml`); si no, "no_aplicable". Nunca se adivina un botón.
- Perfiles coherentes y predefinidos en `data/profiles/` (solo Chromium), más uno
  incoherente para la demo. La IP no cambia.
- Detector de inconsistencias (`data/consistency_rules.yaml`): valores observados
  = EVIDENCIA; "poco común o detectable" = INFERENCIA.
- Identificador igual en ≥ 2 corridas limpias del mismo perfil = EVIDENCIA; su
  origen (huella, IP o constante del sitio) = INFERENCIA.
- Nunca se afirma anonimato: solo qué cambió y qué sigue observable.
- El navegador del worker no genera tráfico propio (docs/adr/013).

## Mi exposición (F6)
- Colector en el navegador del visitante (`frontend/src/exposure/`); estado por
  atributo DISPONIBLE | NO_DISPONIBLE (con motivo). Sin permisos, sin WebRTC.
- El servidor no guarda nada de esta página: sin tabla y sin valores del cliente
  en los logs (docs/adr/011).
- `GET /api/exposure/server`: IP observada (X-Forwarded-For solo desde
  TRUSTED_PROXIES; una IP privada nunca se presenta como pública) y cabeceras.
- Inteligencia IP offline: DB-IP Lite país + ASN (CC BY 4.0), `data/ipdb/`,
  `scripts/update-ipdb.sh`. IP privada: "no aplica (red privada)".
- IP pública y comparación entre asistentes: solo con opt-in. La comparación usa
  hashes con sal por grupo, en memoria, con TTL y purga.
- No se afirma que una huella sea única sin una población de referencia.
- Vista en panel (F10.1, docs/adr/022): tarjetas de resumen, cuadrícula
  atributo | valor | identificabilidad | ⓘ, botón "Actualizar" con hora de lectura.
- Nivel de identificabilidad Alto / Medio / Bajo por atributo en
  `data/identifiability.yaml` (con justificación), servido por
  `GET /api/exposure/identifiability`. Es una estimación cualitativa: no se
  publican bits de entropía. Atributo sin entrada = sin badge ("—").
- IP observada, campo `ip.access`: `local` (red interna de Docker,
  `DOCKER_INTERNAL_NETWORKS`, o loopback: no es la IP del visitante), `lan`
  (IP privada, misma red local), `public` (país y ASN), `other`.
- Cruce con scans (v1.2): opcional, «Comparar con un scan» (`GET /api/exposure/scan-usage?job_id=`).
  Sin scan elegido la página muestra solo el navegador del visitante. Sin `job_id` el endpoint
  sigue sumando los scans guardados, sin los de fixtures ni los de tests (lo usa el Panel).
- Redacción: trato de usted; "grupo" y "administrador" en los textos. Se
  conservan por compatibilidad `/api/exposure/room`, `X-Presenter-Token`,
  `EXPOSURE_PRESENTER_TOKEN` y los códigos `ROOM_FULL` / `PURGE_DISABLED`.

## Inteligencia y reportes (F8)
- Consentimiento sin banner (docs/adr/015): estado TCF por `__tcfapi` (gdprApplies,
  cmpId → nombre con la lista de IAB, versión, estado; del tcString solo si existe)
  y Google Consent Mode en las requests (`gcs` documentado; `gcd` no oficial, nunca
  prevalece). Hallazgos EVIDENCIA, sin juicio legal.
- IP real de cada destino desde el proxy (docs/adr/016): usuario `scan-<id>` por
  scan con `PROXY_SCAN_SECRET`, log JSON en el volumen `scanlog` (el worker lo lee
  de solo lectura), rotación y retención. Conexión sin éxito = sin IP.
- Por destino (docs/adr/017): IPs, ASN, organización y país (DB-IP Lite) y dueño del
  dominio; si las fuentes difieren se muestran ambas. El país es la "ubicación
  aproximada del servidor por IP". Todo dominio tiene IP o "no_disponible" con motivo.
- CNAME cloaking: solo subdominios propios presentes en la captura; el resolutor
  consulta nombres y nunca conecta; timeout, caché y rate limit.
- `GET /api/scans/{id}/destinations` y sección `destinations` del reporte.
- Exportación (docs/adr/018): HTML autocontenido y PDF (Chromium del worker, sin red:
  0 requests durante el render). Resumen ejecutivo (lenguaje simple, usted, 3–5
  recomendaciones) + anexo técnico. Siempre: fecha, URL, versiones, leyenda de
  niveles, atribuciones y "no constituye asesoría legal".
- Identificadores enmascarados por defecto (prefijo + largo) en la query, el fragmento y los
  segmentos de ruta con forma de ID; mostrarlos es explícito.
- El sha256 del JSON del reporte va impreso en el documento.
- Marca opcional (`REPORT_BRAND_NAME`, `REPORT_BRAND_DIR` fuera del repo); sin ella,
  encabezado neutro. También para grupos de Privacy Test.
- Schemas: `report-1.6.0` (scan; añade `scan.interactive`, v1.4), `report-1.5.0`, `report-1.4.0` (scan; añade `story` y la frase técnica de hallazgos y requests; F10),
  `report-1.3.0` (añadió `license_profile`) y `group-report-1.0.0` (grupo); se conservan los
  anteriores.

## Hardening y operación (F9)
- Perfil de licencias (docs/adr/019): `LICENSE_PROFILE=no_comercial` (por defecto) o
  `comercial`, que no abre las fuentes NC ni las que no tienen licencia explícita y usa
  AdGuard companiesdb (CC BY-SA 4.0). El perfil se guarda con cada análisis y el reporte lo
  imprime. En modo comercial la CMP se identifica solo por número.
- Secretos (docs/adr/020): envueltos en la configuración de api y worker; no aparecen en
  repr, errores ni logs. Rotación con `scripts/rotate-secrets.sh`, sin perder datos.
- Retención: los scans terminados con más de `SCAN_RETENTION_DAYS` (30) se borran solos, con
  su captura, análisis y reportes; `scripts/purge.sh` para la purga manual. `report_files`
  se borra en cascada con su scan o su grupo.
- Contenedores: todos sin root, `cap_drop: ALL`, `no-new-privileges`, raíz de solo lectura,
  límites de memoria, CPU y pids, y healthcheck. Imágenes base por digest, más los parches
  de seguridad de la distribución. Verificable con `scripts/hardening-check.sh`.
- Escaneo (docs/SECURITY-SCAN.md): pip-audit, npm audit, Trivy y gitleaks sobre el historial.
- Modelo de amenazas en docs/THREAT-MODEL.md, con la evidencia de cada control.
- Arranque normal: `scripts/start.sh` (detecta la red, levanta y espera healthy). Tests:
  `scripts/test.sh`, que pone por su cuenta los valores que solo sirven para probar.
- OpenAPI en `/docs` y `/openapi.json`, solo en el puerto de la api.

## Navegador del worker (perfil base)
Chromium con ventana real sobre Xvfb, sin marcas de automatización y sin falsear
atributos (docs/adr/008). Es la línea base, no spoofing.
Idioma y zona horaria (v1.4.5): `WORKER_LOCALE` (por defecto `es-CL`) y `WORKER_TIMEZONE`
(`America/Santiago`). navigator.languages = [es-CL, es], Accept-Language `es-CL,es;q=0.9` en todas
las requests e Intl en esa zona: coherente para el detector de inconsistencias.

## Seguridad (SSRF)
Capa 1: validación de URL en la API (solo http/https, resolución DNS y
rechazo de IPs prohibidas, revalidación en cada redirect).
Capa 2 (la que garantiza): el proxy valida la IP RESUELTA en cada conexión.
Prohibidos: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15,
224.0.0.0/4, 240.0.0.0/4, 255.255.255.255; IPv6 deshabilitado; nombres de
servicios Docker, localhost, *.local, *.internal. CONNECT solo a 80/443.

## Límites (configurables por .env)
MAX_CONCURRENT_SCANS=2, SCAN_TIMEOUT_S=60, MAX_REQUESTS=1500,
MAX_BODY_CAPTURE_BYTES=65536, SCAN_RATE_LIMIT=10 por IP cada 60 s, MAX_QUEUED_JOBS=20,
MAX_GROUP_JOBS=10, SCAN_RETENTION_DAYS=30,
INTERACTIVE_IDLE_S=600, INTERACTIVE_MAX_S=1800, INTERACTIVE_MAX_REQUESTS=4000, RESOURCES_MEMORY_ALERT_PERCENT=85.

## Limitaciones declaradas
Playwright no ve todo el tráfico interno del navegador. Los Service Workers
pueden alterar lo observado (se bloquean por defecto). Headless puede cambiar
el comportamiento del sitio. La geolocalización por IP es aproximada.
No hay GPS sin permiso.

## Experiencia de usuario (F10, docs/adr/021)
- Regla: primero una frase técnica y técnicamente correcta de qué pasó; debajo, «Ver detalle
  técnico» con lo de siempre (URL, parámetros, decodificaciones, cabeceras, reglas, pesos).
  Trato de usted. Nunca se promete anonimato.
- Frases técnicas (registro técnico, trato de usted, sin analogías ni exclamaciones; nombran
  el mecanismo y lo explican en una línea): plantillas deterministas en `data/explanations.yaml`, una por señal (cada
  request) y por tipo de hallazgo, con variante por nivel. Una frase que no es EVIDENCIA
  lleva siempre un matiz («podría», «es compatible con»); si faltan datos se usa la frase
  genérica del nivel. Un YAML que redacte una inferencia como hecho no carga.
- «Hallazgos por grupo» (sección `story` del reporte, schema `report-1.4.0`): siete grupos (ocho desde v1.4.2, ver más abajo)
  fijos —identificadores persistentes, fingerprinting, fugas de URL y Referer, exfiltración
  de atributos, sincronización de identificadores, consentimiento (TCF / Consent Mode),
  fuera del alcance observable— con
  frase, conteo, niveles y hallazgos con evidencia. Sin hallazgos: «No se observó en esta
  visita». La misma estructura va en el resumen ejecutivo del HTML/PDF, que sigue sobrio.
- Menú del scan, en orden de lectura: Resumen · Hallazgos · Rastreadores · Fingerprinting ·
  Tráfico (requests), cada una con subtítulo técnico de una línea y un panel «¿Qué es
  esto?» (contenido de la vista + método).
- Glosario: `data/glossary.yaml`, `GET /api/glossary`, tooltip en cada término técnico.
- Progreso real: el worker publica etapa y contadores en `jobs.progress`. Etapas: en cola →
  abriendo el sitio → capturando (requests en vivo) → analizando → generando resultado →
  finalizado / falló. Tiempo transcurrido frente a `SCAN_TIMEOUT_S`. Sin porcentajes. El mismo
  componente muestra la «corrida k de N» de un Privacy Test.
- Borrado del historial: `DELETE /api/scans/{id}` y `DELETE /api/scans` con
  `{"confirm": "BORRAR"}`; borra scans, capturas, análisis, reportes y grupos por la cascada
  existente e informa cuánto se liberó. No toca `backups/`. En modo demo responde 403.
- «Mismo valor enviado a varias organizaciones» no cuenta versiones de software, trozos del
  User-Agent ni constantes del sitio (`data/shared_constants.yaml`); lo descartado se
  informa en `site.summary.shared_values_excluded`.
- Hallazgo `persistent_cookie` (EVIDENCIA): cookies que vencen a más de un día de la visita.
- Tema clásico (por defecto) y «Unidad Púrpura» (opcional, solo estilo visual; reemplazó al tema cómic,
  docs/adr/027); modo presentación en ambos; contraste WCAG AA.
  Tipografías OFL servidas localmente: la CSP no cambia (`font-src 'self'`).
- v1.3.3: en «Unidad Púrpura» los títulos de panel llevan franja diagonal de advertencia (`.panel-head`,
  tonos `alert` naranja por defecto, `danger` rojo en avisos de bloqueo y fallos, `neutral` morado/verde
  en paneles anidados). Mientras un scan o una importación de HAR están en curso se muestra una
  ilustración circular girando (`branding/scanning.jpeg`, versión local); desaparece al terminar o
  fallar y con `prefers-reduced-motion` no gira (pulso suave). Clásico: sin franja, borde neutro.

## Claridad y precisión (v1.2, docs/adr/023)
Propósito: analizar cómo los sitios recopilan información de los visitantes, con qué métodos y
hacia quién la envían.
- Menú: Panel · Analizar un sitio · Historial · Glosario. Las cinco pestañas del scan no cambian.
- Panel (`GET /api/panel`): totales (sitios, requests, organizaciones distintas), organizaciones
  «presente en k de N sitios», atributos del navegador más leídos y más enviados, ranking por
  índice de exposición y tarjeta de «Mi exposición» (atributos N de M, huella corta, GPU, tipo de
  IP). Base: scan analizado más reciente de cada sitio; sin scans de fixtures ni de tests.
- Analizar un sitio: sin opciones avanzadas = scan simple. «Opciones avanzadas» (consentimiento,
  perfil, corridas) = grupo de scans (ex Privacy Test). `#/privacy` redirige.
- URL de entrada: se detectan gclid, gclsrc, gbraid, wbraid, dclid, fbclid, msclkid, ttclid, yclid,
  _gl, mc_eid y utm_*; aviso y «Limpiar URL». Por defecto se escanea limpia (`clean_url`); se
  guardan la URL original y la escaneada.
- IDs de cuenta del sitio (`data/account_ids.yaml`: Google Analytics, GTM, Google Ads, Meta,
  Pinterest, Snapchat, TikTok, LinkedIn): se muestran como «ID de cuenta del sitio» (INFERENCIA,
  con evidencia) y se excluyen de «identificadores que persisten» y de «sincronización entre
  organizaciones». Reanálisis sin navegar: `scripts/reanalyze.sh`.
- Historial: scans y grupos de Opciones avanzadas, filtros por fecha, sitio y estado
  (`GET /api/scans`, `GET /api/privacy/tests`), borrar uno y borrar todo.
- Mi exposición: solo el navegador del visitante; «Comparar con un scan» (opcional) marca qué
  atributos leyó y envió el sitio de ese scan.
- Fingerprinting: tabla «Atributos de su navegador que leyó este sitio» (atributo · leído por ·
  enviado a), con los nombres de «Mi exposición».
- Opciones avanzadas: conclusión de una línea por plantilla, con nivel; motivo de los scans
  fallidos (error_code y mensaje, agrupados) en la tabla resumen.
- Modo compacto: títulos con subtítulo de una línea; explicaciones en ⓘ y en el Glosario;
  «Límites de la medición» plegado.
- Logo propio, servido localmente (CSP sin cambios); marca por defecto de los reportes.

## Terceros por organización y representatividad (v1.2.1, docs/adr/024)
- Cada request es `propio` (mismo dominio), `misma organización` (otro dominio del mismo dueño según el
  mapa de entidades) o `tercero` (otra organización o desconocida). Solo los de otra organización cuentan
  como terceros en el resumen, el índice de exposición, el Panel y los reportes; «misma organización» se
  muestra aparte. La clasificación se guarda en `request_analysis.party`.
- Una URL o un Referer completo enviados a un dominio de la misma organización (p. ej. amazon.com →
  ssl-images-amazon.com) es dato informativo, no hallazgo de fuga.
- Alerta «visita posiblemente bloqueada» (`site.summary.blocking`, umbrales en `data/scoring.yaml`): texto de
  verificación antibot en el título (captcha, «unusual traffic», desafío de Cloudflare…) o estado 403/429/503.
  Banner en Resumen, Historial, Panel y reportes; estos scans se excluyen del ranking del Panel. Desde v1.4.8
  pocas requests (< 20 configurable) ya no marcan por sí solas (ver §Scans fallidos y parciales).
- Parámetros de seguimiento de la URL de entrada en `data/tracking_params.yaml` (se añaden gad_source,
  gad_campaignid, srsltid, spm, scm, igshid, si, _hsenc, _hsmi, mkt_tok, oly_anon_id, oly_enc_id, rb_clickid,
  s_cid, vero_id, wickedid, ref_src).
- Giro de cada organización/script en `data/service_types.yaml` (grabación de sesión, antifraude/antibot,
  publicidad, analítica, medición de audiencia, red social, CDN, plataforma de consentimiento…). Es CONTEXTO
  (Inferencia), no evidencia del uso concreto; si no está, «tipo no identificado». Se muestra en Rastreadores,
  Fingerprinting, Panel y reportes.
- Conclusión de consentimiento por plantilla con su nivel (`data/consent_mode.yaml §conclusions`), en Resumen,
  Hallazgos y reportes: gcs granted sin interacción con banner; gcs sin estado (G1--); TCF presente pero no
  mostrado (gdprApplies=false y displayStatus disabled/hidden). Sin juicio legal.

## HAR: importar, exportar y comparar (v1.3, docs/adr/025)
- Todas las cifras de terceros (resumen ejecutivo, `capture.third_party`, destinos por dominio y por país,
  Opciones avanzadas) salen de `request_analysis.party = third_party`; «misma organización» va aparte
  (`capture.same_org`, `destinations.domains[].party`). Schema `report-1.5.0`.
- Analizar un sitio → «Importar archivo HAR» (máx. 50 MB): `POST /api/har/inspect` y `POST /api/har/import`.
  Mismo analizador que un scan. Marcado «Captura importada: navegador real del usuario»; sin
  fingerprinting instrumentado (se indica). Datos del HAR = no confiables: esquema y tamaño validados, solo texto.
- Cookie, Set-Cookie y Authorization: se advierte y se descarta el valor antes de guardar (nombre y largo).
- `net::ERR_BLOCKED_BY_CLIENT` = «bloqueadas por una extensión del navegador», conteo aparte.
- Varias cargas en el HAR (por `pageref` o por tiempo): se elige cuál analizar.
- Hallazgos nuevos (EVIDENCIA, reglas en `data/har_signals.yaml`): «Fuga de búsqueda» (término de búsqueda
  enviado a otro host) y «Ola de sincronización» (ráfaga de sync/csync/cookiematching a varias organizaciones).
- `GET /api/scans/{id}/har`: el scan como HAR 1.2, sin cookies ni Authorization por defecto.
- `GET /api/scans/{id}/compare/{otro}` y botón en el scan: organizaciones solo en uno u otro, ola de
  sincronización solo en el HAR, bloqueos por extensión y conclusión de una línea por plantilla.
- Analizar un sitio muestra la ilustración propia (`branding/analizar.jpeg`, versión optimizada local).
  Panel: «Panel de recolección de datos» · «Métodos, destinos y organizaciones observados en los sitios analizados».

## Antibot con respuesta 200 e índice parcial del HAR (v1.3.1, docs/adr/026)
- «Visita posiblemente bloqueada» suma dos señales (`data/scoring.yaml` §blocking; analizador 1.8.0):
  - `challenge_url`: firma de desafío (punish, _____tmd_____, x5sec, baxia, captcha, challenge-platform,
    cf-chl, px-captcha, datadome, captcha-delivery) en la URL de un documento o frame. Un script con la
    firma no cuenta, ni el iframe de un widget de captcha incrustado (`challenge_url_ignore`).
  - `tracker_anomaly_history` / `tracker_anomaly`: requests de rastreo muy por debajo de lo esperado para
    el total, contra scans anteriores del mismo sitio no marcados; sin historial útil, umbral conservador
    (un sitio con 0 requests de rastreo nunca se marca). El aviso dice siempre «posiblemente».
- v1.3.2 (analizador 1.9.0): la firma sola no marca la visita. Firma + rastreo normal (`challenge_partial`:
  ≥ 10 requests de rastreo y ≥ 5 % del total), sin otra señal y sin estar en la dirección de la propia
  página = «bloqueo parcial: un componente mostró verificación antibot» (`blocking.partial`, informativo,
  sigue en el ranking). Firma + rastreo muy bajo = «visita posiblemente bloqueada». Solo rastreo anómalo: nota
  Posible desde v1.4.8 (ver §Scans fallidos y parciales).
- El índice de un HAR importado se muestra como «índice parcial (sin cookies ni fingerprinting)» en
  Historial, Resumen, Panel y reportes; el ranking del Panel lo excluye (`partial_sites`). La comparación
  scan vs HAR informa requests de rastreo y organizaciones (`tracking`), no el índice.
- Limpieza de URL: `algo_pvid`, `algo_exp_id`, `pdp_npi`, `pdp_ext_f`, `utparam`, `gatewayAdapt`.
- «Importar archivo HAR»: botón «Seleccionar archivo .har» con el nombre elegido al lado; «Importar y
  analizar» visible desde el inicio, deshabilitado hasta elegir archivo.
- Historial muestra la ilustración propia (`branding/historial.jpeg`, versión optimizada local).

## Telemetría propia (v1.3.4, docs/adr/028)
- Envíos de eventos al propio sitio o a otro dominio de la misma organización (`party` = first_party |
  same_org), reconocidos por reglas de `data/first_party_telemetry.yaml`: segmentos de ruta (/count,
  /metrics, /collect, /events, /track, /beacon, /log, /ping.gif…), respuesta 204 a un POST o a un GET
  con parámetros, y analítica propia conocida (melidata, aplus/mmstat, adn, viewability).
- No son terceros ni «requests de rastreo»; se informan aparte (`summary.first_party_telemetry`) en
  Resumen, Rastreadores, Hallazgos (`first_party_telemetry` INFERENCIA, `first_party_analytics_script`
  EVIDENCIA) y reportes.
- Índice de exposición: componente `first_party_telemetry` (tope 4, k 6; cuenta endpoints de eventos +
  scripts de analítica propia). Para mantener la suma de topes en 100, `tracker_domains` baja de 30 a 26.
- Anomalía de rastreo: con título normal, sin firma antibot, sin otra señal y con telemetría propia
  (≥ `min_requests_for_note`), no se marca «posiblemente bloqueada»; queda la nota informativa «rastreo
  de terceros bajo; telemetría propia detectada» (`blocking.note`). Analizador 1.10.0.

## Captura interactiva (v1.4, docs/adr/029)
- Analizar un sitio → «Iniciar captura interactiva» (`POST /api/interactive`, misma validación de URL que un scan):
  el worker abre un Chromium en un display propio (Xvfb `:98`) y lo muestra con x11vnc; la interfaz lo ve con noVNC.
  Mismo `launch_kwargs` que un scan: egress-proxy (anti-SSRF), instrumentación de fingerprinting, monitor de red
  (todas las pestañas) y un único contexto, con las cookies reales de la sesión.
- «Detener y analizar» (`POST /api/interactive/{id}/stop`): mismo analizador; `source = interactive` y línea de tiempo
  de páginas visitadas (`scan.interactive`, schema `report-1.6.0`). Rotulado «captura interactiva» en Resumen,
  Historial y reportes. Dominios propios = sitio inicial y página final.
- Límites: una sesión a la vez (409 `INTERACTIVE_BUSY`), `INTERACTIVE_IDLE_S=600` sin teclado ni ratón,
  `INTERACTIVE_MAX_S=1800`, `INTERACTIVE_MAX_REQUESTS=4000`. Al terminar se destruyen contexto, navegador, x11vnc y Xvfb.
- noVNC solo por `127.0.0.1`: el worker no publica puertos; x11vnc escucha en la red `internal` con contraseña de un
  solo uso y la api hace de relé WebSocket (`/api/interactive/{id}/ws`) con token de sesión y `Origin` = `Host`.
  Sin portapapeles compartido. `file://` bloqueado por política. No disponible en modo demo (403).
- Aviso fijo: lo que se escribe y las cookies quedan en la captura; no iniciar sesión con cuentas reales si se va a
  compartir el reporte.
- v1.4.1: credenciales enmascaradas antes de guardar (`[enmascarado:N]`): campos `type=password` y parámetros o claves
  password, passwd, pass, pwd, secret, token, otp, pin, cvv, en cuerpos form, JSON y multipart. Solo se registra nombre
  y largo (`scan.interactive.masked_fields`). No cubre la query de la URL ni WebSocket.
- v1.4.1, Panel: capturas interactivas y HAR importados van fuera del ranking por índice, aparte y marcados (`partial_sites[].source`).

## Indicador de recursos (v1.4, docs/adr/029)
- Esquina inferior de todas las páginas: CPU y RAM del stack, scans activos y captura interactiva; clic = detalle por
  contenedor (frontend, api, worker, db, egress-proxy). Cada 5 s, solo con la pestaña visible.
- `GET /api/resources`: cada servicio informa sus contadores de cgroup v2 (`/sys/fs/cgroup`, solo lectura). Prohibido
  montar `/var/run/docker.sock`. CPU = diferencia entre dos muestras (100 % = un núcleo); dato sin medir = `no_disponible`.
- Aviso visual si la RAM de un contenedor supera `RESOURCES_MEMORY_ALERT_PERCENT` (85) de su límite.
- v1.4.3 (docs/adr/031): como la consola es fija al pie, el contenido reserva un hueco igual a su alto
  (variable CSS `--rc-reserved` que publica el componente; el último elemento de cada ruta queda visible y
  clicable). Se puede minimizar a un ícono y la preferencia se recuerda en localStorage (con try/catch, sin
  romperse si falta). En ambos temas.

## Registro de interacción y correcciones de capturas reales (v1.4.2, docs/adr/030)
- Hallazgos por grupo: OCHO grupos; el 7.º es «Registro de interacción» (schema `report-1.7.0`). En capturas
  interactivas el grupo fijo dice que hubo navegación humana; «Durante la sesión» en interactivas y HAR.
- Escucha de interacción (EVIDENCIA de la escucha; propósito no afirmado): la instrumentación registra qué script
  pide eventos de clic, mouse, desplazamiento, teclado, escritura, toque y visibilidad (`events.*`).
- Datos de interacción en payloads (INFERENCIA por nombre): coordenadas, profundidad de desplazamiento, permanencia,
  elemento, exposición (`data/interaction_signals.yaml`).
- Captura interactiva: el relé registra hora y tipo de cada clic, desplazamiento y tecla (nunca qué se tecleó ni
  dónde); envíos a otra organización en los 2 s siguientes, por encima de su ritmo normal → «Su interacción se envió a
  X» (EVIDENCIA de la secuencia), con línea de tiempo (`site.summary.interaction`).
- Hallazgos repetidos (mismo tipo, nivel y organizaciones) en una fila con conteo, desplegable; en Rastreadores, las
  requests de una organización por tipo de señal.
- Tipos de servicio: publicidad móvil, DMP, broker de datos, pixel de conversión por URL. Host de nube genérico con
  `_fbp` o payload de Meta → «posible servidor de Conversions API de Meta» (INFERENCIA, `data/server_side_tracking.yaml`).
- Canvas leído por una librería conocida (`data/benign_libraries.yaml`): EVIDENCIA de lectura, sin inferir fingerprinting.
- Scripts inline/eval: atribuidos a la organización (o host) de su documento. `same_org`: «Recurso de la misma organización».
- HAR exportado: una página por página visitada; `creator.version` real.
- Las pruebas no dejan scans en el historial (`scripts/purge-test-scans.sh`).
- Analizar un sitio: cada modo con su acento (tokens `--acc-*`, AA en ambos temas), título e ícono. Indicador de
  recursos: consola (mini de tres cuadros; completa con placas, estado y detalle; ALERTA solo con RAM > 85 %).

## Servicios de terceros, es-CL y correcciones de capturas reales (v1.4.5, docs/adr/032)
- «Servicios de terceros sin señales de rastreo» (`site.summary.third_party_services`): requests a otra
  organización por debajo de la banda de rastreador, por organización y tipo de servicio, con requests y
  evidence_refs. La request es EVIDENCIA; el tipo de servicio, contexto (INFERENCIA). En Rastreadores, Resumen y
  reportes, siempre (también con lista vacía); un análisis anterior no la muestra (no se inventa «0»).
- «Su interacción se envió a X» solo cuenta ENVÍOS con datos: POST/PUT/PATCH, beacon, ping, pixel (imagen con
  parámetros) o GET con parámetros. No cuentan descargas de recursos estáticos (.js, .mjs, .wasm, .css, fuentes,
  imágenes sin parámetros) ni lo servido por dominios de distribución de contenido
  (`data/interaction_signals.yaml §correlation`).
- Catálogo propio `data/organizations.yaml`: organización por sufijo de host (los hosts de `googleapis.com`, sufijo
  público, son de Google) y dominios de dueño desconocido. Tipos de servicio nuevos en `data/service_types.yaml`:
  mapas, fuentes, CDN de librerías, clima, widget para compartir, video, traducción, almacenamiento, backend de
  aplicaciones; los patrones `urls` distinguen un host o producto dentro de una organización.
- Dueño del dominio: si el mapa de entidades trae el nombre de una persona natural, la organización es
  `no_disponible`. Nunca se muestran nombres de personas (regla en `data/organizations.yaml §persons`).
- Frames de error del navegador: lo que corre en `chrome-error://chromewebdata/` (iframe que no cargó) no es del
  sitio; sus llamadas y scripts se descartan y solo consta «un recuadro no cargó» (`site.summary.error_frames`).
- Hallazgo `analytics_accounts` (EVIDENCIA): 2 o más IDs de cuenta de medición del mismo proveedor →
  «Los datos de la visita se enviaron a N cuentas de <proveedor>». Hallazgo `discontinued_tag` (EVIDENCIA, nota
  informativa): IDs `UA-` de Universal Analytics → «etiqueta de un servicio descontinuado».
- Perfil base del navegador en español de Chile (ver §Navegador del worker).

## Atribución, sincronización y cookies por propósito (v1.4.6, docs/adr/033)
- Librerías en CDN público (`data/organizations.yaml §public_cdns`: jsDelivr, cdnjs, unpkg): el recurso se atribuye a
  la librería leída de la ruta (`/npm/<paquete>`, `/gh/<usuario>/<repo>`, `/ajax/libs/<paquete>`, `unpkg.com/<paquete>`),
  nunca a la empresa del CDN (p. ej. Prospect One por jsDelivr): «librería <paquete> en CDN público (<cdn>)»; si la ruta no
  lo permite, «librería en CDN público (<cdn>)». Si la ruta coincide con `data/benign_libraries.yaml`, la librería se marca
  como conocida (`third_party_services.items[].library.benign`). La clasificación por organización (`party`) no cambia;
  en el conteo de organizaciones de «Servicios de terceros», las librerías de un CDN cuentan como una (la del CDN).
- Catálogo: UserWay (`userway.org`, `cdn.userway.org`, `api.userway.org`) es una organización; tipo de servicio
  «widget de accesibilidad».
- Sincronización (grupo 5): solo si el mismo identificador llega a 2 o más organizaciones distintas DEL SITIO (el sitio
  no cuenta como segunda organización). Con una sola organización, hallazgo `persistent_id_org` en el grupo 1:
  «Identificador persistente enviado a <org>» (EVIDENCIA). El índice no cambia por la reclasificación salvo el
  componente `id_sync`, que cuenta solo valores que llegaron a 2 o más organizaciones externas.
- Alias de organización (`data/org_aliases.yaml`): dominios del mismo dueño (p. ej. laserena.cl y munilaserena.cl,
  Municipalidad de La Serena) son la misma organización (`same_org`). Ganan sobre el catálogo y el mapa de entidades;
  entran en `lists_version`.
- Propósito de cookies por su nombre (`data/cookie_purposes.yaml`): funcional (sesión, PHPSESSID, cf_clearance, __cf_bm,
  idioma, carrito), analítica (_ga, _gid, _ga_*, _clck, _clsk, _hj*) y publicidad (_fbp, _fbc, _gcl_au, _ttp, IDE,
  test_cookie); el resto, «sin clasificar». Todas las cookies, también las del propio dominio. INFERENCIA: el nombre no
  prueba el uso. Resumen: `site.summary.cookie_purposes` (conteo por propósito); Hallazgos: `cookie_purpose`
  (analítica, publicidad; grupo 1) y `cookie_purpose_functional` (lista técnica); `persistent_cookie.details.purposes`.
  Las cookies funcionales no suman al índice (`stored_items` = cookies no funcionales + storage). Analizador 1.13.0.

## Fugas hacia un CDN y cookies por la organización (v1.4.7, docs/adr/034)
- La librería cambia la atribución del recurso, no oculta sus fugas: `url_leak` y `referer_leak` hacia un CDN público
  se informan y cuentan igual, y nombran al receptor real (`details.recipient`, `reasons[].data.recipient`): «CDN público
  <cdn> (<dueño>)», o la organización del dominio si el grupo mezcla hosts. Nunca una librería.
- Propósito de cookies en dos pasos (INFERENCIA): (a) nombre conocido; (b) si no, tipo de servicio de la organización
  dueña del dominio de la cookie (`cookie_purposes.yaml §by_service_type`: adtech/publicidad → publicidad; analítica →
  analítica; CDN/antibot → funcional). Sin ninguno: «sin clasificar». Cada cookie lleva `basis` (nombre | organizacion);
  el Resumen da `by_basis`. Nombres nuevos de Alibaba/AliExpress y adtech. Analizador 1.14.0.

## Scans fallidos y parciales, alerta antibot con señal dura (v1.4.8, docs/adr/035)
- Chromium del worker con `--disable-features=AcceptCHFrame` (scan y captura interactiva): un frame ACCEPT_CH (Client
  Hints por ALPS) reiniciaba la navegación y el reinicio quedaba abortado (`ERR_ABORTED`). Efecto: los Client Hints de
  alta entropía pedidos por ALPS no van en la primera request de cada origen; siguen yendo por `Accept-CH`.
- Scan fallido = «Sin medición»: sin índice, sin resumen ni «Nada observado»; se muestran el motivo, el código
  `net::ERR_*` real del navegador (`error.net_error`; si no hubo, se dice) y las requests capturadas antes del fallo.
  Historial: «Sin medición». API: `measured`, `failure`; reporte `scan.failure` (schema `report-1.8.0`).
- Scan parcial: si `goto` agota el tiempo con respuestas ya recibidas, el scan termina y se analiza lo capturado con
  el aviso «Scan parcial» (`result.partial`, `scan.partial_navigation`, `end_reason = navigation_timeout_partial`).
  En la captura interactiva la sesión sigue.
- Alerta antibot: señal dura (estado 403/429/503, título de desafío o firma antibot en la URL) → «el sitio pudo
  detectar el navegador automatizado» y exclusión del ranking. Pocas requests o rastreo anómalo sin señal dura →
  nota POSIBLE «La página podría haber mostrado una versión distinta al navegador automatizado; compare con un HAR
  propio.» (`blocking.possible_variant`), sin exclusión del ranking. Sin veredicto en scans fallidos, capturas
  interactivas ni HAR; en un scan parcial solo cuentan las señales duras. Analizador 1.15.0.
- Bandas: solo las de `data/scoring.yaml`; la 21–40 es «Bajo-moderado» (antes «Posible»). La api las lee del archivo.
- «Servicios de terceros sin señales de rastreo» excluye las organizaciones de publicidad o analítica (tipos de
  `cookie_purposes.yaml §by_service_type`); se cuentan en `excluded_requests`.
- Fuga de búsqueda: no si el valor es el título, la meta description o una meta keyword de la página
  (`result.page_meta`; los scans anteriores solo tienen el título).
- Servidor CAPI de Meta inferido (host de nube): cuenta como Meta en la sincronización y en el índice; se muestra
  «Meta (vía servidor CAPI, inferencia)».
- Fuga de URL: el valor debe contener la URL de la página entera (origen y ruta) seguida de fin o separador; otra
  ruta del mismo origen u otro host que empieza igual no cuentan.
- Catálogo: Liferay (plataforma CMS/analítica), Podscribe (publicidad/atribución), alias INACAP (inacap.cl,
  inacapmovil.cl). Cookies `l` y `cna`: por el nombre solo en dominios de Alibaba.
- WebRTC (grupo 2): creación de RTCPeerConnection y candidatos ICE leídos por la página, por tipo de dirección (IP
  local, IP pública, mDNS; nunca la dirección). EVIDENCIA: `webrtc_connection`, `webrtc_ice_exposed`. Glosario: WebRTC,
  Candidato ICE.

## Client Hints, redirecciones y puntaje por nivel (v1.4.9, docs/adr/036)
- Client Hints (`data/client_hints.yaml`), tres hechos distintos:
  - Solicitud (EVIDENCIA de solicitud): respuesta de otra organización con Accept-CH que pide hints de alta entropía
    (Sec-CH-UA-Full-Version-List, -Model, -Arch, -Bitness, -Platform-Version): «El servidor pidió datos del navegador
    potencialmente útiles para identificarlo; esta solicitud no demuestra que los haya recibido».
  - Envío (EVIDENCIA de envío): solo con la cabecera Sec-CH-UA-* en una request a esa organización. No se infiere por
    Accept-CH.
  - Delegación (contexto): Permissions-Policy (ch-ua-*) o meta delegate-ch del documento principal. «Delegación
    detectada» · «Sin delegación detectada» (no prueba que el envío sea imposible) · «No determinado», con evidencia.
  - Un hint ausente en la primera request a un origen está condicionado por el navegador de captura (ADR 035); una
    captura parcial sin la cabecera no basta para concluir que nunca se transmitió.
  - Puntos: `client_hints_request` (bajo, una vez por organización) y `client_hints_sent` (mayor, por request), en el
    tracking_score de la request; sin componente nuevo del índice.
- Detalle de request: cadena 3xx (Location → request #n); puntaje «Evidencia X + Inferencia Y»; Client Hints de esa
  request; conteo de la coincidencia con lista «N en esta visita, incluida esta».
- Sincronización por redirección (`redirect_sync`, EVIDENCIA, grupo 5): un salto 3xx lleva el mismo identificador de
  una organización externa a otra.
- Índice: cada componente con sus puntos de evidencia e inferencia; `summary.score_by_level`. Schema `report-1.9.0`.
- Identificador igual a una cookie en una request que no envió cookies: «un script copió el valor de la cookie «X» en
  la URL o el cuerpo de la request».
- Appier → publicidad. Bandas: el frontend las lee de `GET /api/bands`. Límites de la medición: aviso de STUN/UDP si la
  página creó conexiones WebRTC. Glosario: Client Hints, Accept-CH, Delegación de Client Hints, Cadena de redirección.
  Analizador 1.16.0.

## Fases
F0 spec · F1 infra+aislamiento · F2 captura · F3 análisis+scoring ·
F4 instrumentación · F5 UI · F6 exposición · F7 escenarios ·
F8 inteligencia+reportes · F9 hardening+docs (versión 1.0.0) ·
F10 experiencia de usuario (versión 1.1.0) · F10.1 Mi exposición (versión 1.1.1) · F10.2 (versión 1.1.2) ·
v1.2 claridad y precisión (versión 1.2.0) ·
v1.2.1 terceros por organización, representatividad y contexto (versión 1.2.1) ·
v1.3 HAR: importar, exportar y comparar; terceros del resumen por organización (versión 1.3.0) ·
v1.4 captura interactiva e indicador de recursos (versión 1.4.0) ·
v1.4.2 registro de interacción, agrupación y acentos (versión 1.4.2) ·
v1.4.3 el indicador de recursos reserva su hueco y se puede minimizar (versión 1.4.3) ·
v1.4.4 instalación simplificada y CI (versión 1.4.4) ·
v1.4.5 servicios de terceros, es-CL y correcciones (versión 1.4.5) ·
v1.4.6 atribución a librerías de CDN, sincronización entre organizaciones, alias y cookies por propósito (versión 1.4.6) ·
v1.4.7 fugas hacia un CDN con su receptor real y cookies por la organización (versión 1.4.7) ·
v1.4.8 navegación con ACCEPT_CH, scans fallidos y parciales, alerta antibot con señal dura, bandas y reglas corregidas, WebRTC (versión 1.4.8) ·
v1.4.9 Client Hints (solicitud, envío y delegación), cadena de redirección y puntaje por nivel (versión 1.4.9)
