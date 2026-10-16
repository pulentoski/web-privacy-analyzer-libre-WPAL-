# ADR 036 — Client Hints (solicitud, envío y delegación), cadena de redirección y puntaje por nivel (v1.4.9)

Estado: aceptada · Fecha: 2026-10-15 · Amplía [ADR 035](035-accept-ch-scans-fallidos-y-parciales.md)

## Contexto
- En AliExpress, la request #244 (Appier, `anylist.c.appier.net/r2?…enable_cookie_sync=1`, respuesta 307) respondía
  con `Accept-CH` pidiendo los Client Hints de alta entropía. El análisis no distinguía entre que un servidor **pida**
  datos del navegador y que el navegador **los envíe**: la cabecera se leía como si la captura demostrara la
  recepción. En esa captura ninguna request posterior a Appier llevó `Sec-CH-UA-Model`, `-Full-Version-List`, etc.
- La misma request iniciaba una cadena 3xx (#244 307 → #297 302 → #347 200) que no se mostraba, y el detalle de la
  request decía «0 requests en esta visita» en la coincidencia con EasyPrivacy, cuando el scan tenía 7.
- El puntaje de una request y el índice del sitio mezclaban, sin distinguirlos, puntos de evidencia y de inferencia.
- La lista de bandas seguía duplicada en el frontend.

## Decisiones
1. **Client Hints en tres hechos** (`data/client_hints.yaml`, `worker/app/analyzer/client_hints.py`):
   - **Solicitud** (EVIDENCIA de solicitud): respuesta de otra organización con `Accept-CH`/`Critical-CH` que pide
     hints de alta entropía (Full-Version-List, Model, Arch, Bitness, Platform-Version). Se registran la organización,
     los hints y las respuestas. Texto fijo: «El servidor pidió datos del navegador potencialmente útiles para
     identificarlo; esta solicitud no demuestra que los haya recibido».
   - **Envío** (EVIDENCIA de envío): solo si la cabecera `Sec-CH-UA-*` aparece en una request a esa organización; se
     registran la request, el destino y los hints. Nunca se infiere por `Accept-CH`.
   - **Delegación** (contexto): `Permissions-Policy` del documento principal con `ch-ua-*` hacia otros orígenes, o
     `<meta http-equiv="delegate-ch">` (el worker lo lee desde v1.4.9 en `result.page_meta.delegate_ch`). Estados:
     «Delegación detectada», «Sin delegación detectada» (cabeceras del documento registradas y meta leído, sin
     delegación) o «No determinado» (falta alguno; p. ej. scans anteriores a v1.4.9 o HAR), con la evidencia usada.
     «Sin delegación detectada» no prueba que el envío sea imposible.
   - Si falta un hint en la primera request a un origen no se atribuye al sitio: está condicionado por el navegador de
     captura (sin reinicio por ACCEPT_CH, ADR 035). Una captura parcial sin la cabecera no basta para concluir que
     nunca se transmitió; ambas notas acompañan el resultado.
   - **Puntuación**: señales de request en `scoring.yaml`, sin componente nuevo en el índice (cuentan a través del
     tracking_score, como las demás): `client_hints_request` (3, una vez por organización, en su primera respuesta con
     Accept-CH) y `client_hints_sent` (10, en cada request que llevó los hints). Solo Accept-CH nunca da puntos de envío.
2. **Cadena de redirección** en el detalle de request: cada salto 3xx con su `Location` y la request a la que llevó.
   **Sincronización por redirección** (`redirect_sync`, EVIDENCIA, grupo 5): un salto que lleva el mismo identificador
   (con forma de identificador, no constante) de una organización externa a otra distinta; el valor cuenta una vez en
   `id_sync`. Dentro de una misma organización (Appier → Appier) no es sincronización.
3. **Puntaje por nivel**: por request, suma de pesos por nivel («Evidencia X + Inferencia Y», con aviso si la suma
   excede 0–100); por sitio, cada componente lleva `evidence_count`, `evidence_points` e `inference_points` (un
   dominio rastreador es evidencia si llega a la banda de rastreador solo con razones EVIDENCIA; `fp_scripts` es
   siempre inferencia; en telemetría propia los scripts son evidencia y los endpoints inferencia), y el resumen trae
   `score_by_level`. Schema de reporte 1.9.0.
4. **Conteo de la lista en el detalle de una request**: la consulta traía los hallazgos sin sus referencias; ahora usa
   las del scan y la frase dice «N en esta visita, incluida esta».
5. **Cookie copiada**: si el valor de una cookie viaja en la URL o el cuerpo de una request que no envió la cabecera
   Cookie, el texto dice que «un script copió el valor de la cookie «X» en la URL o el cuerpo de la request».
6. Appier → publicidad también por la organización (además de appier.net y appier.com).
7. **Bandas**: el frontend no tiene lista propia; las lee de `GET /api/bands` (data/scoring.yaml) al arrancar. El
   color depende de la posición de la banda.
8. **WebRTC** en «Límites de la medición», solo si la página creó conexiones: «El navegador de captura no tiene salida
   UDP; los candidatos ICE obtenidos por STUN (IP pública) no son observables. Un visitante real podría exponerlos.»

## Consecuencias
- Analizador 1.16.0; `reanalyze.sh --all`. Con el reanálisis, la delegación de los scans anteriores queda «No
  determinado» si su documento no envió `Permissions-Policy` (el meta delegate-ch no se había leído).
- Las solicitudes de Client Hints suman pocos puntos a requests que normalmente ya eran de rastreo; el índice puede
  subir ligeramente por `tracker_domains` si una request cruza la banda.
