# ADR 007 — Instrumentación de fingerprinting

Estado: aceptado · Fase: F4

## Contexto
Hay que saber qué scripts usan APIs de fingerprinting y si lo que leen sale hacia
terceros. La instrumentación corre dentro de la página, en el mismo mundo JS que
el sitio analizado, que es hostil: puede intentar detectarla, romperla o
falsificar sus datos.

## Decisiones
1. **Init script + Proxy.** `worker/app/browser/fp_instrument.js` se inyecta con
   `context.add_init_script` (corre antes que el sitio, en cada frame). Cada API se
   reemplaza por un `Proxy` de la función original: conserva `name`, `length`,
   propiedades y prototipo, y el valor de retorno y las excepciones pasan intactos.
   `Function.prototype.toString` también se envuelve para que cada envoltorio se
   presente como la función nativa. Los constructores (`RTCPeerConnection`,
   `OfflineAudioContext`) se reemplazan además en sus alias `webkit*` y en
   `prototype.constructor`.
2. **El nombre aleatorio del binding no basta.** Se revisó el código de
   Playwright 1.63: `expose_binding` deja en el global, además de la función con el
   nombre elegido, la función nativa común `__playwright__binding__` y un objeto
   `__playwright__binding__controller__` cuyo mapa `_bindings` lista los nombres.
   Una página puede enumerarlos y llamar al binding. Por eso el init script:
   captura la función nativa en un closure, **borra del global los tres** (el
   nombre, el controlador y la función nativa) y habla con el worker llamando a la
   función nativa directamente, con el formato de mensaje de Playwright.
   Depende de internos de Playwright: revisar al subir de versión (los tests de
   abuso fallarían).
3. **Primordiales.** Todo lo que el hook usa después de la carga se captura al
   inicio (`Reflect.apply`, `JSON.stringify`, métodos de `WeakMap` y `String`...).
   Los hooks no usan métodos de prototipo, spread, `for-of`, destructuring ni
   regex; los objetos propios no heredan de `Object.prototype` (ni los handlers de
   Proxy ni lo que se serializa), así que un `toJSON`, un `push` o un
   `JSON.stringify` envenenados no interceptan nada.
4. **Atribución con CallSite, no con el texto del stack.** El texto de
   `Error.stack` incluye nombres de función que el sitio controla y pasa por
   `Error.prepareStackTrace`, así que se podrían fabricar frames. Se sustituye
   temporalmente `Error.prepareStackTrace` para pedir a V8 los CallSite
   estructurados y se lee el archivo con `getFileName` nativo, capturado al
   inicio. Luego se restaura lo que tuviera el sitio. Sin URL de script (código
   evaluado), la llamada se atribuye al documento del frame, que lo da Playwright.
5. **Todo mensaje es dato no confiable** (`fp_monitor.py`): token secreto por
   scan, esquema estricto (un lote con un campo inválido se descarta entero),
   catálogo cerrado de nombres de API, tamaños acotados, rate limit (10/s, ráfaga
   40), máximo 3000 lotes y 2000 filas por scan. La URL del frame la pone
   Playwright, no la página.
6. **Agregación en la página.** Contadores por (api, script), envío cada 500 ms
   (y desde los propios hooks, por si el sitio cancela el temporizador). Las
   lecturas de canvas menores de 16x16 solo se cuentan; de las demás se guarda
   detalle de como mucho 2 por combinación, y 60 por frame.
7. **No se guarda contenido de canvas ni de audio**: sha256 (implementado en el
   propio script, síncrono) y longitud. Sí se guardan valores cortos (≤ 256
   caracteres: user agent, GPU, zona horaria, pantalla), porque hacen falta para
   buscar su salida en las requests.
8. **Heurísticas en el analizador** (`analyzer/fingerprinting.py`), con los
   criterios de OpenWPM (Englehardt & Narayanan, 2016) y umbrales en
   `data/scoring.yaml`. "Fingerprinting" es siempre INFERENCIA; EVIDENCIA solo son
   la llamada observada y el valor que aparece en una request.
9. **Exfiltración**: se busca cada valor leído (≥ 10 caracteres), su sha256, sha1
   y md5, y el sha256 de cada lectura de canvas/audio, dentro de los parámetros de
   todas las requests, incluidos los decodificados.
10. **`FP_INSTRUMENTATION=false`** desactiva la instrumentación. Un scan sin ella
    se reporta como `instrumented: false`, no como "sin fingerprinting".
11. **Referer (ajuste de F3)**: se clasifica la cabecera que efectivamente se envió
    a cada tercero (`full_url`, `origin_only`, `absent`); no se deduce de la
    Referrer-Policy. La URL completa hacia un tercero es EVIDENCIA.
12. **site_exposure_score asintótico (ajuste de F3)**: cada componente vale
    `cap·(1−e^(−n/k))` y los topes suman 100; el total se trunca, así que nunca
    llega a 100.

## Limitaciones
- **Detectable.** Un sitio puede notar la instrumentación: los Proxy añaden frames
  al stack de un error, cambian tiempos de ejecución, y `toString` llamado desde
  otro realm (un iframe) sobre una función de este no muestra el nombre. Un sitio
  que la detecte puede comportarse distinto.
- **Web Workers, Service Workers y OffscreenCanvas no se instrumentan.** El init
  script no corre en workers.
- **Se puede esquivar** obteniendo APIs sin envolver por caminos no cubiertos, o
  escuchando candidatos ICE con `addEventListener` (solo se envuelve
  `onicecandidate`).
- **Un sitio puede falsear lo suyo**: no puede atribuir llamadas a otro script ni
  inventar eventos, pero sí puede hacer que sus propias llamadas no se registren
  (p. ej. dejando `Error.prepareStackTrace` no configurable, lo que las deja sin
  atribuir) o sobrecargar el canal hasta el rate limit (queda `truncated`).
- **Exfiltración solo por coincidencia exacta** del valor o de su sha256/sha1/md5.
  Las librerías reales suelen usar otros hashes (murmur) o combinar muchos
  atributos en uno: eso no se detecta. Cero exfiltraciones no significa que no
  haya salida de datos.
- **Initiator poco fiable tras `await`**: CDP reporta como `parser` requests
  lanzadas después de una espera asíncrona, así que la señal
  `fp_script_initiator` no siempre se aplica.
- **Lo último que haga la página puede perderse**: el envío es cada 500 ms y el
  scan termina tras 3 s sin requests.
- **El user agent del worker dice `HeadlessChrome` y `navigator.webdriver` es
  `true`**: algunos sitios cambian su comportamiento ante eso (el spoofing es F7).
