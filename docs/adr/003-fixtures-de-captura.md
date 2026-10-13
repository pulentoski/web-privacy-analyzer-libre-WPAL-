# ADR 003 — Sitio de fixtures y decisiones de la captura (F2)

Estado: aceptado · Fase: F2

## Contexto
F2 exige verificar la captura contra un ground truth: un sitio propio que
registra lo que recibe. Ese sitio vive en la red `egress`, con IP privada y
nombres `*.fixtures.test` que no existen en DNS, es decir, justo lo que las dos
capas SSRF bloquean. Hace falta una excepción acotada y varias decisiones para
que el navegador de los tests sea el mismo que el de producción.

## Decisiones
1. **`ALLOW_FIXTURES` (por defecto 0) activa la excepción en las tres piezas.**
   - Proxy: `entrypoint.sh` activa las líneas `@FIXTURES_ON@` del template: un
     `hosts_file` con solo los tres nombres y una regla
     `allow sandbox_clients fixtures_names fixtures_dst`. Exige a la vez el nombre
     exacto **y** la IP fija del contenedor (172.30.4.10/32), y va después de
     `deny !allowed_ports`. Con `ALLOW_FIXTURES=0`, `.fixtures.test` se deniega
     explícitamente (403), no por fallo de DNS.
   - API: `url_validator` acepta los tres nombres exactos, solo `http` y puerto 80.
   - Worker: ver puntos 2 y 3.
   - `PROXY_ALLOW_FIXTURES` permite apagar la excepción solo en el proxy, para
     probar que es él quien bloquea aunque la API acepte la URL.
2. **`fixtures.test` se trata como sufijo público en los tests.** Por dominio
   registrable, `site.fixtures.test` y `tracker-a.fixtures.test` serían el mismo
   sitio (`fixtures.test`) y nada sería third-party. Con `ALLOW_FIXTURES=1` se
   añade `fixtures.test` a `extra_suffixes` de tldextract, igual que `github.io`
   en la PSL. La PSL es la empaquetada (`suffix_list_urls=()`), con sufijos
   privados incluidos; un TLD que no está en la PSL usa la regla implícita `*`.
3. **Chromium completo (`channel="chromium"`, headless nuevo) en vez de
   chromium-headless-shell.** Un Service Worker solo existe en contexto seguro y
   el sitio de fixtures es HTTP plano. `--unsafely-treat-insecure-origin-as-secure`
   (solo con `ALLOW_FIXTURES=1`, y solo para los tres orígenes) lo resuelve, pero
   headless-shell ignora el flag. Se cambió el binario para todos los scans, no
   solo en tests: así se prueba el mismo navegador que corre en producción, y el
   headless nuevo se comporta como un Chrome real. Coste: más memoria por scan.
   El sandbox (ADR 001) sigue activo; los tests SSRF se repitieron con este binario.
4. **Initiator por CDP con stacks asíncronos.** Se abre una sesión CDP propia
   (`Network.enable`, `Runtime.enable`, `Runtime.setAsyncCallStackDepth`). Sin
   stacks asíncronos, Chromium reporta como `parser` lo que carga en diferido
   (p. ej. `new Image().src = ...`) y no se puede atribuir al script. No se usa
   `Debugger.enable`: pausaría páginas con `debugger;`.
5. **`post_data` con respaldo por CDP.** Playwright no entrega el cuerpo cuando
   es un Blob (típico de `sendBeacon`); en ese caso se pide con
   `Network.getRequestPostData`. La columna `post_data_source` dice de dónde
   salió (`playwright` | `cdp`).
6. **La captura se guarda aunque la navegación falle**, en la misma transacción
   que cierra el job: un scan bloqueado deja como evidencia la request bloqueada.
7. **Al llegar a MAX_REQUESTS el scan termina** (`end_reason=max_requests`): ya
   no se registraría nada más.
8. **Evidencia del Service Worker bloqueado**: el aviso de consola que emite
   Playwright al bloquear `register()` se cuenta y se loguea
   (`service_worker_registration_blocked`), y al final se consulta
   `getRegistrations()`.

> Nota (F5): desde el ADR 008 el worker ya no usa el modo headless; el punto 3 sigue
> valiendo en cuanto al binario (Chromium completo), ahora con ventana sobre Xvfb.

## Consecuencias y limitaciones
- Con `ALLOW_FIXTURES=1` el proxy tiene una ruta a una IP privada. Está limitada
  a una /32 de la red `egress` donde solo existe el contenedor de fixtures, que
  además solo arranca con `--profile test`. No usar en despliegues reales.
- El emparejamiento CDP ↔ Playwright es por (método, URL) en orden: requests
  idénticas y simultáneas pueden intercambiar initiator. Las sesiones CDP de
  iframes cross-site se abren al navegar el frame, así que sus primeras requests
  pueden quedar sin initiator (`null`, nunca inventado).
- El respaldo por CDP devuelve el cuerpo como texto: un Blob binario puede llegar
  alterado. `post_data_source=cdp` lo deja identificable.
- El aviso de consola lo puede imitar la propia página: `blocked_attempts` es un
  indicio; lo que garantiza es `registrations == 0` y `service_workers="block"`.
- Peticiones del propio navegador (favicon) no aparecen en la captura.
- `lease_margin_s` sube de 30 a 45 s: tras `SCAN_TIMEOUT_S` hay hasta 20 s para
  volcar la captura.
