# ADR 029 — Captura interactiva e indicador de recursos (v1.4.0)

Estado: aceptada · Fecha: 2026-10-12

## Contexto
Un scan visita una URL una vez y sin interactuar. Mucho de lo que un sitio recolecta solo aparece
al navegar: aceptar el banner, buscar, entrar a un producto, iniciar sesión. Importar un HAR lo
cubre a medias (sin instrumentación de fingerprinting ni cookies). Se pide que el usuario pueda
navegar él mismo en el Chromium del worker y que esa sesión se analice con el mismo analizador.
Además, la aplicación no mostraba cuánto consume el stack; un Chromium más durante 30 minutos lo
hace necesario.

## Decisiones — captura interactiva
1. **Mismo navegador que un scan.** `launch_kwargs` y `context_kwargs` sin cambios: proxy de salida
   con usuario `scan-<id>`, sin tráfico propio, Service Workers bloqueados, descargas rechazadas,
   `FingerprintMonitor` y `NetworkMonitor` (que ahora vigila varias pestañas). Un solo contexto para
   toda la sesión: las cookies son las reales de la sesión y se guardan al detener.
2. **Display y VNC propios, efímeros.** Xvfb `:98` (1440×900) y `x11vnc` se levantan al iniciar y se
   matan al terminar; los scans siguen en `:99` y no se ven. x11vnc se instala desde Ubuntu (GPL-2,
   proceso aparte).
3. **noVNC solo en 127.0.0.1, sin tocar las redes.** El worker sigue sin puertos publicados y solo
   en redes `internal: true`. x11vnc escucha en la IP del worker en la red `internal` (ni loopback
   ni `sandbox`). Quien lo acerca al navegador del usuario es la api, con un relé WebSocket
   (`/api/interactive/{id}/ws`) que nginx publica en `127.0.0.1:8080`. El cliente noVNC (MPL-2.0,
   v1.4.0: 1.5 y 1.6 no se pueden empaquetar) va en el bundle, en un chunk aparte; la CSP no cambia.
   Se descartó publicar un puerto de websockify en el worker: habría que sacarlo de sus redes
   internas (regla 3).
4. **Tres barreras para ver la pantalla:** estar en el equipo (loopback); el token de la sesión
   (256 bits, se entrega una vez a quien la inició, en la base solo su sha256, comparación en tiempo
   constante) junto con `Origin` = `Host` (evita el secuestro del WebSocket desde otro sitio); y la
   contraseña VNC de un solo uso (x11vnc borra el archivo al leerlo; se borra de la base al
   terminar). La api solo conecta a una IP de las redes de Docker y al puerto 5900.
5. **Deshabilitada en modo demo** (403): con el frontend en la LAN nadie debe manejar un navegador
   dentro del equipo.
6. **Límites.** Una sesión a la vez (índice único parcial en `interactive_sessions`; 409
   `INTERACTIVE_BUSY`), en un turno propio del worker que no ocupa `MAX_CONCURRENT_SCANS`. Cierre
   por inactividad (`INTERACTIVE_IDLE_S`, 600): inactividad = sin teclado ni ratón en el visor (la
   anota el relé; el tráfico de la página no cuenta). Duración máxima (`INTERACTIVE_MAX_S`, 1800) y
   tope de requests (`INTERACTIVE_MAX_REQUESTS`, 4000). También termina si el usuario cierra la
   ventana. En todos los casos se analiza lo capturado y se destruyen contexto, navegador, x11vnc y
   Xvfb. Si el worker se cae, la sesión no se repite (`max_attempts = 1`) y la api libera el turno.
7. **Marcado.** `source = interactive` en el job, el resultado, el resumen del análisis y el
   reporte (schema `report-1.6.0`: `scan.interactive` con la línea de tiempo de páginas —hora, URL,
   título, pestaña— y el motivo de cierre). Historial, Resumen y reportes HTML/PDF lo rotulan
   «captura interactiva»; las URLs de la línea de tiempo se enmascaran como las demás.
8. **Propio = el sitio inicial.** Los dominios propios son el de la URL inicial y el de la última
   página, igual que en un scan; lo demás que se visite cuenta como tercero. Es una decisión, no una
   medición: una sesión que salta entre sitios no es comparable con una visita.

## Riesgos y tratamiento
| Riesgo | Tratamiento | Residual |
|---|---|---|
| Lo que el usuario escribe (búsquedas, formularios, **contraseñas**) y sus cookies quedan en la captura y en el reporte | v1.4.1: las credenciales se enmascaran antes de guardar (ver «Enmascarado de credenciales»). Aviso fijo antes de iniciar y en el reporte: «No inicie sesión con cuentas reales si va a compartir el reporte». Reportes enmascarados por defecto; retención y borrado del historial como cualquier scan | **Sí**: las cookies de una sesión iniciada se guardan (son parte de lo que se analiza); el enmascarado no cubre la query de la URL, los frames de WebSocket, cuerpos en formatos no reconocidos ni un campo de texto corriente con un nombre no listado |
| El navegador como pivote a la red interna | El proxy valida la IP resuelta de cada conexión, igual que en un scan; `<-loopback>` impide el acceso directo a loopback; WebRTC sin UDP fuera del proxy | Probado desde la sesión real (`worker/tests/ssrf/test_interactive_ssrf.py`) |
| El navegador alcanza su propio VNC | Va por el proxy, que rechaza IPs privadas y nombres de servicio; además pide contraseña | Probado |
| Leer archivos del worker con `file://` (código, `/proc/self/environ`) | Política `URLBlocklist: ["file://*"]` y, como segunda barrera, la sesión vuelve a `about:blank` | `chrome://` sigue disponible para el operador (no expone secretos: la contraseña del proxy no va en la línea de comandos) |
| Otro proceso del equipo o un sitio abierto en el navegador del usuario intenta ver o manejar la sesión | Token + `Origin` + contraseña VNC; el estado público no entrega ninguno | `POST …/stop` no pide token: cualquiera en el equipo puede detener la sesión (se analiza lo capturado) |
| Portapapeles compartido | Desactivado (`-nosel`); no se puede pegar desde el equipo | Incomodidad aceptada |
| Sesión olvidada consumiendo recursos | Inactividad, duración máxima y tope de requests; indicador de recursos visible | — |
| Datos de la sesión en la interfaz | La pantalla es un `<canvas>`; URLs y títulos de la línea de tiempo se revalidan y se pintan como texto | Probado con la página de XSS |
| VNC sin cifrar | Solo viaja por la red interna de Docker y por loopback | Aceptado |

## Enmascarado de credenciales (v1.4.1)
- Antes de codificar y guardar cada cuerpo (el sha256 y el tamaño guardados son los del cuerpo ya enmascarado), el valor se
  reemplaza por `[enmascarado:N]` (N = largo). Solo en la captura interactiva; un scan automático no cambia.
- Qué campos: los que en la página eran `<input type="password">`, se llamen como se llamen, y los parámetros o claves llamados
  `password`, `passwd`, `pass`, `pwd`, `secret`, `token`, `otp`, `pin`, `cvv`, solos o como segmento de un nombre compuesto
  (`new_password`, `accessToken`, `user[pin]`; no `passenger` ni `pinterest`).
- Formatos: formulario urlencoded, JSON a cualquier profundidad (también cortado) y multipart (no los archivos).
- Se registra solo nombre, largo y request (`scan.interactive.masked_fields`); `null` = captura anterior a v1.4.1, sin enmascarar.
- Los nombres de los campos de contraseña los consulta el worker en cada frame, una vez por segundo: la instrumentación de
  fingerprinting retira del global el canal de bindings de Playwright, así que la página no puede avisar por un binding propio.
- Costo aceptado: en una captura interactiva un `token` de sesión enviado a un tercero queda enmascarado y deja de contar como
  valor compartido entre organizaciones.

## Decisiones — indicador de recursos
1. **Cada servicio lee su propio cgroup v2** (`/sys/fs/cgroup`, solo lectura dentro del contenedor):
   `cpu.stat`, `memory.current`, `memory.stat`, `memory.max`, `cpu.max`, `pids.*`. **Nadie monta
   `/var/run/docker.sock`** (`scripts/hardening-check.sh` lo verifica en ejecución).
2. **Cómo llega cada muestra a la api** (`GET /api/resources`): la api lee sus archivos; PostgreSQL
   lee los suyos con `pg_read_file` en la misma consulta que cuenta los scans; el frontend y el
   egress-proxy corren un bucle de shell (`report-resources.sh`, cada 5 s) — el frontend la sirve
   en un puerto interno (8082, no publicado) y el proxy la deja en el volumen `scanlog`; el worker
   publica la suya y reenvía la del proxy en `service_resources` (no tiene listeners y la api no
   comparte red con el proxy).
3. **Nada se estima.** CPU = diferencia entre dos muestras del mismo servicio (100 % = un núcleo);
   sin muestra anterior o con una de más de 20 s, «no disponible». RAM = `memory.current` menos la
   caché de archivos inactiva, como `docker stats`. Las muestras de otros servicios se validan
   (claves conocidas, solo números).
4. **Interfaz.** Esquina inferior de todas las páginas: CPU y RAM totales, scans activos y captura
   interactiva; clic = detalle por contenedor. Consulta cada 5 s solo con la pestaña visible; la api
   reutiliza la respuesta 1 s. Aviso visual si la RAM de un contenedor supera el 85 % de su límite
   (`RESOURCES_MEMORY_ALERT_PERCENT`).
5. Solo los cinco servicios del stack normal; los del perfil `test` no se informan.

## Consumo medido (2026-10-12, stack de pruebas, contadores de cgroup leídos con `docker exec`)
| Situación | CPU del stack (100 % = un núcleo) | RAM del stack |
|---|---|---|
| Reposo | 6,1 % | 506 MB |
| Captura interactiva abierta, visor conectado, página quieta | 13,1 % (worker 6,6 %, api 3,9 %) | 828 MB (worker 514 MB: +325 MB) |
| Navegación continua por el visor (12 páginas en 45 s) | 50,2 % (worker 41,4 %, api 5,8 %) | 864 MB (worker 546 MB) |
| Tras cerrar la sesión | 6,2 % | 525 MB (worker 201 MB) |

Indicador: una consulta sin caché cuesta ≈ 10,8 ms de CPU sumando nginx, api y PostgreSQL
(645 ms en 60 consultas) y responde en 4,2 ms de mediana (p95 15,5 ms), 1,3 kB. A una consulta
cada 5 s, ≈ 0,2 % de un núcleo. Los dos bucles de shell cuestan ≈ 0,18 % de un núcleo cada uno
(24 y 27 ticks de 10 ms en 135 s) y la lectura del worker 0,2 ms por muestra. Total ≈ 0,6 % de un
núcleo con una pestaña abierta; con la pestaña en segundo plano, solo los reporteros (≈ 0,4 %).

## Consecuencias
- Imagen del worker: + x11vnc y sus librerías. Api: + `websockets`. Frontend: + `@novnc/novnc`.
- Migración `0014`; schema `report-1.6.0` (se conservan los anteriores).
- Panel (v1.4.1): un sitio cuyo registro más reciente es una captura interactiva o un HAR importado sale del ranking por
  índice y se lista aparte, marcado con su origen; sigue contando para organizaciones y totales.
