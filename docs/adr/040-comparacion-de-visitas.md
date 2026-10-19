# ADR 040 — Comparación de visitas: perfiles A y B en disco, cola con espera y comparación por contexto

Estado: aceptada · Versión: 1.5.2 · Analizador 1.18.0 (sin cambios) · Schema de reporte 1.11.0 (sin cambios) ·
Protocolo de visita 1 (sin cambios)

## Contexto

Un scan es una visita con un navegador limpio (contexto efímero de Playwright). Con una sola visita no se puede saber si
un valor que el sitio envía o guarda se conserva entre visitas del mismo visitante. Se pidió una comparación
reproducible —no un detector de retargeting— de tres visitas: (1) perfil A limpio, (2) el mismo perfil A tras cerrar el
navegador, conservar su estado en disco y esperar un intervalo, (3) un perfil B limpio de control. Sin cambiar el
puntaje, la clasificación ni los resultados de los scans existentes.

Restricciones del stack: el worker tiene la raíz de solo lectura y solo tmpfs (RAM); la cola reparte jobs a 2 slots sin
forma de programar un job para más tarde; el egress-proxy no cachea (`cache deny all`).

## Decisión

### Cada visita es un job normal
Las tres visitas son jobs con el protocolo de visita de la v1.5.0 y el mismo análisis: su puntaje, banda y reporte se
calculan igual que los de cualquier scan. La api crea la comparación (`visit_comparisons`) y sus tres jobs juntos, cada
uno con `comparison_id`, `options.comparison {id, visit, profile}` y **un solo intento** (`max_attempts = 1`): repetir una
visita cambiaría el perfil en disco. Las tres cuentan para el rate limit y la cola: caben todas o no se crea ninguna.

### Cola con espera (`jobs.not_before`)
Columna nueva, nullable: el claim toma solo jobs con `not_before IS NULL OR not_before <= now()`. Las filas existentes
quedan en NULL y la cola funciona igual. Las visitas 2 y 3 nacen con `not_before = infinity`; al terminar una visita, en
la misma transacción que la cierra, el worker guarda su estado y libera la siguiente: la 2 con
`cierre del navegador de la 1 + intervalo`, la 3 de inmediato (el control queda lo más cerca posible en el tiempo). Si una
visita falla, las pendientes se marcan `COMPARISON_ABORTED` (también lo hace el reaper, para una visita cuyo lease venció).
Intervalo: `interval_s` en la petición (0–86 400) o `VISIT_COMPARISON_INTERVAL_S` (300 s). Se registran el configurado y
el real (del cierre del navegador en la visita 1 a su apertura en la visita 2).

### Contexto persistente solo en las comparaciones
Solo las visitas de una comparación usan `launch_persistent_context(user_data_dir)`; los scans normales e interactivos
siguen con `new_context()` efímero, como en la v1.5.1. Las tres visitas usan el mismo mecanismo (si solo A fuera
persistente, 1 y 3 se visitarían distinto de 2). Las opciones son las del navegador y del contexto efímero
(`launch_kwargs` + `context_kwargs`), más `--disk-cache-dir` dentro del perfil. La comparación no admite escenario, perfil
emulado ni sondeo: lo único que cambia entre visitas es el estado del perfil. Un test e2e compara la huella de un scan
normal con la que dio el código de la v1.5.1 (`e2e/tests/golden/scan_v151.json`).

### Perfiles en disco y su verificación
- Volumen Docker `profiles` montado solo en el worker en `/var/lib/wpa/profiles`; dueño pwuser (uid 1001) y 0700, que hereda
  de la imagen. Un directorio por comparación (`<uuid>/A`, `<uuid>/B`), con nombre siempre validado como UUID.
- Visitas 1 y 3: el directorio no puede existir antes (si existe → `COMPARISON_PROFILE_NOT_CLEAN`); se crea vacío (0700) y,
  antes de navegar, se comprueba que el contexto no tiene ninguna cookie. B es otro directorio, otro proceso de Chromium y
  otro usuario del proxy.
- Entre 1 y 2 se cierra el navegador entero: Chromium vuelca cookies, Local Storage e IndexedDB al disco. Las cookies de
  sesión se pierden, como en un navegador real.
- Al cerrar la visita 1 se guardan, en `visit_comparisons.state`, huellas: sha256 de cada archivo del perfil y de cada valor
  de cookie persistente (nunca los valores) y el inventario de almacenes. Antes de la visita 2 se recalcula la huella del
  directorio y, antes de navegar, se comparan las cookies cargadas con las de la visita 1 aún vigentes.
- La comparación es **no válida**, con su motivo, si: falta el directorio de A (`COMPARISON_STATE_LOST`), su contenido
  cambió, faltan cookies persistentes vigentes, no se pudieron leer, un perfil limpio no estaba vacío o tenía cookies,
  alguna visita falló, se borró o no tiene análisis.
- Los directorios se borran al terminar la visita 3 o al fallar una visita, y el worker borra al arrancar y en cada vuelta
  del reaper los de comparaciones sin visitas pendientes.

### Qué se compara
Función pura en la api (`api/app/comparison.py`), calculada al leer sobre las tablas que ya existen (`scan_requests`,
`request_analysis`, `scan_destinations`, `scan_cookies`, `scan_storage`, `parameters`): no escribe nada en los scans.
Siempre valores exactos dentro de su contexto, nunca solo nombres:

| Elemento | Contexto |
|---|---|
| Requests | método, host y ruta (tramos con forma de ID como `:id`) — presencia |
| Destinos | host — presencia |
| Organizaciones | organización — presencia |
| Cookies | dominio, ruta y nombre → valor |
| Identificadores en cookies | host, origen (`cookie`/`set_cookie`, decodificado) y nombre → valor |
| Storage | origen, tipo y clave → valor |
| URL | host, ruta, origen (query, referer, decodificado) y parámetro → valor |
| Cabeceras | host, ruta y cabecera → valor (sin las que genera el navegador, las del proxy, `Cookie` ni `Referer`) |
| Cuerpos | host, ruta, origen (formulario, cuerpo, decodificado) y campo → valor |

Clases y textos fijos:

| Visitas en que se observó | Texto |
|---|---|
| 1 y 2, distinto o ausente en 3 (solo valores con forma de identificador) | «se observó un identificador persistente entre dos visitas con el mismo perfil; el perfil limpio de control mostró un resultado distinto» |
| Solo 2 | «cambio observado en el perfil persistente que no apareció en los perfiles limpios» |
| 2 y 3 | «también observado en el control» |
| 1 y 2 (presencia) | «observado en las dos visitas con el mismo perfil y no en el perfil limpio de control» |
| 1, 3 o 1 y 3 | «observado solo en visitas con perfil limpio» |
| Ausencia en una visita | «no observado en esta captura» (nunca «no existe») |

Se descartan, con su motivo y total: valores iguales en las tres visitas (estáticos), de sesión (cookie sin expiración,
`sessionStorage` o su valor en la cabecera `Cookie`), constantes conocidas (`data/shared_constants.yaml`), sin forma de
identificador y, para «solo en la visita 2», los campos en que cada visita trae un valor propio (marca de tiempo, nonce).
Los valores se enmascaran salvo `?reveal=true`. Advertencia fija y siempre visible: tres visitas no prueban causalidad;
una diferencia puede deberse a publicidad dinámica, pruebas A/B, estado del servidor o a la captura, y el resultado no
indica que el sitio haya reconocido al visitante.

### Mismas condiciones
Cada visita registra URL, versión de Chromium, headful/headless, idioma, zona horaria, Accept-Language, instrumentación,
versión del protocolo, límites de captura, huella de los argumentos de Chromium, país de salida, worker y modo de perfil.
Cualquier diferencia se lista en el resultado.

### Fuera del Panel y del historial de un sitio
La visita 2 no es un perfil limpio: las visitas de una comparación no entran en el ranking del Panel ni en el historial con
que el analizador compara un scan con los anteriores del mismo sitio. El Historial lista las comparaciones aparte.

## Consecuencias y límites

- **Caché HTTP**: Playwright la desactiva en todos los scans (también los normales), porque el navegador se autentica
  contra el egress-proxy; las requests salen con `Cache-Control: no-cache` y el recurso cacheable del fixture llega al
  servidor en las tres visitas. B no puede compartir caché con A, pero la caché o el ETag como vía de persistencia no se
  observan. No se reactivó: cambiaría cómo se captura respecto de un scan normal.
- **noexec/nosuid**: Docker no los aplica a un volumen con nombre en disco (probado con Docker 29.8.0: el volumen rechaza
  esas opciones; con un bind el montaje queda `rw` y un binario copiado ahí se ejecuta). Quedan 0700 y uid 1001, verificados
  por un test, más `no-new-privileges`, seccomp y la raíz de solo lectura del worker (docs/THREAT-MODEL.md).
- **Misma IP**: las tres visitas salen por la misma IP; lo que el sitio asocie a la IP también alcanza al control.
- **Contexto persistente ≠ efímero**: las visitas de una comparación no se comparan con scans sueltos.
- Lo que la captura no ve (estado del servidor, service workers bloqueados, beacons de cierre no garantizados) sigue fuera.
- Migración 0016: tabla `visit_comparisons`, `jobs.comparison_id` (FK con cascada) y `jobs.not_before`, nullables; las filas
  existentes no cambian.
- Una comparación ocupa 3 scans del rate limit; con un intervalo largo la visita 2 espera en la cola sin ocupar slot.
