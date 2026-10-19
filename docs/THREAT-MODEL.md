# Modelo de amenazas

Alcance: el stack de `docker-compose.yml` en el equipo de quien lo opera, usado en
local y, puntualmente, en una demostración con la página "Mi exposición" publicada en la red
local. No cubre un despliegue en internet: no hay autenticación de usuarios y no está
pensado para eso.

Cada control cita su **evidencia**: un test que falla si el control se rompe, o una
línea de configuración que `scripts/hardening-check.sh` o el propio compose verifican.

## Activos

| Activo | Por qué importa |
|---|---|
| Red local y servicios del equipo anfitrión | Un analizador de URLs es, por diseño, algo que hace peticiones a donde le digan. |
| Secretos (`POSTGRES_PASSWORD`, `PROXY_SCAN_SECRET`, `EXPOSURE_PRESENTER_TOKEN`) | Acceso a la base, uso del proxy, purga del grupo. |
| Datos capturados (URLs, cabeceras, parámetros, cookies de la sesión del scan) | Pueden contener identificadores de terceros y contenido del sitio analizado. |
| Datos de los asistentes a una demostración | Lo que su navegador revela en "Mi exposición". |
| Integridad de los resultados | Un reporte se entrega a un tercero: debe decir lo que se observó. |
| El propio equipo del operador y de quien abre un reporte | La interfaz y los reportes muestran contenido de sitios hostiles. |

## Actores

| Actor | Capacidad |
|---|---|
| Sitio analizado hostil | Controla todo lo que el navegador del worker carga y ejecuta: HTML, scripts, redirecciones, DNS de su dominio, nombres de archivo, valores. |
| Usuario del formulario | Elige la URL. En local es el operador; con `DEMO_MODE=1`, cualquiera en la red. |
| Asistente en la red local | Llega a los puertos publicados en modo demo y puede enviar peticiones arbitrarias. |
| Destinatario de un reporte | Abre un HTML o PDF exportado; puede reenviarlo. |
| Dependencia comprometida | Una imagen base, un paquete o una lista descargada con contenido malicioso. |

## Superficies

1. **Formulario de URL** — `POST /api/scans`, `POST /api/privacy/test`.
2. **Sitio analizado** — lo que ejecuta Chromium en el worker y todo dato que de ahí
   llega a la base, a la api, a la interfaz y a los reportes.
3. **Demo en LAN** — puertos 8088/8443 (`DEMO_MODE=exposure`) u 8080 (`DEMO_MODE=1`).
4. **Archivos exportados** — HTML, PDF y JSON que salen del sistema.
5. **Cadena de suministro y operación** — imágenes, dependencias, listas, `.env`, respaldos.

## Amenazas (STRIDE), control y evidencia

### 1. Formulario de URL

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| I, E | SSRF: pedir `http://169.254.169.254/`, `http://db:5432/`, la IP LAN o el gateway | Capa 1: la api valida esquema, puerto, host y la IP resuelta. Capa 2 (la que garantiza): el proxy valida la IP resuelta en **cada** conexión; el worker no tiene otra salida | `api/tests/test_url_validator.py`; `worker/tests/ssrf/test_ssrf.py` (Chromium real contra gateway, IP LAN, metadatos, nombres de servicios); redes `internal: true` en `docker-compose.yml` |
| I | SSRF por redirección: URL válida que responde 302 hacia un destino prohibido | El proxy valida la IP resuelta en cada conexión, no solo la primera | `test_redirect_from_an_allowed_site_to_a_forbidden_destination_is_blocked` (metadatos, loopback, red privada, `api`, `db`) |
| I | DNS que cambia entre la validación y la conexión (rebinding) | La validación de la api no es la que garantiza: el proxy resuelve por su cuenta y aplica la lista de rangos a esa IP | `egress-proxy/squid.conf.template` (ACL `dst` sobre la IP resuelta); nombres que resuelven a IPs privadas en `BLOCKED_URLS` (`localtest.me`, `10.0.0.1.nip.io`). Sin test con un DNS que cambie entre consultas |
| T | URL con credenciales, IPv6, puertos raros, IPs en octal o hexadecimal | Rechazadas antes de encolar | `api/tests/test_url_validator.py` |
| D | Inundar la cola de scans | Límite por IP (`SCAN_RATE_LIMIT`), tope de cola (`MAX_QUEUED_JOBS`), tope por grupo; las URLs inválidas no gastan cupo | `api/tests/test_limits_api.py` |
| D | Un fallo de DNS deja inservible el formulario | Responde 400 `DNS_RESOLUTION_FAILED` sin gastar cupo | `test_dns_failure_is_a_400_and_does_not_consume_quota` |
| S | Falsear la IP de origen con `X-Forwarded-For` para saltarse el límite | Solo se acepta desde el nginx del frontend (`TRUSTED_PROXIES`) | `test_rate_limit_is_per_client_ip_from_trusted_proxy_only` |

### 2. Sitio analizado hostil

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| E | Escapar del navegador al contenedor o al anfitrión | Sandbox de Chromium activo, perfil seccomp, usuario sin privilegios, `cap_drop: ALL`, `no-new-privileges`, raíz de solo lectura, límites de memoria, CPU y pids | ADR 001; `scripts/hardening-check.sh` (tabla abajo) |
| I | Usar el navegador como pivote hacia la red interna | El worker solo está en redes `internal: true`; toda conexión pasa por el proxy con su lista de rangos prohibidos; IPv6 deshabilitado | `worker/tests/ssrf/test_ssrf.py`; ADR 002 |
| T, E | XSS almacenado: payloads en título, URLs, parámetros, cookies, nombres de script | Todo se pinta como texto; sin `dangerouslySetInnerHTML`; las URLs capturadas no son enlaces; CSP sin `unsafe-inline` | `e2e/tests/test_xss.py` (sitio que siembra payloads en todo); control negativo `e2e/tests/test_xss_control.py` |
| T | Inyección en SQL o en el schema del reporte | Consultas parametrizadas; el reporte se valida contra su JSON Schema antes de servirse | `test_invalid_report_is_not_served`; `test_schema_rejects_findings_without_level_or_evidence` |
| T | Falsear la telemetría de fingerprinting desde la página | Los datos del binding se tratan como no confiables: tipo y tamaño validados, topes | `worker/tests/fingerprint/test_instrumentation.py`; ADR 007 |
| D | Agotar recursos: miles de requests, cuerpos enormes, página que no termina | `MAX_REQUESTS`, `MAX_BODY_CAPTURE_BYTES`, `SCAN_TIMEOUT_S`, límites del contenedor | `worker/tests/capture/test_capture.py` (página de inundación) |
| T | Engañar al análisis para que el scan de otro cliente reciba sus conexiones | Cada scan usa su usuario de proxy; el log se filtra por usuario exacto | `worker/tests/f8/test_proxy_attribution.py` |
| I | Convertir el resolutor de CNAME en un SSRF por DNS | Solo hostnames ya presentes en la captura, sintaxis estricta, solo consulta de nombres, nunca una conexión | `test_resolver_rejects_hostnames_outside_the_capture` y siguientes |
| R | Afirmar más de lo observado | Todo hallazgo lleva nivel y referencias; sin ellas el schema lo rechaza | Regla 1 de CLAUDE.md; tests de schema |
| I | La consulta del país de la IP de salida (v1.5.0) expone o guarda la IP del analizador | Va por el egress-proxy con un usuario propio y fuera del navegador; respuesta acotada a 64 bytes y validada como IP pública; la IP se descarta tras geolocalizarla (ni en la base ni en los logs); `EGRESS_IP_SERVICE_URL` vacía = sin consulta. El servicio externo sí ve la IP de salida y la hora (no la URL analizada) | `worker/tests/v150/test_visit_protocol.py` (variable vacía, respuestas inválidas, usuario de proxy propio); `worker/tests/v150/test_visit_stack.py::test_scan_records_country_without_the_ip`; ADR 038 |

### 2 bis. Captura interactiva e indicador de recursos (v1.4, docs/adr/029)

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| I, E | El navegador que maneja el usuario como pivote a la red interna, a loopback o a su propio VNC | Mismo `launch_kwargs` que un scan: todo sale por el proxy, que valida la IP resuelta | `worker/tests/ssrf/test_interactive_ssrf.py` (23 destinos, fetch y WebSocket desde la página) |
| S, E | Ver o manejar la sesión sin haberla iniciado (otro proceso, otra pestaña, un sitio que abre un WebSocket) | Solo loopback; token de sesión (hash en la base) + `Origin` = `Host`; contraseña VNC de un solo uso; x11vnc solo en la red `internal` | `api/tests/test_v14_api.py::test_interactive_session_end_to_end`; `test_vnc_listens_only_on_the_internal_network_and_requires_password` |
| E | Manejar un navegador del equipo desde la LAN en modo demo | 403 `INTERACTIVE_DISABLED` en REST y en el WebSocket | `test_interactive_is_disabled_in_demo_mode` |
| I | Leer archivos del worker con `file://` | Política `URLBlocklist` y regreso a `about:blank` | `test_local_files_are_not_reachable` |
| I | Contraseñas y datos escritos por el usuario dentro del reporte | v1.4.1: campos de contraseña y claves de credenciales enmascarados antes de guardar (nombre y largo); aviso antes de iniciar y en el reporte. **Residual**: cookies de sesión, query de la URL, WebSocket | `worker/tests/v141/test_password_masking.py`; ADR 029 |
| T, E | XSS con el título o la URL de una página visitada | La pantalla es un canvas; la línea de tiempo se revalida y se pinta como texto | `test_interactive_capture_end_to_end_with_hostile_page`; `test_timeline_from_the_visited_site_is_revalidated_and_masked` |
| D | Sesión olvidada o varias a la vez | Una a la vez, inactividad, duración máxima, tope de requests; todo se destruye al terminar | `worker/tests/v14/test_interactive_limits.py`; `test_everything_is_destroyed_at_the_end` |
| E | El indicador de recursos como vía al daemon de Docker | Cada servicio lee su cgroup (solo lectura); ningún contenedor monta `docker.sock` | `scripts/hardening-check.sh`; `worker/tests/v14/test_resources.py` |
| T | Muestra de recursos manipulada por otro contenedor | Solo claves conocidas y números; la interfaz la pinta como texto | `test_cgroup_parsing_and_untrusted_samples`; `test_resource_indicator_warns_above_85_percent_and_renders_text_only` |

| I | El registro de interacción guarda lo que el usuario tecleó o dónde hizo clic | El relé solo anota hora y tipo; no lee el keysym ni la posición | `api/tests/test_v142_api.py::test_interaction_log_keeps_time_and_kind_only`; `e2e/tests/test_v142.py` |
| R | Afirmar que la interacción «se envió» por coincidencia temporal | Línea base por organización, mínimo de interacciones, navegaciones excluidas; el texto dice «secuencia temporal» | `worker/tests/v142/test_rules.py` |

### 2 ter. Comparación de visitas (v1.5.2, docs/adr/040)

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| I | Los perfiles A y B guardan en disco cookies, Local Storage e IndexedDB de sitios reales | Volumen `profiles` montado solo en el worker; directorio dueño pwuser (uid 1001) y 0700; los perfiles se borran al terminar la comparación o al fallar una visita, y los huérfanos al arrancar el worker y en cada vuelta del reaper; fuera de respaldos (`scripts/backup.sh` vuelca solo la base) y de los exportes | `test_profiles_volume_is_private_to_the_worker_user`; `test_worker_runs_the_three_visits_and_removes_the_profiles` |
| I | `visit_comparisons.state` filtra valores de cookies | Solo huellas sha256 de cada archivo del perfil y de cada valor de cookie, nunca los valores | `test_cookie_fingerprints_keep_hashes_never_values` |
| T | Un nombre de directorio construido con datos externos sale del volumen | El directorio sale siempre de `uuid.UUID(...)` y del perfil `A`/`B`; la purga solo toca directorios con nombre de UUID | `test_profile_dir_only_from_uuid_and_known_profile` |
| T | El perfil B arrastra estado de A, o el de A se pierde sin aviso | B es otro directorio, otro proceso de Chromium y otro usuario del proxy, y debe abrir sin cookies; el estado de A se verifica por huellas antes de la visita 2; si algo no cuadra, la comparación es no válida | `test_profile_b_shares_nothing_with_profile_a`; `test_lost_or_changed_state_of_a_is_detected`; `test_lost_state_of_a_invalidates_the_comparison` |
| E | Un binario escrito en el perfil se ejecuta | Docker no permite `noexec`/`nosuid` en un volumen con nombre en disco (probado con Docker 29.8.0; con un bind el montaje queda `rw` y un binario copiado ahí se ejecuta). Lo compensan `no-new-privileges`, seccomp, `cap_drop: ALL`, uid 1001 y la raíz de solo lectura del worker | `scripts/hardening-check.sh`; `docker-compose.yml` (worker) |
| R | El resultado se lee como prueba de que el sitio reconoció al visitante | Textos fijos («se observó…», «no observado en esta captura», nunca «no existe») y advertencia fija: tres visitas no prueban causalidad | `test_same_value_in_1_and_2_and_different_in_3_is_persistent_with_the_fixed_text`; `test_absent_in_control_is_never_said_to_not_exist` |

### 3. Demo en LAN

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| E | Un asistente lanza scans o lee resultados | En `DEMO_MODE=exposure` los puertos publicados solo sirven "Mi exposición"; la API de scans responde 403 | `e2e/demo_tests/test_demo_mode.py` |
| I | El servidor acumula datos de los asistentes | "Mi exposición" no tiene tabla; los logs no llevan IP, User-Agent ni query; el grupo vive en memoria con TTL | `api/tests/test_exposure_api.py`; ADR 011 |
| S | Suplantar al administrador para purgar el grupo | Token en `.env`, comparación en tiempo constante; sin token la purga remota está apagada | `test_purge_needs_the_presenter_token`; `test_wrong_presenter_token_is_rejected_without_echoing_the_real_one` |
| S | Interceptar la página en una red compartida | https con certificado autofirmado y huella proyectada para que el público la compare | `test_certificate_matches_the_lan_address`; ADR 012 |
| D | Saturar la comparación grupal de huellas | Límite de peticiones y de participantes | `api/tests/test_exposure_api.py` |
| I | Olvidar el modo demo encendido | `./scripts/demo.sh down`; `scripts/start.sh` siempre levanta solo en loopback | docs/OPERACION.md; docs/GUIA-DEMOSTRACION.md |
| I | La documentación OpenAPI queda expuesta en la LAN | `/docs` solo existe en el puerto de la api (loopback); nginx no la reenvía | `frontend/nginx.conf`; ADR 020 |

### 4. Archivos exportados

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| E | El HTML ejecuta código o carga recursos al abrirse | Todo escapado; sin scripts, enlaces ni recursos externos; CSP `default-src 'none'` dentro del archivo; se sirve como adjunto con `sandbox` | `test_html_has_both_levels_and_the_mandatory_blocks`; `e2e/tests/test_reports.py` |
| I | El render del PDF filtra datos o contacta a un tercero | Navegador sin proxy, contexto offline, JavaScript apagado, toda request abortada y contada (debe ser 0) | `worker/tests/f8/test_render.py`; log `report_rendered` |
| I | El reporte reenvía identificadores de terceros | Enmascarado por defecto en query, fragmento y segmentos de ruta con forma de ID; mostrarlos es una opción explícita y el documento lo advierte | `test_mask_url_masks_id_shaped_path_segments`; `test_export_is_masked_by_default_and_sha256_matches_the_json` |
| T | Alguien altera el reporte después de exportarlo | El sha256 del JSON va impreso en el documento | `test_export_is_masked_by_default_and_sha256_matches_the_json` |
| R | El reporte se lee como dictamen legal o prueba de anonimato | Aviso "no constituye asesoría legal" al inicio y al final; ningún texto promete anonimato | `e2e/tests/test_reports.py`; `frontend/src/lib/wording.test.js` |
| I | Los reportes viejos quedan para siempre | Cascada al borrar el scan y purga por `SCAN_RETENTION_DAYS` | `test_report_files_are_deleted_with_their_scan_and_with_their_group`; `worker/tests/f9/test_retention.py` |

### 5. Cadena de suministro y operación

| STRIDE | Amenaza | Control | Evidencia |
|---|---|---|---|
| T | Imagen base o dependencia con vulnerabilidades conocidas | Imágenes por digest, versiones exactas en `requirements.txt` y `package-lock.json`, escaneo con pip-audit, npm audit y Trivy | `scripts/security-scan.sh`; docs/SECURITY-SCAN.md |
| T | Una lista descargada es una página de error o contenido inesperado | Los scripts validan formato y tamaño, registran sha256 y solo reemplazan si todo descargó bien; las listas son datos, nunca código | `scripts/update-*.sh`; `MANIFEST.json` de cada directorio |
| I | Un secreto aparece en un log, un traceback o el repositorio | Secretos envueltos (`SecretStr`/`Secret`); `.env` fuera de git; gitleaks sobre todo el historial | `api/tests/test_hardening_api.py`; `worker/tests/f9/test_secrets.py`; docs/SECURITY-SCAN.md |
| I | `PROXY_SCAN_SECRET` llega a la captura: en las requests `http://` Chromium manda `Proxy-Authorization` (usuario del scan y secreto en base64) y Playwright la entrega con las cabeceras del sitio (hasta 1.5.2) | La captura descarta `Proxy-Authorization` y `Proxy-Connection`; la migración 0017 las borró de las capturas existentes; la api las filtra en el detalle de request, el HAR (también con `include_sensitive`) y la comparación (ADR 041) | `worker/tests/v153/test_proxy_headers.py` (scan http real: ni la cabecera ni el secreto, en claro o base64, en ninguna salida ni reporte); `api/tests/test_v153_api.py`; `e2e/tests/test_v153.py` |
| I | Un secreto filtrado sigue sirviendo | Rotación con un comando, verificada contra la base | `scripts/rotate-secrets.sh` |
| I | Un respaldo de la base circula sin cuidado | `backups/` fuera de git, archivos con permisos 600 | `scripts/backup.sh`; `.gitignore` |
| I | Uso comercial con datos de licencia no comercial | `LICENSE_PROFILE=comercial` no abre esas fuentes y el reporte dice el perfil | `worker/tests/f9/test_license_profile.py`; ADR 019 |

## Endurecimiento por servicio

Salida de `./scripts/hardening-check.sh --profile test` del 2026-10-07 (lee los
contenedores en ejecución, no el archivo compose):

| Servicio | Usuario (uid) | cap_drop | no-new-privileges | Raíz solo lectura | Memoria | CPU | pids | Healthcheck | Estado |
|---|---|---|---|---|---|---|---|---|---|
| api | app (10001) | ALL | sí | sí | 512 MiB | 1 | 200 | healthy | OK |
| db | postgres (70) | ALL | sí | sí | 1024 MiB | 2 | 200 | healthy | OK |
| e2e | pwuser (1001) | ALL | sí | sí | 2048 MiB | 2 | 1024 | healthy | OK |
| egress-proxy | proxy (13) | ALL | sí | sí | 512 MiB | 1 | 200 | healthy | OK |
| fixtures | app (10001) | ALL | sí | sí | 256 MiB | 0,5 | 100 | healthy | OK |
| frontend | nginx (101) | ALL | sí | sí | 128 MiB | 0,5 | 100 | healthy | OK |
| frontend-vulnerable | nginx (101) | ALL | sí | sí | 128 MiB | 0,5 | 100 | healthy | OK |
| worker | pwuser (1001) | ALL | sí | sí | 4096 MiB | 4 | 2048 | healthy | OK |

Notas:
- `fixtures`, `e2e` y `frontend-vulnerable` solo existen con `--profile test`.
- El worker añade un perfil seccomp propio (`worker/seccomp_profile.json`) que permite
  al sandbox de Chromium crear sus espacios de nombres sin dar capabilities (ADR 001).
- Lo que cada servicio puede escribir es un `tmpfs` o un volumen declarado; el único
  volumen con datos persistentes es `pgdata`; `profiles` (v1.5.2) guarda los perfiles de una comparación de visitas
  solo mientras dura.
- Puertos publicados: solo `127.0.0.1:8000` (api) y `127.0.0.1:8080` (frontend).

## Riesgos aceptados

- **Sin autenticación de usuarios.** En loopback el operador es el único usuario. Con
  `DEMO_MODE=1` cualquiera en la red puede lanzar scans y ver resultados: por eso para
  demostraciones se recomienda `DEMO_MODE=exposure`.
- **El sitio analizado ve la IP pública del operador.** No hay VPN ni proxy externo.
- **Un escape del sandbox de Chromium** con un 0-day alcanzaría el contenedor del
  worker: sin privilegios, sin capabilities, sin escritura fuera de `tmpfs` y sin más
  red que el proxy y la base. La base sí es alcanzable desde ahí con la contraseña del
  entorno del worker.
- **Vulnerabilidades sin parche** en paquetes de las imágenes base
  (docs/SECURITY-SCAN.md).
- **Swagger UI** carga scripts de un CDN en el navegador de quien abre `/docs`.
- **Volumen `profiles` sin `noexec`/`nosuid`** (v1.5.2): Docker no lo permite en un volumen con nombre en disco;
  ver §2 ter.
- **El enmascarado es heurístico**: puede dejar pasar un identificador con forma de
  palabra. La variante con valores completos es siempre un documento sensible.
