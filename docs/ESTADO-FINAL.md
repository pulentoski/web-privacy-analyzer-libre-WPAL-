# Estado final del proyecto (v1.0.0)

Checklist del encargo original, con la evidencia de cada punto tomada el 2026-10-07
sobre el stack en ejecución. Los comandos se pueden repetir tal cual.

| Punto | Estado | Evidencia (comando → salida) |
|---|---|---|
| Docker build | ✅ | `docker compose --profile test build` → termina sin error; 8 imágenes: `api`, `db`, `e2e`, `egress-proxy`, `fixtures`, `frontend`, `frontend-vulnerable`, `worker` |
| Contenedores | ✅ | `./scripts/start.sh --profile test` → los 8 servicios `healthy`; `./scripts/hardening-check.sh --profile test` → 8 filas `OK` (sin root, `cap_drop ALL`, `no-new-privileges`, raíz de solo lectura, límites, healthcheck) |
| Health del backend | ✅ | `curl -s 127.0.0.1:8000/health` → `{"status":"ok","database":true,"worker":true}` |
| Frontend | ✅ | `curl -sI 127.0.0.1:8080/` → `HTTP/1.1 200 OK` con `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; …` |
| Playwright | ✅ | `docker compose exec worker python -c "from importlib.metadata import version; print(version('playwright'))"` → `1.63.0` |
| Chromium | ✅ | Lanzado desde el worker con Playwright → `chromium 153.0.8010.12` |
| Validación de URL | ✅ | `POST /api/scans` con `ftp://example.com` → `SCHEME_NOT_ALLOWED`; `http://user:pass@example.com/` → `CREDENTIALS_NOT_ALLOWED`; `https://example.com:8443/` → `PORT_NOT_ALLOWED`; `no-es-url` → `SCHEME_NOT_ALLOWED` |
| Protección SSRF | ✅ | Capa 1: `http://127.0.0.1/` y `http://169.254.169.254/latest/meta-data/` → `IP_FORBIDDEN`. Capa 2: `docker compose exec worker pytest -q tests/ssrf` → `36 passed` (Chromium real contra gateway, IP LAN, metadatos, servicios internos y redirecciones 302 hacia ellos) |
| Carga de sitios | ✅ | Desde cero (`docker compose down -v` + `./scripts/start.sh`), scan de `https://example.com` → `status completed`, `http_status 200`, `title 'Example Domain'`, destino `172.66.147.243 / AS13335` |
| Captura de requests | ✅ | `GET /api/scans/<aliexpress>` → `total_requests 427` (92 propias, 335 de terceros), 82 cookies, 57 ítems de almacenamiento, 20 cadenas de redirección |
| Clasificación | ✅ | `GET /api/scans/<aliexpress>/trackers` → 196 requests de seguimiento en 33 grupos (Alibaba 75, Google 20, Taboola 13…), cada una con categoría y mecanismo |
| Análisis de parámetros | ✅ | Tabla `parameters` del mismo scan → 3 993 parámetros, 1 135 con forma de identificador; 460 decodificaciones (`base64`, `json`, `url`, `query` y cadenas como `base64 → query`) |
| Scoring | ✅ | Mismo scan → índice de exposición 92 («Muy alto»); bandas por request `Bajo 218 · Posible 13 · Moderado 111 · Alto 43 · Muy alto 42`; cada score con sus razones (`list_easyprivacy 40 EVIDENCIA`, `url_leak 20`, `fp_exfiltration 30`…) |
| Persistencia | ✅ | Tras rotar secretos, recrear contenedores y restaurar un respaldo: `180 scans, 34 499 requests, 3 891 hallazgos`, migración `0008 (head)`, idéntico antes y después |
| API | ✅ | `curl -s 127.0.0.1:8000/openapi.json` → versión `1.0.0`, 26 rutas; interfaz en `/docs` |
| Frontend con resultados | ✅ | `docker compose exec e2e pytest -q` → `26 passed` (flujo completo scan → resumen → requests → trackers → fingerprinting → hallazgos → evidencia → descarga de PDF, en un navegador real) |
| Tests | ✅ | `./scripts/test.sh api worker ssrf frontend e2e demo` → api `267 passed`, worker `341 passed` (incluye SSRF `36`), frontend `129 passed`, e2e `26 passed`, demo `6 passed` |
| Manejo de errores | ✅ | `GET /api/scans/00000000-…` → `{"error_code":"JOB_NOT_FOUND","message":"El job no existe.","details":{},"stage":"queue","timestamp":…}`; un UUID mal formado → `REQUEST_INVALID`; un error interno → `INTERNAL_ERROR` sin detalles (`test_error_responses_do_not_leak_internals`) |
| README | ✅ | `README.md` (368 líneas): qué es, objetivo, arquitectura con diagrama, tecnologías, instalación (`docker compose up --build`, `docker compose ps`, `curl /health`), uso, API, estructura, seguridad, limitaciones, tests y roadmap |

Notas sobre la evidencia:

- La primera pasada de la regresión dio `1 failed, 340 passed` en el worker: una
  comprobación de F8 exigía que las marcas de tiempo de tres scans se solaparan en el log
  del proxy, cosa que depende del orden de arranque de los navegadores. La atribución de
  conexiones sí pasó. Se cambió por una comprobación determinista (tiempo de vida de cada
  scan) y la suite completa volvió a correr: `341 passed`.
- Los scans de `<aliexpress>` son los de las muestras de F8 (`docs/samples/`). El único
  scan real de F9 fue el de `example.com`.
- Documentos de esta fase: [OPERACION.md](OPERACION.md), [GUIA-DEMOSTRACION.md](GUIA-DEMOSTRACION.md),
  [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY-SCAN.md](SECURITY-SCAN.md) y el
  [índice de ADR](adr/README.md).
