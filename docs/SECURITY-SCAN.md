# Escaneo de seguridad

Última ejecución: **2026-10-07**, con `./scripts/security-scan.sh` (usa la imagen oficial
de cada herramienta; ninguna recibe acceso al socket de Docker). Repetir antes de cada
publicación y tras actualizar imágenes o dependencias.

| Herramienta | Qué revisa | Resultado |
|---|---|---|
| pip-audit | `requirements.txt` de api, worker, e2e y fixtures | Sin vulnerabilidades conocidas en los cuatro |
| npm audit | `frontend/package-lock.json`, nivel alto o superior | 0 vulnerabilidades |
| Trivy 0.75.0 | Las 7 imágenes del proyecto, severidad HIGH y CRITICAL | 0 con corrección disponible; 44 + 44 + 2 + 2 altas **sin parche publicado**, justificadas abajo |
| gitleaks 8.30.1 | Todo el historial de git (9 commits) | 7 hallazgos, los 7 falsos positivos; ningún secreto real |

## Trivy

Primera pasada (antes de corregir), HIGH/CRITICAL con corrección disponible:

| Imagen | Hallazgos | Causa | Corrección aplicada |
|---|---|---|---|
| api, fixtures | 0 | — | — |
| worker, e2e | 2 del sistema + 7 de Python | OpenSSL de Ubuntu; `msgpack`, `setuptools`, `urllib3`, `virtualenv` que trae la imagen de Playwright (y copias dentro de `pip`) | `apt-get upgrade` en el build; se desinstalan `pip`, `setuptools`, `virtualenv` y `msgpack`, que no se usan en ejecución |
| egress-proxy | 4 | OpenSSL de Ubuntu | `apt-get upgrade` en el build |
| frontend | 42 | Paquetes de Alpine (curl, OpenSSL, expat, libxml2, c-ares, pcre2…) | `apk upgrade` en el build |
| db (postgres:16-alpine) | 22 (1 crítica) | `gosu`, binario Go con una stdlib antigua | Imagen propia que borra `gosu`: nunca se ejecuta porque el contenedor arranca como `postgres` |

Segunda pasada, tras reconstruir: **0 hallazgos HIGH/CRITICAL con corrección disponible
en las 7 imágenes** (`trivy exit=0`).

### Altas sin parche publicado (aceptadas)

| Imagen | Cantidad | Paquetes | Por qué se acepta |
|---|---|---|---|
| api, fixtures | 44 cada una | `util-linux` y su familia (`mount`, `login`, `libmount1`, `libblkid1`, `libuuid1`, `bsdutils`…: 4 CVE repetidos en 9 paquetes), `ncurses`, `libsystemd0`, `libudev1`, `perl-base`, `libacl1` | Vienen en `python:3.12-slim` (Debian 13) y Debian aún no publica corrección (estado `affected` / `fix_deferred`). El servicio no invoca esas utilidades, corre sin root, sin capabilities, con `no-new-privileges` y raíz de solo lectura: no hay camino para llegar a ellas desde una petición HTTP |
| worker, e2e | 2 cada una | `gstreamer1.0-plugins-bad`, `libgstreamer-plugins-bad1.0-0` | Dependencias de la imagen de Playwright para otros motores; Chromium no las carga. Sin corrección en Ubuntu 24.04 |

Se vuelven a revisar en cada escaneo: cuando la distribución publique el parche, la capa
de actualización del build lo recoge sola.

## gitleaks

Los 7 hallazgos, revisados uno a uno:

| Archivo | Regla | Qué es en realidad |
|---|---|---|
| `data/lists/easylist.txt` (3) | `sourcegraph-access-token` | Hashes de commits de git citados en comentarios de EasyList |
| `fixtures/static/manifest.json` (2), `fixtures/static/tracker.js` (1) | `jwt` | JWT de prueba del sitio de fixtures, con firma `signatura-de-prueba-no-valida` |
| `api/tests/test_reports_api.py` (1) | `generic-api-key` | Identificador ficticio usado para probar el enmascarado |

Sus huellas están en `.gitleaksignore`, cada una con su motivo; con ese archivo el
escaneo sale limpio. **No se reescribió el historial.**

Comprobación adicional, independiente de gitleaks: los valores de
`POSTGRES_PASSWORD`, `PROXY_SCAN_SECRET` y `EXPOSURE_PRESENTER_TOKEN` (los actuales y los
anteriores a la rotación) aparecen **0 veces** en `git log -p --all`.

## Qué no cubre

- Vulnerabilidades de severidad media o baja (se listan con
  `TRIVY_EXTRA="--severity MEDIUM,LOW" ./scripts/security-scan.sh trivy`).
- El binario de Chromium que distribuye Playwright: se actualiza subiendo de versión
  Playwright (docs/OPERACION.md).
- Las listas descargadas en `data/`: son datos, no código.
