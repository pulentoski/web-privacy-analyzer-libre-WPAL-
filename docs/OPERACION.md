# Operación

Todo se ejecuta desde la raíz del repositorio, en el equipo anfitrión. Requisitos:
Docker con Compose v2, `curl`, `openssl` y `python3`.

| Tarea | Comando |
|---|---|
| Arrancar | `./scripts/start.sh` |
| Parar (conserva los datos) | `docker compose --profile test down` |
| Ver estado | `docker compose ps` · `curl -s 127.0.0.1:8000/health` |
| Ver logs | `docker compose logs --tail=200 <servicio>` |
| Ejecutar los tests | `./scripts/test.sh` |
| Rotar secretos | `./scripts/rotate-secrets.sh` |
| Purgar datos antiguos | `./scripts/purge.sh [días] [--dry-run]` |
| Respaldar / restaurar | `./scripts/backup.sh` · `./scripts/restore.sh <archivo> --si-reemplazar` |
| Modo demo | `DEMO_MODE=exposure ./scripts/demo.sh` · `./scripts/demo.sh down` |
| Revisión de seguridad | `./scripts/hardening-check.sh` · `./scripts/security-scan.sh` |

## Arrancar

```sh
./scripts/start.sh
```

Es la forma normal de arrancar, también después de un reinicio o de cambiar de red:

1. detecta el gateway y la IP LAN actuales y los escribe en `.env`
   (`scripts/refresh-lan-env.sh`);
2. ejecuta `docker compose up -d --build`;
3. espera a que **todos** los servicios estén `healthy` (hasta 420 s; el primer
   arranque crea la base y puede tardar más de un minuto) y muestra el estado.

Si un servicio no llega a `healthy`, el script termina con error y dice cuál.
`START_BUILD=0` evita reconstruir; `./scripts/start.sh --profile test` añade los
servicios de prueba.

`UPSTREAM_DNS` **no** se detecta solo: es el resolver que usa el proxy. Si los scans
fallan con `ERR_DNS_FAIL` en `docker compose logs egress-proxy`, revisarlo
(`resolvectl status`) y volver a ejecutar `start.sh`.

Por qué no basta `docker compose up`: en un equipo que cambia de red, `LAN_GATEWAY` y
`HOST_LAN_IP` quedan obsoletos. Los tests SSRF seguirían pasando, pero probando
direcciones que ya no existen, y el modo demo se publicaría en una IP que el equipo ya
no tiene.

## Actualizar datos

Los contenedores no descargan nada: `data/` se monta de solo lectura y lo actualiza el
anfitrión. Cada directorio tiene su `MANIFEST.json` (fecha, URL, sha256) y su
`LICENSES.md`.

| Qué | Comando | Después |
|---|---|---|
| Listas de filtros y mapa de entidades | `./scripts/update-lists.sh` | `docker compose restart worker` |
| Mapa de organizaciones del perfil comercial | `./scripts/update-companiesdb.sh` | `docker compose restart worker` |
| Base de IP (DB-IP Lite, mensual) | `./scripts/update-ipdb.sh` | `docker compose restart api` |
| Lista de CMP de IAB | `./scripts/update-cmp-list.sh` | `docker compose restart worker` |

Un scan ya hecho no cambia solo: `POST /api/scans/{id}/reanalyze` lo vuelve a analizar
con los datos nuevos, sin navegar otra vez.

**Perfil de licencias** (`LICENSE_PROFILE` en `.env`, docs/adr/019): con `comercial` no
se abren el mapa de DuckDuckGo ni la lista de IAB. Requiere haber ejecutado antes
`update-companiesdb.sh`. Tras cambiarlo: `./scripts/start.sh`. Comprobar en el log del
worker (`analyzer_resources_loaded`) qué fuentes cargó y cuáles excluyó.

## Rotar secretos

```sh
./scripts/rotate-secrets.sh
```

Genera valores nuevos para `POSTGRES_PASSWORD`, `PROXY_SCAN_SECRET` y
`EXPOSURE_PRESENTER_TOKEN`, cambia la contraseña en la base en marcha, actualiza `.env`
y recrea los contenedores. Los datos no se tocan. Al final comprueba, desde la api, que
la base acepta la contraseña nueva y **rechaza la anterior**. No imprime ningún valor.

- Interrumpe los scans en curso (el worker se reinicia) y deja sin efecto el token de
  administrador anterior.
- Deja una copia del `.env` anterior en `.env.bak-rotacion` (permisos 600, fuera de
  git). Borrarla cuando se confirme que todo funciona.
- Cuándo rotar: si un secreto apareció en una pantalla compartida, un log o un mensaje;
  antes de una demostración; al cambiar quién opera el equipo.

Si falla después del paso 2 (la base ya cambió) y antes de escribir `.env`, la api
quedará sin acceso: volver a ejecutar el script, que usa el socket local de la base y
no necesita la contraseña anterior.

## Retención y purga

El worker borra cada hora los scans **terminados** con más de `SCAN_RETENTION_DAYS`
días (30 por defecto; `0` desactiva). Con cada scan se van su captura, su análisis y
sus reportes exportados. Los scans en cola, en curso o en análisis no se tocan. Queda
en el log como `retention_purged`.

```sh
./scripts/purge.sh 7 --dry-run   # cuántos scans y reportes se borrarían
./scripts/purge.sh 7             # borra lo anterior a 7 días
./scripts/purge.sh               # usa SCAN_RETENTION_DAYS
```

Borrar un scan concreto: `DELETE FROM jobs WHERE id = '<uuid>'` desde
`docker compose exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"`; la cascada hace el
resto. "Mi exposición" no guarda nada, así que no tiene purga en disco (el grupo de la
comparación grupal de huellas vive en memoria y caduca sola).

### Borrar el historial desde la interfaz (F10)
En el inicio, cada scan tiene **Borrar este scan** y al pie de la lista está **Borrar todo
el historial**, que pide escribir `BORRAR`. Equivalen a:

```sh
curl -X DELETE http://127.0.0.1:8000/api/scans/<id>
curl -X DELETE http://127.0.0.1:8000/api/scans -H 'Content-Type: application/json' -d '{"confirm":"BORRAR"}'
curl http://127.0.0.1:8000/api/history     # cuánto hay guardado y si se puede borrar
```

Borran scans, capturas, análisis, reportes y grupos de Privacy Test, e informan cuántos y
cuánto ocupaban. Es definitivo. No tocan `backups/` (para conservar algo, respalde antes con
`./scripts/backup.sh`). En modo demo responden `403 HISTORY_DELETE_DISABLED`.

## Respaldar y restaurar

```sh
./scripts/backup.sh                                             # → backups/wpa-AAAAMMDD-HHMMSS.dump
./scripts/restore.sh backups/wpa-AAAAMMDD-HHMMSS.dump --si-reemplazar
```

- El respaldo es un `pg_dump` en formato custom. Contiene todo lo capturado de los
  sitios analizados: `backups/` está fuera de git y los archivos se crean con permisos
  600. No incluye `.env` ni `data/`.
- Restaurar **reemplaza** la base actual: detiene api y worker, restaura en una sola
  transacción y vuelve a arrancar; la api aplica al iniciar las migraciones que falten.
- `docker compose down -v` borra el volumen de la base. Respaldar antes.

## Subir de versión Playwright

Playwright trae su propio Chromium, así que subirlo cambia el navegador.

1. Cambiar la versión en **tres** sitios, que deben coincidir exactamente:
   `worker/requirements.txt`, `e2e/requirements.txt` y el tag de la imagen base en
   `worker/Dockerfile` y `e2e/Dockerfile`. Actualizar también el digest:
   `docker pull mcr.microsoft.com/playwright/python:vX.Y.Z-noble` y copiar el que
   muestra `docker image inspect --format '{{index .RepoDigests 0}}'`.
2. `./scripts/test.sh` y mirar en especial los tests que dependen de internos del
   navegador o de Playwright:

| Test | Qué delata si falla |
|---|---|
| `worker/tests/fingerprint/test_instrumentation.py` | El init script ya no envuelve alguna API, o cambió cómo se atribuye la llamada al script por la pila (ADR 007) |
| `worker/tests/fingerprint/test_base_profile.py` | El navegador vuelve a delatarse como automatizado (`HeadlessChrome`, `navigator.webdriver`) o cambió un atributo base (ADR 008) |
| `worker/tests/capture/test_capture.py` | Cambió el initiator por CDP, el `post_data`, los WebSockets o la cadena de redirecciones (ADR 003) |
| `worker/tests/privacy/test_profiles.py` | Los Client Hints por CDP o el init script de perfiles ya no se aplican (ADR 014) |
| `worker/tests/ssrf/test_ssrf.py` | El navegador encontró una salida que no pasa por el proxy |
| `worker/tests/f8/test_proxy_attribution.py` | Cambió cómo el navegador se autentica en el proxy |
| `worker/tests/f8/test_render.py` | `page.pdf` o el bloqueo de red del render |
| `e2e/tests/test_xss.py` | La CSP o el escapado dejaron de contener un payload |

3. Repetir a mano la comprobación de tráfico propio de Chromium del ADR 013: un scan de
   una página vacía no debe dejar en el log del proxy conexiones a dominios de Google.
4. Si cambió el sandbox, revisar el perfil seccomp (ADR 001).
5. `./scripts/security-scan.sh trivy` sobre las imágenes nuevas.

## Actualizar imágenes base

Las imágenes van fijadas por digest en cada `Dockerfile`. Para actualizar una:
`docker pull <imagen:tag>`, copiar el digest nuevo al `FROM`, reconstruir con
`./scripts/start.sh` y ejecutar `./scripts/test.sh` y `./scripts/security-scan.sh`. El
build añade además los parches de seguridad de la distribución publicados después del
digest (docs/adr/020).

## Modo demo y cómo apagarlo

```sh
DEMO_MODE=exposure ./scripts/demo.sh   # publica SOLO "Mi exposición" en la IP LAN (http 8088, https 8443)
./scripts/demo.sh down                 # vuelve a solo-loopback
```

- `DEMO_MODE=1` publica la interfaz completa, sin autenticación: evitarlo en redes que
  no se controlan.
- **Apagar siempre al terminar.** Comprobar con `docker compose ps frontend`: los
  puertos deben ser solo `127.0.0.1:8080`.
- `./scripts/start.sh` también deja el frontend solo en loopback.
- El guion completo de una demostración está en [GUIA-DEMOSTRACION.md](GUIA-DEMOSTRACION.md).

## Tests

```sh
./scripts/test.sh                 # api, worker (incluye SSRF), frontend y e2e
./scripts/test.sh api             # una sola suite: api | worker | ssrf | frontend | e2e | demo
```

El script pone por su cuenta lo que solo sirve para probar (`ALLOW_FIXTURES=1`,
`SCAN_RATE_LIMIT=100`) y, al terminar, devuelve el stack a los valores de `.env`. En
`.env` el límite normal es `SCAN_RATE_LIMIT=10`.

**Fallo intermitente conocido (resuelto en F9).** En F8,
`test_request_n_plus_one_is_rate_limited` falló una vez con 400 en lugar de 202. Causa:
crear un scan resuelve el host por DNS y, si el DNS no responde, la api contesta
`400 DNS_RESOLUTION_FAILED`; ese día la red del equipo tuvo cortes de DNS (el proxy
registró `ERR_DNS_FAIL` en los mismos minutos). Los tests de la api ya no dependen del
DNS externo y `test_dns_failure_is_a_400_and_does_not_consume_quota` reproduce el caso
a propósito. Con DNS estable, 20 corridas seguidas pasaron.

## Diagnóstico rápido

| Síntoma | Dónde mirar |
|---|---|
| Scan `NAVIGATION_FAILED` | `docker compose logs egress-proxy`: `ERR_DNS_FAIL` (revisar `UPSTREAM_DNS`), `ERR_ACCESS_DENIED` (destino prohibido), `407` (proxy y worker con secretos distintos: reconstruir juntos) |
| Todos los dominios sin IP en el reporte | Log del worker: `scanlog_unreadable` |
| La CMP aparece solo como número | `cmp_list_unavailable` en el log del worker, o perfil comercial |
| El PDF no termina | `report_render_failed` en el log del worker; volver a exportar |
| `429 RATE_LIMITED` | Límite de scans por IP; esperar un minuto |
| La api no arranca | `docker compose logs api`: una migración falló, o `.env` y la base tienen contraseñas distintas |
