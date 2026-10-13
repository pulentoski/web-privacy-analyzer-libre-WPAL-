#!/bin/sh
# Forma normal de arrancar: detecta la red actual, levanta el stack y espera a que todo
# esté healthy. Úsalo siempre en vez de `docker compose up` a secas: en un equipo que cambia
# de red, LAN_GATEWAY y HOST_LAN_IP de .env quedan obsoletos (los usan los tests SSRF y el
# modo demo).
#
#   ./scripts/start.sh                  # stack normal
#   ./scripts/start.sh --profile test   # con fixtures, e2e y control de XSS (para los tests)
#   START_BUILD=0 ./scripts/start.sh    # sin reconstruir imágenes
#   START_TIMEOUT_S=600 ./scripts/start.sh
set -eu
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "Falta .env: copiar .env.example y completar (ver README, Instalación)." >&2; exit 1; }
./scripts/refresh-lan-env.sh
# Datos de terceros (listas, base de IP, CMP): no se versionan por sus licencias; se bajan si faltan.
./scripts/fetch-data.sh

build="--build"
[ "${START_BUILD:-1}" = "1" ] || build=""
# Los argumentos (p. ej. --profile test) son opciones globales de compose.
# shellcheck disable=SC2086
docker compose "$@" up -d $build

timeout="${START_TIMEOUT_S:-420}"
waited=0
echo "Esperando a que todos los servicios estén healthy (máx. ${timeout}s)..." >&2
while :; do
    status=$(docker compose "$@" ps -a --format '{{.Service}}={{.State}}/{{.Health}}')
    pending=$(printf '%s\n' "$status" | grep -v '=running/healthy$' || :)
    if [ -n "$status" ] && [ -z "$pending" ]; then
        break
    fi
    if [ "$waited" -ge "$timeout" ]; then
        echo "Tiempo agotado. Servicios que no llegaron a healthy:" >&2
        printf '%s\n' "$pending" >&2
        echo "Revisar con: docker compose logs --tail=100 <servicio>" >&2
        exit 1
    fi
    sleep 3
    waited=$((waited + 3))
done

docker compose "$@" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'
port=$(sed -n 's/^FRONTEND_PORT=//p' .env | head -n 1)
api_port=$(sed -n 's/^API_PORT=//p' .env | head -n 1)
echo "Listo en ${waited}s. Interfaz: http://127.0.0.1:${port:-8080}   API: http://127.0.0.1:${api_port:-8000}/health   OpenAPI: http://127.0.0.1:${api_port:-8000}/docs"
