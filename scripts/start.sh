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

detect_upstream_dns() {
    # Resolver(es) DNS reales del equipo, nunca el stub local 127.0.0.53. Primero systemd-resolved
    # y luego /etc/resolv.conf; devuelve las IPv4 únicas separadas por comas (vacío si no encuentra).
    {
        if command -v resolvectl >/dev/null 2>&1; then
            resolvectl status 2>/dev/null | sed -n 's/.*Current DNS Server: *//p; s/.*DNS Servers: *//p'
        fi
        sed -n 's/^nameserver[[:space:]]*//p' /etc/resolv.conf 2>/dev/null
    } | tr ' ' '\n' \
      | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
      | grep -v '^127\.' \
      | awk '!seen[$0]++' \
      | paste -sd, -
}

# La primera vez genera .env desde .env.example: secretos con openssl y el DNS real del equipo.
if [ ! -f .env ]; then
    [ -f .env.example ] || { echo "Falta .env.example: no puedo generar .env." >&2; exit 1; }
    command -v openssl >/dev/null 2>&1 || { echo "Falta 'openssl' para generar los secretos de .env." >&2; exit 1; }
    echo "No existe .env: generándolo desde .env.example..." >&2
    cp .env.example .env
    chmod 600 .env

    set_env() {
        # set_env CLAVE VALOR: reescribe CLAVE=... en .env (la clave ya existe en .env.example).
        if grep -q "^$1=" .env; then
            sed -i "s|^$1=.*|$1=$2|" .env
        else
            printf '%s=%s\n' "$1" "$2" >> .env
        fi
    }

    set_env POSTGRES_PASSWORD "$(openssl rand -hex 24)"
    set_env PROXY_SCAN_SECRET "$(openssl rand -hex 24)"
    set_env EXPOSURE_PRESENTER_TOKEN "$(openssl rand -hex 16)"

    dns=$(detect_upstream_dns)
    if [ -n "$dns" ]; then
        set_env UPSTREAM_DNS "$dns"
        dns_note="UPSTREAM_DNS=$dns (detectado)"
    else
        dns_note="UPSTREAM_DNS: no detectado, queda en 'CAMBIAR' -> edítelo a mano ('resolvectl status', nunca 127.0.0.53)"
    fi

    echo "  Generado en .env:" >&2
    echo "    POSTGRES_PASSWORD, PROXY_SCAN_SECRET, EXPOSURE_PRESENTER_TOKEN (openssl rand)" >&2
    echo "    $dns_note" >&2
    echo "    LAN_GATEWAY y HOST_LAN_IP: los detecta refresh-lan-env a continuación." >&2
fi
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
