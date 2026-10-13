#!/bin/sh
# Rota POSTGRES_PASSWORD, PROXY_SCAN_SECRET y EXPOSURE_PRESENTER_TOKEN sin perder datos.
#
# Qué hace, en este orden:
#   1. genera tres valores nuevos (openssl rand);
#   2. cambia la contraseña del rol en la base EN MARCHA (ALTER ROLE por el socket local);
#   3. solo si eso funcionó, escribe los tres valores en .env (copia previa en .env.bak-rotacion);
#   4. recrea los contenedores para que tomen los valores nuevos y espera healthy;
#   5. comprueba que la base acepta la contraseña nueva y que la api responde.
# Los datos viven en el volumen pgdata, que no se toca. Ningún valor se imprime.
#
# Efectos: los scans en curso se interrumpen (el worker se reinicia) y el token de
# presentador anterior deja de servir.
set -eu
umask 077
cd "$(dirname "$0")/.."

env_file=.env
[ -f "$env_file" ] || { echo "No existe $env_file" >&2; exit 1; }
command -v openssl >/dev/null || { echo "Falta openssl" >&2; exit 1; }

get() { sed -n "s/^$1=//p" "$env_file" | head -n 1; }
pg_user=$(get POSTGRES_USER)
pg_db=$(get POSTGRES_DB)
printf '%s' "$pg_user" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$' || { echo "POSTGRES_USER no es un identificador simple" >&2; exit 1; }

new_pg=$(openssl rand -hex 24)
new_proxy=$(openssl rand -hex 24)
new_token=$(openssl rand -hex 16)
for value in "$new_pg" "$new_proxy" "$new_token"; do
    printf '%s' "$value" | grep -Eq '^[0-9a-f]{32,}$' || { echo "openssl no devolvió un valor válido" >&2; exit 1; }
done

profile=""
if docker compose --profile test ps --services 2>/dev/null | grep -qx e2e; then
    profile="--profile test"
fi

echo "1/4 Base de datos en marcha..." >&2
docker compose up -d db >/dev/null
waited=0
until [ "$(docker compose ps db --format '{{.Health}}')" = "healthy" ]; do
    [ "$waited" -lt 240 ] || { echo "La base no llegó a healthy" >&2; exit 1; }
    sleep 3; waited=$((waited + 3))
done

echo "2/4 Cambiando la contraseña del rol en la base..." >&2
# Por stdin: el valor no aparece en la lista de procesos ni en el historial.
printf "ALTER ROLE \"%s\" PASSWORD '%s';\n" "$pg_user" "$new_pg" \
    | docker compose exec -T db psql -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$pg_db" >/dev/null

echo "3/4 Actualizando .env (copia anterior en .env.bak-rotacion)..." >&2
cp -p "$env_file" .env.bak-rotacion
chmod 600 .env.bak-rotacion "$env_file"
set_var() {
    if grep -q "^$1=" "$env_file"; then
        sed -i "s/^$1=.*/$1=$2/" "$env_file"
    else
        printf '%s=%s\n' "$1" "$2" >> "$env_file"
    fi
}
set_var POSTGRES_PASSWORD "$new_pg"
set_var PROXY_SCAN_SECRET "$new_proxy"
set_var EXPOSURE_PRESENTER_TOKEN "$new_token"

echo "4/4 Recreando contenedores con los valores nuevos..." >&2
# shellcheck disable=SC2086
START_BUILD=0 ./scripts/start.sh $profile >/dev/null

# Verificación desde la api, por la red interna: ahí la base exige contraseña (scram). Desde
# dentro del contenedor de la base no serviría: las conexiones locales son de confianza.
# La contraseña a probar va por stdin; nunca en la línea de comandos.
try_password() {
    docker compose exec -T api python -c '
import asyncio, os, sys
import asyncpg

async def main():
    conn = await asyncpg.connect(host=os.environ.get("POSTGRES_HOST", "db"), user=os.environ["POSTGRES_USER"],
                                 password=sys.stdin.readline().strip(), database=os.environ["POSTGRES_DB"], timeout=10)
    await conn.close()

try:
    asyncio.run(main())
except asyncpg.InvalidPasswordError:
    sys.exit(3)
'
}
sed -n 's/^POSTGRES_PASSWORD=//p' "$env_file" | head -n 1 | try_password \
    || { echo "La base NO acepta la contraseña nueva. Restaurar con .env.bak-rotacion y revisar." >&2; exit 1; }
status=0
sed -n 's/^POSTGRES_PASSWORD=//p' .env.bak-rotacion | head -n 1 | try_password 2>/dev/null || status=$?
[ "$status" = "3" ] || { echo "ATENCIÓN: la base no rechazó la contraseña anterior (código $status)." >&2; exit 1; }
api_port=$(get API_PORT)
curl -fsS "http://127.0.0.1:${api_port:-8000}/health" >/dev/null || { echo "La api no responde tras la rotación" >&2; exit 1; }

echo "Rotados: POSTGRES_PASSWORD, PROXY_SCAN_SECRET, EXPOSURE_PRESENTER_TOKEN."
echo "La base rechaza la contraseña anterior y acepta la nueva; la api responde."
echo "Cuando confirmes que todo funciona, borra la copia: rm .env.bak-rotacion"
