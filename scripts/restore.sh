#!/bin/sh
# Restaura un respaldo de scripts/backup.sh. REEMPLAZA el contenido actual de la base.
#   ./scripts/restore.sh backups/wpa-AAAAMMDD-HHMMSS.dump --si-reemplazar
set -eu
cd "$(dirname "$0")/.."
file="${1:-}"
[ -f "$file" ] || { echo "Uso: $0 <archivo.dump> --si-reemplazar" >&2; exit 1; }
[ "${2:-}" = "--si-reemplazar" ] || { echo "Esto reemplaza la base actual. Repetir con --si-reemplazar para confirmar." >&2; exit 1; }

docker compose up -d db >/dev/null
# Nadie debe escribir mientras se restaura.
docker compose stop api worker >/dev/null
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --single-transaction' < "$file"
START_BUILD=0 ./scripts/start.sh >/dev/null
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT '"'"'scans: '"'"' || count(*) FROM jobs"'
echo "Restaurado desde $file. La api aplicó las migraciones pendientes al arrancar."
