#!/bin/sh
# Respaldo de la base (formato custom de pg_dump) en backups/, que git ignora.
# El archivo contiene todo lo capturado de los sitios analizados: trátalo como dato sensible.
#   ./scripts/backup.sh  →  backups/wpa-AAAAMMDD-HHMMSS.dump
# Restaurar: ./scripts/restore.sh backups/<archivo>.dump
set -eu
umask 077
cd "$(dirname "$0")/.."
mkdir -p backups
out="backups/wpa-$(date +%Y%m%d-%H%M%S).dump"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$out"
[ -s "$out" ] || { rm -f "$out"; echo "El respaldo quedó vacío" >&2; exit 1; }
docker compose exec -T db sh -c 'pg_restore --list' < "$out" >/dev/null || { echo "El respaldo no es legible por pg_restore" >&2; exit 1; }
echo "$out ($(wc -c < "$out") bytes, sha256 $(sha256sum "$out" | cut -d' ' -f1))"
