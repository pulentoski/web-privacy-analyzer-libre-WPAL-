#!/bin/sh
# Purga manual de scans terminados y de sus reportes (la automática usa SCAN_RETENTION_DAYS).
#   ./scripts/purge.sh              # lo anterior a SCAN_RETENTION_DAYS (30 por defecto)
#   ./scripts/purge.sh 7            # lo anterior a 7 días
#   ./scripts/purge.sh 7 --dry-run  # solo cuenta, no borra
set -eu
cd "$(dirname "$0")/.."
days="${1:-}"
[ -z "$days" ] || shift
if [ -n "$days" ]; then
    printf '%s' "$days" | grep -Eq '^[1-9][0-9]*$' || { echo "Días debe ser un entero >= 1" >&2; exit 1; }
    docker compose exec -T worker python -m app.retention --days "$days" "$@"
else
    docker compose exec -T worker python -m app.retention "$@"
fi
