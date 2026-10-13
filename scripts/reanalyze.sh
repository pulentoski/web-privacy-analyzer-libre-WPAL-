#!/bin/sh
# Reanaliza los scans guardados con el analizador actual, SIN volver a navegar: el worker lee
# la captura ya guardada y reescribe su análisis (lo mismo que POST /api/scans/{id}/reanalyze,
# para todos). Útil tras cambiar listas, pesos o reglas (p. ej. data/account_ids.yaml).
#
#   ./scripts/reanalyze.sh            # los analizados con una versión anterior del analizador
#   ./scripts/reanalyze.sh --all      # todos los que tienen captura
#   ./scripts/reanalyze.sh --dry-run  # solo cuenta
set -eu
cd "$(dirname "$0")/.."

mode="outdated"; dry=0
for arg in "$@"; do
    case "$arg" in
        --all) mode="all" ;;
        --dry-run) dry=1 ;;
        *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
    esac
done

sql() { docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atc "$1"' sh "$1"; }

current=$(docker compose exec -T worker python -c 'from app.analyzer import ANALYZER_VERSION; print(ANALYZER_VERSION)')
scope="j.status IN ('completed', 'failed') AND j.analysis_status IS DISTINCT FROM 'running' AND j.analysis_status IS DISTINCT FROM 'queued' AND EXISTS (SELECT 1 FROM scan_requests r WHERE r.job_id = j.id)"
if [ "$mode" = "outdated" ]; then
    scope="$scope AND NOT EXISTS (SELECT 1 FROM site_analysis s WHERE s.job_id = j.id AND s.analyzer_version = '$current')"
fi

pending=$(sql "SELECT count(*) FROM jobs j WHERE $scope")
echo "Analizador actual: $current. Scans por reanalizar: $pending."
[ "$dry" = "0" ] || exit 0
[ "$pending" != "0" ] || exit 0

sql "UPDATE jobs j SET analysis_status = 'queued', updated_at = now() WHERE $scope" >/dev/null
waited=0
while :; do
    left=$(sql "SELECT count(*) FROM jobs WHERE analysis_status IN ('queued', 'running')")
    [ "$left" != "0" ] || break
    [ "$waited" -lt "${REANALYZE_TIMEOUT_S:-1800}" ] || { echo "Tiempo agotado: quedan $left análisis en cola." >&2; exit 1; }
    sleep 3; waited=$((waited + 3))
done
failed=$(sql "SELECT count(*) FROM jobs WHERE analysis_status = 'failed'")
done_now=$(sql "SELECT count(*) FROM site_analysis WHERE analyzer_version = '$current'")
echo "Listo en ${waited}s. Scans con análisis $current: $done_now. Análisis fallidos: $failed."
