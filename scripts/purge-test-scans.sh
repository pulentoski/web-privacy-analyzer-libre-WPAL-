#!/bin/sh
# Borra del historial los scans que NO son de sitios reales: el sitio de fixtures (*.fixtures.test),
# nombres reservados para pruebas (.test, .example, .invalid, .localhost, example.com/net/org) y los
# HAR sintéticos de las suites. Es el mismo criterio que `is_test_scan` de la api. Con ellos se van
# (en cascada) su captura, análisis, reportes, grupos y comparaciones de visitas. No toca scans de sitios reales ni backups/.
#
#   ./scripts/purge-test-scans.sh            # borra
#   ./scripts/purge-test-scans.sh --dry-run  # solo cuenta
# Lo ejecuta scripts/test.sh al terminar, para que las pruebas no dejen nada en el historial.
set -eu
cd "$(dirname "$0")/.."

host="lower(substring(url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#@]+)'))"
test_host="($host ~ '(^|\\.)(test|example|invalid|localhost)\$' OR $host ~ '(^|\\.)example\\.(com|net|org)\$')"
sql() { docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atc "$1"' sh "$1"; }

jobs=$(sql "SELECT count(*) FROM jobs WHERE $test_host")
groups=$(sql "SELECT count(*) FROM test_groups WHERE $test_host")
comparisons=$(sql "SELECT count(*) FROM visit_comparisons WHERE $test_host")
echo "Scans de prueba: $jobs. Grupos de prueba: $groups. Comparaciones de visitas de prueba: $comparisons."
[ "${1:-}" != "--dry-run" ] || exit 0
sql "DELETE FROM report_files WHERE (subject_type = 'scan' AND subject_id IN (SELECT id FROM jobs WHERE $test_host)) OR (subject_type = 'group' AND subject_id IN (SELECT id FROM test_groups WHERE $test_host))" >/dev/null
sql "DELETE FROM jobs WHERE $test_host" >/dev/null
sql "DELETE FROM test_groups WHERE $test_host" >/dev/null
# v1.5.2: también las que quedaron sin visitas (no las arrastra el borrado de sus jobs).
sql "DELETE FROM visit_comparisons WHERE $test_host" >/dev/null
echo "Borrados. Quedan $(sql 'SELECT count(*) FROM jobs') scans en el historial."
