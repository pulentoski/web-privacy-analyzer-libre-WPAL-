#!/bin/sh
# Ejecuta todas las suites. Los valores que solo sirven para probar se ponen AQUÍ, no en .env:
#   - ALLOW_FIXTURES=1   el proxy, la api y el worker aceptan el sitio de fixtures;
#   - SCAN_RATE_LIMIT=100 las suites crean muchos scans seguidos (en .env el límite es 10).
# Al terminar (también si algo falla) el stack vuelve a los valores de .env.
#
#   ./scripts/test.sh            # api, worker (incluye SSRF), frontend y e2e
#   ./scripts/test.sh api e2e    # solo algunas: api | worker | ssrf | frontend | e2e | demo
set -eu
cd "$(dirname "$0")/.."

suites="${*:-api worker frontend e2e}"
restore() {
    # Las pruebas no dejan nada en el historial (v1.4.2): fuera los scans de fixtures, .example y HAR sintéticos.
    ./scripts/purge-test-scans.sh >&2 || echo "No se pudieron borrar los scans de prueba: ejecutar ./scripts/purge-test-scans.sh" >&2
    echo "== Restaurando el stack con los valores de .env ==" >&2
    START_BUILD=0 ./scripts/start.sh --profile test >/dev/null
}
trap restore EXIT

# BLOCKING_MIN_REQUESTS=2: las páginas de fixtures son pequeñas a propósito; sin este override la
# alerta antibot (v1.2.1) las marcaría como "pocas requests" y las sacaría del ranking del Panel.
export ALLOW_FIXTURES=1 SCAN_RATE_LIMIT=100 BLOCKING_MIN_REQUESTS=2
./scripts/start.sh --profile test >/dev/null

failed=""
run() {
    name="$1"; shift
    echo "== $name ==" >&2
    if "$@"; then echo "== $name: OK ==" >&2; else echo "== $name: FALLÓ ==" >&2; failed="$failed $name"; fi
}
for suite in $suites; do
    case "$suite" in
        api) run api docker compose exec -T api pytest -q ;;
        worker) run worker docker compose exec -T worker pytest -q -p no:cacheprovider ;;
        ssrf) run ssrf docker compose exec -T worker pytest -q -p no:cacheprovider tests/ssrf ;;
        # data/ va montado (solo lectura): el test de textos revisa también las frases técnicas y el glosario.
        frontend) run frontend docker run --rm -e WPA_DATA_REQUIRED=1 -v "$PWD/frontend":/src -v "$PWD/data":/data:ro -w /src node:22-alpine sh -c "npm ci --ignore-scripts >/dev/null 2>&1 && npm test" ;;
        e2e) run e2e docker compose exec -T e2e pytest -q ;;
        demo)
            DEMO_MODE=exposure ./scripts/demo.sh >/dev/null 2>&1
            run demo docker compose exec -T e2e pytest demo_tests -q
            ./scripts/demo.sh down >/dev/null 2>&1
            ;;
        *) echo "Suite desconocida: $suite" >&2; exit 2 ;;
    esac
done

if [ -n "$failed" ]; then
    echo "Suites con fallos:$failed" >&2
    exit 1
fi
echo "Todas las suites en verde: $suites"
