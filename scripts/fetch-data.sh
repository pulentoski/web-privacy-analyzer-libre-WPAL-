#!/bin/sh
# Descarga, si faltan, los datos de terceros que NO se incluyen en el repositorio por sus
# licencias (ver NOTICE y data/*/LICENSES.md): listas de filtros EasyList/EasyPrivacy y mapa de
# entidades de DuckDuckGo Tracker Radar (data/lists), base de IP offline DB-IP Lite (data/ipdb) y
# lista oficial de CMP de IAB Europe (data/iab). Es lo que el perfil por defecto (no_comercial)
# necesita para clasificar. Se ejecuta en el HOST (necesita internet); el worker nunca sale solo.
#
#   ./scripts/fetch-data.sh           # descarga solo lo que falte
#   ./scripts/fetch-data.sh --force   # vuelve a descargar todo
#
# start.sh lo llama automáticamente. Para el perfil comercial, además: ./scripts/update-companiesdb.sh
set -eu
cd "$(dirname "$0")/.."

force=0
[ "${1:-}" = "--force" ] && force=1
missing() { [ "$force" = "1" ] || [ ! -s "$1" ]; }

if missing data/lists/easylist.txt || missing data/lists/easyprivacy.txt || missing data/lists/entity_map.json; then
    echo "== Listas de filtros y mapa de entidades (DDG Tracker Radar) ==" >&2
    ./scripts/update-lists.sh
fi

if missing data/ipdb/dbip-country-lite.mmdb || missing data/ipdb/dbip-asn-lite.mmdb; then
    echo "== Base de IP offline (DB-IP Lite) ==" >&2
    # DB-IP publica una edición por mes; si la del mes en curso aún no está, se usa la anterior.
    ./scripts/update-ipdb.sh || ./scripts/update-ipdb.sh "$(date -u -d 'last month' +%Y-%m 2>/dev/null || date -u +%Y-%m)"
fi

if missing data/iab/cmp-list.json; then
    echo "== Lista de CMP (IAB TCF) ==" >&2
    ./scripts/update-cmp-list.sh
fi

echo "Datos de terceros listos en data/." >&2
