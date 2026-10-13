#!/bin/sh
# Descarga las bases offline de IP (país y ASN) de DB-IP Lite a data/ipdb/ y
# regenera data/ipdb/MANIFEST.json (fecha, URL de origen, sha256).
#
# Se ejecuta en el HOST. DB-IP publica una edición por mes; por defecto se baja la
# del mes actual (o la que se pase: ./scripts/update-ipdb.sh 2026-10).
# Licencia: CC BY 4.0, con atribución obligatoria (data/ipdb/LICENSES.md).
# Tras actualizar: docker compose restart api
set -eu

dir="$(cd "$(dirname "$0")/.." && pwd)/data/ipdb"
mkdir -p "$dir"
edition="${1:-$(date -u +%Y-%m)}"
printf '%s' "$edition" | grep -Eq '^[0-9]{4}-[0-9]{2}$' || { echo "Edición inválida: $edition (formato AAAA-MM)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for kind in country asn; do
    url="https://download.db-ip.com/free/dbip-$kind-lite-$edition.mmdb.gz"
    echo "Descargando $url ..." >&2
    curl -fsSL --max-time 300 --retry 2 -o "$tmp/$kind.mmdb.gz" "$url"
    gunzip "$tmp/$kind.mmdb.gz"
    # Una base MMDB termina con este marcador de metadatos: no guardar una página de error.
    grep -aq 'MaxMind.com' "$tmp/$kind.mmdb" || { echo "$kind: no es una base MMDB" >&2; exit 1; }
    [ "$(wc -c < "$tmp/$kind.mmdb")" -gt 1000000 ] || { echo "$kind: archivo sospechosamente corto" >&2; exit 1; }
    sha=$(sha256sum "$tmp/$kind.mmdb" | cut -d' ' -f1)
    bytes=$(wc -c < "$tmp/$kind.mmdb" | tr -d ' ')
    printf '    {"id": "%s", "file": "dbip-%s-lite.mmdb", "url": "%s", "edition": "%s", "retrieved_at": "%s", "sha256": "%s", "bytes": %s, "license": "CC-BY-4.0", "noncommercial": false, "attribution": "IP Geolocation by DB-IP (https://db-ip.com)"}\n' \
        "$kind" "$kind" "$url" "$edition" "$now" "$sha" "$bytes" >> "$tmp/entries"
done

# Solo si las dos se descargaron y validaron se reemplaza lo anterior.
for kind in country asn; do
    mv "$tmp/$kind.mmdb" "$dir/dbip-$kind-lite.mmdb"
done
{
    printf '{\n  "generated_at": "%s",\n  "sources": [\n' "$now"
    sed '$!s/$/,/' "$tmp/entries"
    printf '  ]\n}\n'
} > "$dir/MANIFEST.json"
echo "Actualizado $dir/MANIFEST.json:"
cat "$dir/MANIFEST.json"
