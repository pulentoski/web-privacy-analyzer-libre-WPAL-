#!/bin/sh
# Descarga las listas de filtros y el mapa dominio→entidad a data/lists/ y
# regenera data/lists/MANIFEST.json (fecha, URL de origen, sha256).
#
# Se ejecuta en el HOST: el worker no tiene salida directa a internet y solo lee
# data/ (montado de solo lectura). Tras actualizar: docker compose restart worker
# y, si se quiere, POST /api/scans/{id}/reanalyze sobre scans existentes.
#
# Licencias: data/lists/LICENSES.md (Tracker Radar es NO COMERCIAL, ver ADR 005).
set -eu

dir="$(cd "$(dirname "$0")/.." && pwd)/data/lists"
mkdir -p "$dir"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# id | archivo | url | licencia | no_comercial | tipo
sources='easylist|easylist.txt|https://easylist.to/easylist/easylist.txt|GPL-3.0-or-later OR CC-BY-SA-3.0|false|adblock
easyprivacy|easyprivacy.txt|https://easylist.to/easylist/easyprivacy.txt|GPL-3.0-or-later OR CC-BY-SA-3.0|false|adblock
entity_map|entity_map.json|https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated/entity_map.json|CC-BY-NC-SA-4.0|true|ddg-entity-map'

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
entries=""
echo "$sources" | while IFS='|' read -r id file url license nc kind; do
    echo "Descargando $id ..." >&2
    curl -fsSL --max-time 120 --retry 2 -o "$tmp/$file" "$url"
    # Validación mínima: no guardar una página de error como si fuera la lista.
    case "$kind" in
        adblock)
            head -n 1 "$tmp/$file" | grep -q '^\[Adblock' || { echo "$id: no parece una lista Adblock" >&2; exit 1; }
            [ "$(wc -l < "$tmp/$file")" -gt 1000 ] || { echo "$id: lista sospechosamente corta" >&2; exit 1; }
            version=$(sed -n 's/^! Version: *//p' "$tmp/$file" | head -n 1)
            ;;
        ddg-entity-map)
            head -c 1 "$tmp/$file" | grep -q '{' || { echo "$id: no es JSON" >&2; exit 1; }
            [ "$(wc -c < "$tmp/$file")" -gt 100000 ] || { echo "$id: archivo sospechosamente corto" >&2; exit 1; }
            version=""
            ;;
    esac
    sha=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
    bytes=$(wc -c < "$tmp/$file" | tr -d ' ')
    printf '    {"id": "%s", "file": "%s", "url": "%s", "retrieved_at": "%s", "sha256": "%s", "bytes": %s, "version": "%s", "license": "%s", "noncommercial": %s, "format": "%s"}\n' \
        "$id" "$file" "$url" "$now" "$sha" "$bytes" "$version" "$license" "$nc" "$kind" >> "$tmp/entries"
done

# Solo si TODO se descargó y validó se reemplaza lo anterior.
echo "$sources" | while IFS='|' read -r id file url license nc kind; do
    mv "$tmp/$file" "$dir/$file"
done
{
    printf '{\n  "generated_at": "%s",\n  "sources": [\n' "$now"
    sed '$!s/$/,/' "$tmp/entries"
    printf '  ]\n}\n'
} > "$dir/MANIFEST.json"

echo "Actualizado $dir/MANIFEST.json:"
cat "$dir/MANIFEST.json"
