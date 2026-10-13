#!/bin/sh
# Descarga la lista oficial de plataformas de consentimiento (CMP) registradas en el TCF de
# IAB Europe y la guarda en data/iab/ con fecha, URL y sha256 (data/iab/MANIFEST.json).
# Se ejecuta en el HOST. Sirve solo para traducir cmpId -> nombre. Ver data/iab/LICENSES.md.
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/data/iab"
mkdir -p "$dir"
url="https://cmplist.consensu.org/v2/cmp-list.json"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL --max-time 60 --retry 2 -o "$tmp" "$url"
grep -q '"cmps"' "$tmp" || { echo "No parece la lista de CMP" >&2; exit 1; }
[ "$(wc -c < "$tmp")" -gt 5000 ] || { echo "Lista sospechosamente corta" >&2; exit 1; }
# mktemp crea el archivo 0600 y los contenedores lo leen con otro usuario.
chmod 644 "$tmp"
mv "$tmp" "$dir/cmp-list.json"
trap - EXIT
sha=$(sha256sum "$dir/cmp-list.json" | cut -d' ' -f1)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
updated=$(sed -n 's/.*"lastUpdated" *: *"\([^"]*\)".*/\1/p' "$dir/cmp-list.json" | head -n 1)
printf '{\n  "generated_at": "%s",\n  "sources": [\n    {"id": "iab_cmp_list", "file": "cmp-list.json", "url": "%s", "retrieved_at": "%s", "sha256": "%s", "version": "%s", "license": "sin licencia explícita", "noncommercial": false}\n  ]\n}\n' "$now" "$url" "$now" "$sha" "$updated" > "$dir/MANIFEST.json"
cat "$dir/MANIFEST.json"
