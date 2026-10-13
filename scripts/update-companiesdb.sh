#!/bin/sh
# Descarga AdGuard companiesdb (basada en whotracks.me) y genera el mapa dominio → organización
# que usa el perfil de licencias COMERCIAL (LICENSE_PROFILE=comercial, docs/adr/019).
#
# Licencia: CC BY-SA 4.0 (https://github.com/AdguardTeam/companiesdb/blob/main/LICENSE).
# Se ejecuta en el HOST (necesita curl y python3). Después: docker compose restart worker.
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/data/lists/companiesdb"
base="https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist"
mkdir -p "$dir"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for file in trackers.json companies.json; do
    echo "Descargando $file ..." >&2
    curl -fsSL --max-time 120 --retry 2 -o "$tmp/$file" "$base/$file"
    [ "$(wc -c < "$tmp/$file")" -gt 100000 ] || { echo "$file: archivo sospechosamente corto" >&2; exit 1; }
done

# -I: modo aislado. Los archivos descargados son datos no confiables: solo se leen como JSON.
python3 -I - "$tmp" "$base" <<'PY'
import datetime, hashlib, json, pathlib, sys

tmp, base = pathlib.Path(sys.argv[1]), sys.argv[2]
trackers = json.loads((tmp / "trackers.json").read_text(encoding="utf-8"))
companies = json.loads((tmp / "companies.json").read_text(encoding="utf-8"))["companies"]
entity_map = {}
for domain, tracker_id in trackers["trackerDomains"].items():
    tracker = trackers["trackers"].get(tracker_id) or {}
    company = companies.get(tracker.get("companyId") or "") or {}
    name = company.get("name") or tracker.get("name")
    if isinstance(domain, str) and isinstance(name, str) and name.strip():
        entity_map[domain.lower().strip(".")] = name.strip()[:200]
if len(entity_map) < 1000:
    sys.exit(f"Solo {len(entity_map)} dominios: no parece la base completa")
body = json.dumps(dict(sorted(entity_map.items())), ensure_ascii=False, indent=0)
(tmp / "entity_map.json").write_text(body, encoding="utf-8")
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
manifest = {
    "generated_at": now,
    "sources": [{
        "id": "companiesdb", "file": "entity_map.json", "url": f"{base}/trackers.json + {base}/companies.json",
        "retrieved_at": now, "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(), "bytes": len(body.encode("utf-8")),
        "version": str(trackers.get("timeUpdated") or ""), "license": "CC-BY-SA-4.0", "noncommercial": False,
        "format": "simple-entity-map", "domains": len(entity_map),
        "upstream_sha256": {name: hashlib.sha256((tmp / name).read_bytes()).hexdigest() for name in ("trackers.json", "companies.json")},
    }],
}
(tmp / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

chmod 644 "$tmp/entity_map.json" "$tmp/MANIFEST.json"
mv "$tmp/entity_map.json" "$dir/entity_map.json"
mv "$tmp/MANIFEST.json" "$dir/MANIFEST.json"
cat "$dir/MANIFEST.json"
