#!/bin/sh
# Mide la pérdida de cobertura del perfil de licencias comercial frente al no comercial:
# cuántos dominios de terceros quedan sin organización identificada. Usa los dominios de las
# muestras (docs/samples/*.json) y los del sitio de fixtures. No hace ningún scan.
set -eu
cd "$(dirname "$0")/.."
python3 -I - <<'PY' | docker compose exec -T worker python -m app.analyzer.license_coverage
import glob, json, pathlib
sets = {}
for path in sorted(glob.glob("docs/samples/*.json")):
    report = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    domains = [d["domain"] for d in (report.get("destinations") or {}).get("domains", []) if d.get("third_party")]
    sets[f"muestra {pathlib.Path(path).stem}"] = domains
manifest = json.loads(pathlib.Path("fixtures/static/manifest.json").read_text(encoding="utf-8"))
first = manifest["first_party_host"]
sets["fixtures"] = sorted({r["host"] for r in manifest["requests"] if r.get("host") and r["host"] != first})
print(json.dumps(sets))
PY
