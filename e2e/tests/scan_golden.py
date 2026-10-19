"""Huella normalizada de un scan normal (v1.5.2): lo que no depende del momento de la medición.

La referencia (golden/scan_v151.json) se generó con el código de la v1.5.1 antes de añadir la comparación de visitas.
Un scan normal del mismo fixture debe dar la misma huella: la comparación no cambia los scans normales.

Regenerar (solo si cambia a propósito el resultado de un scan normal):
    API=http://127.0.0.1:8000 python -m tests.scan_golden --write
"""

import json
import os
import pathlib
import re
import sys
import time
import urllib.request

API = os.environ.get("API", os.environ.get("BASE_URL", "http://frontend:8080"))
GOLDEN = pathlib.Path(__file__).parent / "golden" / "scan_v151.json"
PAGES = ("http://site.fixtures.test/", "http://site.fixtures.test/fp/article?ref=campaign42")


def call(path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(API + path, data=data, headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def wait_analyzed(job_id: str, timeout_s: float = 180) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        scan = call(f"/api/scans/{job_id}")
        if scan["status"] == "failed" or (scan["status"] == "completed" and scan["analysis_status"] in ("completed", "failed")):
            return scan
        time.sleep(1)
    raise AssertionError(f"el scan {job_id} no terminó")


VOLATILE_KEYS = {"evidence_ref", "evidence_refs", "request_id", "request_ids", "id", "job_id", "first_seen", "timestamp"}
# Marcas de tiempo en milisegundos que el fixture pone en sus URLs (ts=...).
EPOCH_MS = re.compile(r"(?<![0-9])1[0-9]{12}(?![0-9])")
# Cuadros de animación que cuenta la página de fingerprinting en un tiempo fijo: depende de la carga de la máquina.
FRAMES = re.compile(r"frames=[0-9]+")
# Si varias reglas de una lista coinciden, el motor informa una de ellas (docs/adr/039): el ejemplo puede variar.
RULE_EXAMPLE = re.compile(r"p\. ej\. «[^»]*»")


def scrub(value):
    """Quita lo que cambia en cada medición: ids de filas y marcas de tiempo."""
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items() if key not in VOLATILE_KEYS}
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        return RULE_EXAMPLE.sub("p. ej. «<regla>»", FRAMES.sub("frames=<n>", EPOCH_MS.sub("<ts>", value)))
    return value


def _sorted(items):
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))


def fingerprint(job_id: str) -> dict:
    scan = wait_analyzed(job_id)
    result = scan["result"] or {}
    capture = result.get("capture") or {}
    measurement = result.get("measurement") or {}
    report = call(f"/api/scans/{job_id}/report")
    requests = call(f"/api/scans/{job_id}/requests?page_size=200")["items"]
    return scrub({
        "status": scan["status"],
        "http_status": result.get("http_status"),
        "title": result.get("title"),
        "final_url": result.get("final_url"),
        "capture": {key: capture.get(key) for key in ("total_requests", "cookies", "storage_items", "end_reason", "truncated", "websockets", "first_party_domains")},
        "browser_mode": measurement.get("browser_mode"),
        "stages": [(stage.get("name"), stage.get("completed"), stage.get("reason")) for stage in (measurement.get("visit_protocol") or {}).get("stages", [])],
        "summary": scan.get("summary"),
        "analysis": {key: (scan.get("analysis") or {}).get(key) for key in ("site_exposure_score", "band", "trackers", "partial")},
        "findings": _sorted([(item["kind"], item["type"], item["level"], item["claim"]) for item in call(f"/api/scans/{job_id}/findings")["items"]]),
        "domains": _sorted(call(f"/api/scans/{job_id}/domains")["domains"]),
        "trackers": _sorted(call(f"/api/scans/{job_id}/trackers").get("entities", [])),
        "requests": _sorted([
            (item["method"], item["url"], item["resource_type"], item.get("status"), item["party"], item["score"], item["category"], item["mechanism"], item["entity"])
            for item in requests
        ]),
        "report_cookies": _sorted([(c.get("name"), c.get("domain"), c.get("path"), c.get("http_only"), c.get("secure")) for c in report.get("cookies", [])]),
    })


def scan_fingerprints() -> dict:
    out = {}
    for url in PAGES:
        job_id = call("/api/scans", {"url": url})["job_id"]
        out[url] = fingerprint(job_id)
    # Se reordena después de quitar lo volátil, y tuplas → listas, como en el archivo.
    return json.loads(json.dumps(normalize(out)))


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return _sorted([normalize(item) for item in value])
    return value  # tuplas → listas, como en el archivo


if __name__ == "__main__":
    data = scan_fingerprints()
    if "--write" in sys.argv:
        GOLDEN.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        json.dump(data, sys.stdout, indent=1, sort_keys=True, ensure_ascii=False)
