"""v1.5.3: Proxy-Authorization y Proxy-Connection no se guardan ni salen por ninguna salida.

El sitio de fixtures es http: Chromium manda esas cabeceras al egress-proxy en cada request, con el usuario del scan y
PROXY_SCAN_SECRET en base64. Hasta 1.5.2 la captura las guardaba. Este test es el único con el secreto a mano (el worker
lo tiene en su entorno): recorre todas las salidas de la api de un scan real del fixture y busca la cabecera, el secreto
y el usuario del proxy, en claro y en base64.
"""

import base64
import json
import time
import urllib.error
import urllib.request

import asyncpg
import pytest

from app.browser.network_monitor import clean_headers
from app.config import settings
from tests.helpers import run_async

API = "http://api:8000"
PAGE = "http://site.fixtures.test/"


def test_capture_drops_proxy_headers_in_any_case():
    headers = [
        {"name": "Proxy-Authorization", "value": "Basic c2Nhbi0xOnNlY3JldG8="},
        {"name": "proxy-connection", "value": "keep-alive"},
        {"name": "PROXY-AUTHORIZATION", "value": "Basic eA=="},
        {"name": "Accept", "value": "*/*"},
        {"name": "Authorization", "value": "Bearer del-sitio"},
    ]
    assert clean_headers(headers) == [{"name": "Accept", "value": "*/*"}, {"name": "Authorization", "value": "Bearer del-sitio"}]


def call(path: str, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(API + path, data=data, headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def get_json(path: str) -> dict:
    status, body = call(path)
    assert status == 200, (path, status, body[:300])
    return json.loads(body)


def wait_for(predicate, what: str, timeout_s: float = 240):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(2)
    raise AssertionError(f"tiempo agotado esperando {what}")


def needles(job_id: str) -> list[str]:
    secret = settings.proxy_scan_secret.get_secret_value()
    user = f"scan-{job_id}"
    credentials = f"{user}:{secret}"
    b64 = lambda value: base64.b64encode(value.encode()).decode()  # noqa: E731
    # «scan-<uuid>:» son 42 bytes = 14 grupos de base64: el prefijo del valor de la cabecera no depende del secreto.
    return ["proxy-authorization", "proxy-connection", secret, b64(secret), b64(credentials), b64(f"{user}:")[:56], f"{user}:"]


async def stored_proxy_headers(job_id: str) -> int:
    conn = await asyncpg.connect(host=settings.postgres_host, user=settings.postgres_user,
                                 password=settings.postgres_password.get_secret_value(), database=settings.postgres_db, timeout=10)
    try:
        return await conn.fetchval(
            "SELECT count(*) FROM scan_requests WHERE job_id = $1::uuid AND "
            "(request_headers::text ILIKE '%proxy-%' OR coalesce(response_headers::text, '') ILIKE '%proxy-%')", job_id)
    finally:
        await conn.close()


@pytest.mark.needs_stack
def test_proxy_headers_and_secret_reach_no_output(fixtures_site):
    status, body = call("/api/scans", {"url": PAGE})
    assert status == 202, body[:300]
    job_id = json.loads(body)["job_id"]
    wait_for(lambda: get_json(f"/api/scans/{job_id}")["analysis_status"] in ("completed", "failed"), "el análisis")
    assert get_json(f"/api/scans/{job_id}")["analysis_status"] == "completed"

    # La captura ya no las guarda (en 1.5.2 cada request http del fixture llevaba Proxy-Authorization).
    assert run_async(stored_proxy_headers(job_id)) == 0

    outputs: dict[str, bytes] = {}
    for path in ("", "/requests?page_size=200", "/findings", "/trackers", "/domains", "/destinations", "/fingerprinting",
                 "/report", "/har", "/har?include_sensitive=true", "/compare-candidates"):
        status, body = call(f"/api/scans/{job_id}{path}")
        assert status == 200, (path, status)
        outputs[path or "/"] = body
    items = json.loads(outputs["/requests?page_size=200"])["items"]
    assert any(item["url"].startswith("http://") for item in items), "el fixture es http: las requests pasaron por el proxy en claro"
    for item in items:
        for reveal in ("false", "true"):
            path = f"/requests/{item['request_id']}?reveal={reveal}"
            status, body = call(f"/api/scans/{job_id}{path}")
            assert status == 200, (path, status)
            outputs[path] = body
    # Reportes exportados, enmascarado y con valores completos: JSON, HTML y PDF.
    for reveal in (False, True):
        status, _ = call(f"/api/scans/{job_id}/export", {"reveal": reveal})
        assert status == 202
        flag = str(reveal).lower()
        wait_for(lambda: get_json(f"/api/scans/{job_id}/export?reveal={flag}")["files"]["pdf"]["status"] in ("ready", "failed"),
                 "el PDF", timeout_s=180)
        for kind in ("json", "html", "pdf"):
            status, body = call(f"/api/scans/{job_id}/export/{kind}?reveal={flag}")
            assert status == 200, (kind, reveal, status)
            outputs[f"export/{kind}?reveal={flag}"] = body

    leaks = [(name, needle) for name, body in outputs.items() for needle in needles(job_id)
             if needle.lower() in body.decode("utf-8", "replace").lower()]
    assert leaks == [], leaks
    assert len(outputs) > 20
