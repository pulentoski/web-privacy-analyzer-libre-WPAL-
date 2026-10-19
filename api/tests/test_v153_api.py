"""v1.5.3: Proxy-Authorization y Proxy-Connection (cabeceras del navegador con el egress-proxy) no salen por la api.

La prueba con el sitio de fixtures y PROXY_SCAN_SECRET está en worker/tests/v153 (el worker tiene el secreto); aquí, con
filas sembradas: el filtro, el detalle de request, el HAR exportado e importado y la migración 0017.
"""

import importlib.util
import json
import pathlib
import uuid

import pytest
from sqlalchemy import delete, text

from app import har_import
from app.db import SessionLocal
from app.models import HarImport, Job
from app.proxy_headers import is_proxy_header, without_proxy_headers
from tests import har_fixture
from tests.factories import _request

# El valor es base64 de «scan-<uuid>:<secreto>» de mentira: lo que guardaba la captura hasta 1.5.2.
PROXY_VALUE = "Basic c2Nhbi0wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDA6c2VjcmV0by1kZS1wcnVlYmE="
HEADERS = [
    {"name": "Accept", "value": "*/*"},
    {"name": "Proxy-Authorization", "value": PROXY_VALUE},
    {"name": "Proxy-Connection", "value": "keep-alive"},
    {"name": "Authorization", "value": "Bearer del-sitio"},
]
MIGRATION = pathlib.Path(__file__).parent.parent / "migrations" / "versions" / "0017_strip_proxy_headers.py"


def leaked(body) -> bool:
    raw = json.dumps(body) if not isinstance(body, (str, bytes)) else body.decode() if isinstance(body, bytes) else body
    return "proxy-authorization" in raw.lower() or "proxy-connection" in raw.lower() or PROXY_VALUE in raw


def test_filter_is_case_insensitive_and_keeps_the_rest_in_order():
    assert is_proxy_header("PROXY-AUTHORIZATION") and is_proxy_header(" proxy-connection ") and not is_proxy_header("authorization")
    assert without_proxy_headers([*HEADERS, {"name": "pRoXy-AuThOrIzAtIoN", "value": "x"}]) == [HEADERS[0], HEADERS[3]]
    assert without_proxy_headers(None) is None


@pytest.fixture(scope="module")
def proxy_scan(client):
    """Un scan guardado como lo dejaba 1.5.2: la request http lleva Proxy-Authorization y Proxy-Connection."""
    job_id = uuid.uuid4()
    ids = {}

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="completed", analysis_status="completed",
                            result={"final_url": "http://site.example/", "http_status": 200, "title": "T", "capture": {"truncated": False}}))
            await session.flush()
            request = _request(job_id, 0, resource_type="document", is_navigation=True, request_headers=list(HEADERS),
                               response_headers=[{"name": "content-type", "value": "text/html"}, {"name": "Proxy-Connection", "value": "close"}])
            session.add(request)
            await session.flush()
            ids[0] = request.id
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id), ids
    client.portal.call(cleanup)


@pytest.mark.parametrize("reveal", ["false", "true"])
def test_request_detail_never_shows_proxy_headers(client, proxy_scan, reveal):
    job_id, ids = proxy_scan
    body = client.get(f"/api/scans/{job_id}/requests/{ids[0]}?reveal={reveal}").json()
    assert not leaked(body)
    assert [header["name"] for header in body["request_headers"]] == ["Accept", "Authorization"]
    assert [header["name"] for header in body["response_headers"]] == ["content-type"]


@pytest.mark.parametrize("sensitive", ["false", "true"])
def test_har_export_never_includes_proxy_headers(client, proxy_scan, sensitive):
    job_id, _ = proxy_scan
    response = client.get(f"/api/scans/{job_id}/har?include_sensitive={sensitive}")
    assert response.status_code == 200 and not leaked(response.content)
    names = [header["name"] for header in response.json()["log"]["entries"][0]["request"]["headers"]]
    # Authorization es del sitio: sale solo con include_sensitive. Las del proxy, nunca.
    assert names == (["Accept", "Authorization"] if sensitive == "true" else ["Accept"])


def test_har_import_does_not_keep_proxy_headers():
    document = har_fixture.build()
    document["log"]["entries"][0]["request"]["headers"] += [dict(header) for header in HEADERS[1:3]]
    imported = har_import.build_import(json.dumps(document).encode(), "page:0", "con-proxy.har")
    assert not leaked(imported["entries"])
    # Proxy-Authorization sigue contando como credencial descartada en el aviso del import.
    assert har_import.sensitive_counts([{"request": {"headers": HEADERS}, "response": {}}])["authorization"] == 2


def test_migration_0017_strips_stored_proxy_headers(client, proxy_scan):
    job_id, ids = proxy_scan
    spec = importlib.util.spec_from_file_location("migration_0017", MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    staging = {"page_url": "http://site.example/", "entries": [
        {"url": "http://site.example/", "request_headers": list(HEADERS), "response_headers": None},
        {"url": "http://site.example/a", "request_headers": [HEADERS[0]], "response_headers": [{"name": "Proxy-Connection", "value": "close"}]},
    ]}

    async def run():
        async with SessionLocal() as session:
            session.add(HarImport(job_id=uuid.UUID(job_id), payload=staging))
            await session.flush()
            statements = []
            migration.op = type("Op", (), {"execute": staticmethod(statements.append)})
            migration.upgrade()
            for statement in statements:
                await session.execute(text(statement))
            row = (await session.execute(text("SELECT request_headers, response_headers FROM scan_requests WHERE id = :id"), {"id": ids[0]})).one()
            payload = await session.scalar(text("SELECT payload FROM har_imports WHERE job_id = :id"), {"id": job_id})
            await session.rollback()  # el scan sembrado queda como estaba para los demás tests del módulo
            return row, payload

    (request_headers, response_headers), payload = client.portal.call(run)
    assert request_headers == [HEADERS[0], HEADERS[3]] and response_headers == [{"name": "content-type", "value": "text/html"}]
    assert payload["entries"][0]["request_headers"] == [HEADERS[0], HEADERS[3]] and payload["entries"][0]["response_headers"] is None
    assert payload["entries"][1]["response_headers"] == [] and payload["page_url"] == "http://site.example/"
