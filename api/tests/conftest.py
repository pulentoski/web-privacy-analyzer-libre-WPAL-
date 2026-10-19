import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db import SessionLocal
from app.main import app
from app.models import Job, ScanRedirect
from tests.factories import _request


# El CI (.github/workflows/tests.yml) ejecuta las pruebas de la api con WPA_UNIT_ONLY=1, que
# deselecciona las marcadas @pytest.mark.needs_stack: las que necesitan la base de IP (DB-IP, que no
# se versiona) o el stack en marcha (worker/frontend) para resources, rankings o la captura interactiva.
# Sin la variable (uso normal dentro del stack) NO cambia nada: se ejecutan todas, como siempre.
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_stack: requiere la base de IP o el stack en marcha; se omite en CI (WPA_UNIT_ONLY=1).",
    )


def pytest_collection_modifyitems(config, items):
    if os.environ.get("WPA_UNIT_ONLY") != "1":
        return
    deselected = [item for item in items if item.get_closest_marker("needs_stack")]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        kept = [item for item in items if not item.get_closest_marker("needs_stack")]
        items[:] = kept


@pytest.fixture(autouse=True)
def fresh_rate_limit():
    """Cada test parte con el cupo de scans intacto."""
    from app.ratelimit import scan_limiter

    scan_limiter.reset()
    yield


# Hosts que los tests usan como "sitio público". Se resuelven aquí, sin DNS externo: en F8 un
# corte de DNS convirtió un 202 esperado en un 400 DNS_RESOLUTION_FAILED (ver docs/OPERACION.md).
STABLE_DNS = {"example.com": ["93.184.215.14"], "www.example.com": ["93.184.215.14"]}


@pytest.fixture(autouse=True)
def stable_dns(monkeypatch):
    from app.security import url_validator

    real = url_validator.system_resolver

    async def resolver(host: str) -> list[str]:
        if host in STABLE_DNS:
            return STABLE_DNS[host]
        return await real(host)

    monkeypatch.setattr(url_validator, "system_resolver", resolver)


@pytest.fixture(scope="session")
def client():
    """Un único cliente (y un único event loop) para toda la sesión.

    El pool de conexiones del engine queda ligado al loop que lo usó primero: con
    un cliente por módulo, el segundo módulo heredaría conexiones de un loop cerrado.
    """
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


# Scans que no son de sitios reales (mismo criterio que app.testscans.is_test_scan y scripts/purge-test-scans.sh).
TEST_HOST_SQL = "(lower(substring(url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#@]+)')) ~ '(^|\\.)(test|example|invalid|localhost)$' OR lower(substring(url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#@]+)')) ~ '(^|\\.)example\\.(com|net|org)$')"


@pytest.fixture(scope="session", autouse=True)
def leave_no_test_scans(client):
    """Las pruebas no dejan scans en el historial (v1.4.2): al terminar se borran los de hosts de prueba."""
    yield
    from sqlalchemy import text

    async def purge():
        async with SessionLocal() as session:
            await session.execute(text(f"DELETE FROM jobs WHERE {TEST_HOST_SQL}"))
            await session.execute(text(f"DELETE FROM test_groups WHERE {TEST_HOST_SQL}"))
            await session.execute(text(f"DELETE FROM visit_comparisons WHERE {TEST_HOST_SQL}"))
            await session.commit()

    client.portal.call(purge)


@pytest.fixture(scope="session")
def scan(client):
    """Job completed con 5 requests: 2 first-party, 3 third-party (1 bloqueada, 1 POST)."""
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add(
                Job(id=job_id, url="http://site.example/", status="completed", result={"capture": {"truncated": True}})
            )
            await session.flush()
            session.add_all(
                [
                    _request(job_id, 0, resource_type="document", is_navigation=True),
                    _request(job_id, 1),
                    _request(
                        job_id, 2, host="t.tracker.example", registrable_domain="tracker.example", third_party=True,
                        response_status=302,
                    ),
                    _request(
                        job_id, 3, host="t.tracker.example", registrable_domain="tracker.example", third_party=True,
                        redirected_from_seq=2, method="POST", resource_type="fetch", post_data="aGVsbG8=",
                        post_data_encoding="utf8", post_data_sha256="ab" * 32, post_data_size=8,
                        post_data_truncated=False, post_data_source="playwright",
                        initiator={"type": "script", "script_url": "http://site.example/app.js", "stack": []},
                    ),
                    _request(
                        job_id, 4, host="internal.example", registrable_domain="internal.example", third_party=True,
                        response_status=403, blocked_by_proxy=True,
                        response_headers=[{"name": "x-squid-error", "value": "ERR_ACCESS_DENIED 0"}],
                    ),
                ]
            )
            session.add_all(
                [
                    ScanRedirect(job_id=job_id, chain_index=0, hop_index=0, request_seq=2, url="http://t.tracker.example/r2", status=302),
                    ScanRedirect(job_id=job_id, chain_index=0, hop_index=1, request_seq=3, url="http://t.tracker.example/r3", status=200),
                ]
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))  # cascada a scan_*
            await session.commit()

    client.portal.call(insert)
    yield str(job_id)
    client.portal.call(cleanup)


@pytest.fixture(scope="session")
def empty_scan(client):
    """Job fallido sin captura (failed: el worker no lo toma)."""
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="failed", error={"error_code": "X"}))
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id)
    client.portal.call(cleanup)
