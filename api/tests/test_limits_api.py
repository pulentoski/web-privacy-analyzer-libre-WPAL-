"""Rate limit, tope de cola, lista de scans y opciones (F5)."""

import uuid

import pytest
from sqlalchemy import delete, text

from app.config import get_settings
from app.db import SessionLocal
from app.models import Job
from app.ratelimit import SlidingWindowLimiter, client_ip
from tests.test_analysis_api import analyzed_scan  # noqa: F401  (fixture compartida)

URL = {"url": "https://example.com"}


@pytest.fixture
def created(client):
    """Borra los jobs que cree el test (el worker real podría tomarlos)."""
    ids: list[str] = []
    yield ids

    async def cleanup():
        async with SessionLocal() as session:
            for job_id in ids:
                await session.execute(delete(Job).where(Job.id == uuid.UUID(job_id)))
            await session.commit()

    client.portal.call(cleanup)


@pytest.fixture
def limits(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_rate_limit", 3)
    monkeypatch.setattr(settings, "scan_rate_window_s", 60)
    return settings


def test_request_n_plus_one_is_rate_limited(client, limits, created):
    for _ in range(3):
        response = client.post("/api/scans", json=URL)
        assert response.status_code == 202, response.text
        created.append(response.json()["job_id"])
    response = client.post("/api/scans", json=URL)
    assert response.status_code == 429
    body = response.json()
    assert set(body) == {"error_code", "message", "details", "stage", "timestamp"}
    assert body["error_code"] == "RATE_LIMITED" and body["stage"] == "rate_limit"
    assert body["details"]["limit"] == 3 and body["details"]["window_s"] == 60 and 0 < body["details"]["retry_after_s"] <= 60
    # Leer no está limitado.
    assert client.get(f"/api/scans/{created[0]}").status_code == 200


def test_dns_failure_is_a_400_and_does_not_consume_quota(client, limits, created, monkeypatch):
    """Causa del fallo intermitente de F8: si el DNS no responde, crear un scan da 400, no 202."""
    from app.security import url_validator

    async def broken(host: str) -> list[str]:
        raise OSError("Temporary failure in name resolution")

    monkeypatch.setattr(url_validator, "system_resolver", broken)
    for _ in range(5):
        response = client.post("/api/scans", json=URL)
        assert response.status_code == 400 and response.json()["error_code"] == "DNS_RESOLUTION_FAILED"

    async def working(host: str) -> list[str]:
        return ["93.184.215.14"]

    # Los intentos fallidos no gastaron cupo: caben los 3 scans del límite.
    monkeypatch.setattr(url_validator, "system_resolver", working)
    for _ in range(3):
        response = client.post("/api/scans", json=URL)
        assert response.status_code == 202, response.text
        created.append(response.json()["job_id"])
    assert client.post("/api/scans", json=URL).status_code == 429


def test_invalid_urls_do_not_consume_quota(client, limits, created):
    for _ in range(10):
        assert client.post("/api/scans", json={"url": "http://127.0.0.1/"}).status_code == 400
    response = client.post("/api/scans", json=URL)
    assert response.status_code == 202
    created.append(response.json()["job_id"])


def test_rate_limit_is_per_client_ip_from_trusted_proxy_only(client, limits, created, monkeypatch):
    # El TestClient conecta como "testclient": no es un proxy de confianza, su X-Forwarded-For se ignora.
    for index in range(3):
        response = client.post("/api/scans", json=URL, headers={"X-Forwarded-For": f"203.0.113.{index}"})
        assert response.status_code == 202
        created.append(response.json()["job_id"])
    assert client.post("/api/scans", json=URL, headers={"X-Forwarded-For": "203.0.113.99"}).status_code == 429


class FakeRequest:
    def __init__(self, peer, forwarded=None):
        self.client = type("Client", (), {"host": peer})()
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}


def test_client_ip_trusts_forwarded_header_only_from_the_proxy(monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxies", "172.30.1.10")
    assert client_ip(FakeRequest("172.30.1.10", "198.51.100.7")) == "198.51.100.7"
    assert client_ip(FakeRequest("172.30.1.10", "1.1.1.1, 198.51.100.7")) == "198.51.100.7"  # la que añadió el proxy
    assert client_ip(FakeRequest("172.30.1.10", "no-es-ip")) == "172.30.1.10"
    assert client_ip(FakeRequest("172.30.1.10")) == "172.30.1.10"
    # Cualquier otro origen (incluido el gateway de Docker): la cabecera no cuenta.
    assert client_ip(FakeRequest("172.30.1.1", "198.51.100.7")) == "172.30.1.1"
    assert client_ip(FakeRequest("203.0.113.5", "198.51.100.7")) == "203.0.113.5"


def test_sliding_window_limiter():
    limiter = SlidingWindowLimiter()
    assert [limiter.check("a", 2, 60) for _ in range(3)][:2] == [None, None]
    assert limiter.check("a", 2, 60) > 0
    assert limiter.check("b", 2, 60) is None  # otra IP, otro cupo
    assert limiter.check("a", 2, 0) is None  # ventana vencida


def test_queue_cap(client, created, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_queued_jobs", 0)
    response = client.post("/api/scans", json=URL)
    assert response.status_code == 429
    body = response.json()
    assert body["error_code"] == "QUEUE_FULL" and body["stage"] == "queue" and body["details"]["max_queued_jobs"] == 0


def test_scan_options(client, created):
    response = client.post("/api/scans", json={**URL, "options": {"fp_instrumentation": False}})
    assert response.status_code == 202 and response.json()["options"] == {"fp_instrumentation": False}
    created.append(response.json()["job_id"])
    plain = client.post("/api/scans", json=URL)
    assert plain.json()["options"] is None
    created.append(plain.json()["job_id"])
    for bad in ({"fp_instrumentation": "no"}, {"otra": 1}, "texto"):
        assert client.post("/api/scans", json={**URL, "options": bad}).status_code == 422


def test_recent_scans_list(client, analyzed_scan, scan):
    body = client.get("/api/scans", params={"limit": 100}).json()
    by_id = {item["job_id"]: item for item in body["items"]}
    analyzed = by_id[analyzed_scan[0]]
    assert analyzed["status"] == "completed" and analyzed["site_exposure_score"] == 34 and analyzed["title"] == "T"
    assert by_id[scan]["site_exposure_score"] is None  # sin análisis: null, no 0
    created = [item["created_at"] for item in body["items"]]
    assert created == sorted(created, reverse=True)
    assert client.get("/api/scans", params={"limit": 1}).json()["items"].__len__() == 1
    assert client.get("/api/scans", params={"limit": 0}).status_code == 422


def test_requests_filter_by_mechanism_domain_and_sort(client, analyzed_scan):
    job_id, _ = analyzed_scan
    get = lambda **params: client.get(f"/api/scans/{job_id}/requests", params=params).json()  # noqa: E731
    assert [i["seq"] for i in get(mechanism="pixel")["items"]] == [1]
    assert [i["seq"] for i in get(domain="METRICS")["items"]] == [1, 2]
    assert [i["seq"] for i in get(domain="unknown.example")["items"]] == [3]
    # El texto buscado es literal: % y _ no son comodines.
    assert get(domain="%")["total"] == 0 and get(domain="_")["total"] == 0
    assert [i["score"] for i in get(sort="-score")["items"]] == [90, 75, 45, 0]
    assert [i["score"] for i in get(sort="score")["items"]] == [0, 45, 75, 90]
    assert [i["seq"] for i in get(sort="-time")["items"]] == [3, 2, 1, 0]
    assert client.get(f"/api/scans/{job_id}/requests", params={"sort": "otro"}).status_code == 422


def test_request_detail_has_parameters_decodings_and_related_findings(client, analyzed_scan):
    job_id, ids = analyzed_scan

    async def insert():
        async with SessionLocal() as session:
            await session.execute(
                text(
                    "INSERT INTO parameters (job_id, request_id, source, name, value, value_truncated, category, shapes, length, "
                    "entropy, identifier_like, encoding_chain) VALUES (:job, :rid, 'query', 'uid', 'abc123def456', false, "
                    "'identity', '[\"hex\"]', 12, 3.1, true, '[]')"
                ),
                {"job": uuid.UUID(job_id), "rid": ids[1]},
            )
            await session.execute(
                text(
                    "INSERT INTO decoded_values (job_id, request_id, source, name, path, raw_value, decoded_value, "
                    "decoded_truncated, encoding_chain, confidence) VALUES (:job, :rid, 'query', 'd', '', 'eyJhIjoxfQ', "
                    ":decoded, false, '[\"base64\", \"json\"]', 0.85)"
                ),
                {"job": uuid.UUID(job_id), "rid": ids[1], "decoded": '{"a":1}'},
            )
            await session.commit()

    client.portal.call(insert)
    detail = client.get(f"/api/scans/{job_id}/requests/{ids[1]}").json()
    assert [(p["source"], p["name"], p["category"]) for p in detail["parameters"]] == [("query", "uid", "identity")]
    assert detail["decoded_values"][0]["encoding_chain"] == ["base64", "json"]
    assert detail["decoded_values"][0]["raw_value"] == "eyJhIjoxfQ"
    # Los dos hallazgos de prueba citan la request 1; solo uno cita la 3.
    assert [(f["kind"], f["type"], f["level"]) for f in detail["findings"]] == [
        ("general", "id_sync", "EVIDENCIA"), ("general", "identifier_param", "INFERENCIA"),
    ]
    other = client.get(f"/api/scans/{job_id}/requests/{ids[3]}").json()
    assert [f["type"] for f in other["findings"]] == ["id_sync"]
    assert client.get(f"/api/scans/{job_id}/requests/{ids[0]}").json()["findings"] == []


def test_findings_endpoint(client, analyzed_scan):
    job_id, ids = analyzed_scan
    body = client.get(f"/api/scans/{job_id}/findings").json()
    general = [item for item in body["items"] if item["kind"] == "general"]
    assert [(i["type"], i["level"]) for i in general] == [("id_sync", "EVIDENCIA"), ("identifier_param", "INFERENCIA")]
    assert general[0]["evidence_refs"] == {"calls": [], "requests": [ids[1], ids[3]]}
    assert all(item["id"] and item["claim"] for item in body["items"])
    only = client.get(f"/api/scans/{job_id}/findings", params={"level": "INFERENCIA"}).json()
    assert {item["level"] for item in only["items"]} == {"INFERENCIA"} and only["by_level"]["EVIDENCIA"] >= 1
    assert client.get(f"/api/scans/{job_id}/findings", params={"level": "SEGURO"}).status_code == 422


def test_domains_endpoint(client, analyzed_scan):
    body = client.get(f"/api/scans/{analyzed_scan[0]}/domains").json()
    by_domain = {item["domain"]: item for item in body["domains"]}
    assert by_domain["site.example"] == {
        "domain": "site.example", "third_party": False, "party": "first_party", "requests": 1, "max_score": 0, "category": "first-party",
        "entity": "no_disponible", "tracker_requests": 0, "tracker": False, "fingerprinting": False,
    }
    assert by_domain["metrics.example"]["tracker"] is True and by_domain["metrics.example"]["entity"] == "Metrics Corp"
    assert by_domain["unknown.example"]["max_score"] == 90 and by_domain["unknown.example"]["third_party"] is True
