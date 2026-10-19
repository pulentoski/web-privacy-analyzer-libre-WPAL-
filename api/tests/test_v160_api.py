"""v1.6.0: GET /api/scans/{id}/overview: «Quién recibió más datos» y el scan anterior del mismo sitio (docs/adr/042).

Se calcula al leer, con los hallazgos y el análisis ya guardados: no cambia el análisis, el puntaje ni el reporte.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, text

from app import overview
from app.db import SessionLocal
from app.models import Job, RequestAnalysis
from tests.factories import _request
from tests.test_analysis_api import VERSION

TRACKER_BANDS = ("Moderado", "Alto", "Muy alto")


def test_ranking_orders_by_data_types_then_tracking_requests():
    requests = {
        1: {"entity": "Ads Co", "party": "third_party", "band": "Alto", "domain": "ads.example"},
        2: {"entity": "Ads Co", "party": "third_party", "band": "Bajo", "domain": "ads.example"},
        3: {"entity": "Metrics", "party": "third_party", "band": "Alto", "domain": "metrics.example"},
        4: {"entity": "Metrics", "party": "third_party", "band": "Muy alto", "domain": "metrics.example"},
        5: {"entity": "no_disponible", "party": "third_party", "band": "Alto", "domain": "cdn.example"},
        6: {"entity": "Sitio", "party": "first_party", "band": "Alto", "domain": "site.example"},
        7: {"entity": "no_disponible", "party": "third_party", "band": "Alto", "domain": "other.example"},
    }
    findings = [
        {"type": "id_sync", "evidence_refs": [1, 3, 6]},       # identificador: Ads Co y Metrics (el sitio no es tercero)
        {"type": "url_leak", "evidence_refs": [2]},            # URL: Ads Co
        {"type": "consent_mode_state", "evidence_refs": [1]},  # consentimiento: Ads Co
        {"type": "search_leak", "evidence_refs": [5]},         # búsqueda: el dominio sin organización
        {"type": "list_match", "evidence_refs": [3, 4, 7]},    # no es un tipo de dato
    ]
    exfiltrations = [{"request_refs": [4]}]                    # dispositivo: Metrics
    cookies = [{"entity": "Ads Co", "domain": "ads.example", "third_party": "True", "max_days": "395", "names": ["uid"]},
               {"entity": "Ads Co", "domain": "ads.example", "third_party": "True", "max_days": "30", "names": ["a", "b"]},
               {"entity": "Sitio", "domain": "site.example", "third_party": "False", "max_days": "999", "names": ["s"]}]
    ranked = overview.recipients(requests, findings, exfiltrations, cookies, TRACKER_BANDS)
    assert [(row["rank"], row["organization"], row["domains"], row["data_types"], row["tracking_requests"]) for row in ranked] == [
        (1, "Ads Co", ["ads.example"], ["identificador", "url", "consentimiento"], 1),
        (2, "Metrics", ["metrics.example"], ["identificador", "dispositivo"], 2),
        (3, "no_disponible", ["cdn.example"], ["busqueda"], 1),
        (4, "no_disponible", ["other.example"], [], 1),  # solo requests de tracking: va al final
    ]
    assert ranked[0]["longest_cookie_days"] == 395 and ranked[0]["longest_cookie"] == "uid"
    assert ranked[1]["longest_cookie_days"] is None
    # Sin organización no se juntan dominios distintos, y el propio sitio nunca aparece.
    assert all(row["organization"] != "Sitio" for row in ranked)


def test_previous_scan_only_with_the_same_protocol():
    newer = {"job_id": "b", "score": 50, "protocol_version": 1}
    older = {"job_id": "a", "score": 40, "protocol_version": 1}
    assert overview.previous_scan(1, [newer, older]) == {"previous": newer, "reason": None}
    # El más reciente es de otro protocolo: no se compara (tampoco se salta a uno más viejo).
    assert overview.previous_scan(2, [newer, older]) == {"previous": None, "reason": "otro_protocolo"}
    assert overview.previous_scan(None, [newer]) == {"previous": None, "reason": "otro_protocolo"}
    assert overview.previous_scan(1, []) == {"previous": None, "reason": "sin_scan_anterior"}


@pytest.fixture(scope="module")
def two_scans(client):
    """Dos scans de http://www.site.example/: el anterior (protocolo 1, índice 40) y el actual (protocolo 1, índice 55)."""
    previous_id, current_id, other_protocol_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    now = datetime.now(timezone.utc)
    protocol = lambda version: {"measurement": {"visit_protocol": {"protocol_version": version}}}  # noqa: E731

    async def insert():
        async with SessionLocal() as session:
            for job_id, created, score, version, url in ((other_protocol_id, now - timedelta(days=9), 30, 2, "http://www.site.example/x"),
                                                         (previous_id, now - timedelta(days=2), 40, 1, "http://site.example/"),
                                                         (current_id, now, 55, 1, "http://www.site.example/")):
                session.add(Job(id=job_id, url=url, status="completed", analysis_status="completed", created_at=created,
                                result={"final_url": url, "http_status": 200, "title": "T", "capture": {"truncated": False}, **protocol(version)}))
                await session.flush()
                await session.execute(
                    text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                         "VALUES (:job, :v, 'l', '[]', :score, 'Moderado', '[]', '[]', '{}', '{}', false, 5)"), {"job": job_id, "v": VERSION, "score": score})
            requests = [_request(current_id, 0, resource_type="document", is_navigation=True),
                        _request(current_id, 1, host="px.ads.example", registrable_domain="ads.example", third_party=True)]
            session.add_all(requests)
            await session.flush()
            for request, entity, party, band in ((requests[0], "Sitio", "first_party", "Bajo"), (requests[1], "Ads Co", "third_party", "Alto")):
                session.add(RequestAnalysis(job_id=current_id, request_id=request.id, score=70, band=band, category="advertising", mechanism="pixel",
                                            entity=entity, party=party, list_matches=[], analyzer_version=VERSION, reasons=[]))
            for kind, refs, details in (("url_leak", [requests[1].id], {"recipient": "Ads Co"}),
                                        ("persistent_cookie", [requests[1].id], {"entity": "Ads Co", "domain": "ads.example", "third_party": "True", "max_days": "180", "names": ["uid"]})):
                await session.execute(
                    text("INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version) "
                         "VALUES (:job, :type, 'EVIDENCIA', 'c', CAST(:refs AS jsonb), CAST(:details AS jsonb), :v)"),
                    {"job": current_id, "type": kind, "refs": json.dumps(refs), "details": json.dumps(details), "v": VERSION})
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id.in_([previous_id, current_id, other_protocol_id])))
            await session.commit()

    client.portal.call(insert)
    yield {"previous": str(previous_id), "current": str(current_id), "other": str(other_protocol_id)}
    client.portal.call(cleanup)


def test_overview_endpoint_ranks_and_finds_the_previous_scan(client, two_scans):
    body = client.get(f"/api/scans/{two_scans['current']}/overview").json()
    assert [row["organization"] for row in body["recipients"]] == ["Ads Co"]
    row = body["recipients"][0]
    assert row["data_types"] == ["url"] and row["data_type_labels"] == ["URL de la página"]
    assert row["tracking_requests"] == 1 and row["longest_cookie_days"] == 180
    # Mismo sitio (con y sin «www.»), anterior y con el mismo protocolo.
    assert body["previous_scan"]["job_id"] == two_scans["previous"] and body["previous_scan"]["score"] == 40
    assert [item["id"] for item in body["data_types"]] == ["identificador", "url", "consentimiento", "dispositivo", "busqueda"]
    # El scan anterior al «anterior» es de otro protocolo: para él no hay comparación.
    older = client.get(f"/api/scans/{two_scans['previous']}/overview").json()
    assert older["previous_scan"] is None and older["previous_reason"] == "otro_protocolo"
    first = client.get(f"/api/scans/{two_scans['other']}/overview").json()
    assert first["previous_scan"] is None and first["previous_reason"] == "sin_scan_anterior"


def test_overview_does_not_touch_the_report(client, two_scans):
    before = client.get(f"/api/scans/{two_scans['current']}/report")
    client.get(f"/api/scans/{two_scans['current']}/overview")
    after = client.get(f"/api/scans/{two_scans['current']}/report")
    strip = lambda body: {key: value for key, value in body.items() if key != "generated_at"}  # noqa: E731
    assert before.status_code == after.status_code
    if before.status_code == 200:
        assert strip(before.json()) == strip(after.json())


def test_overview_needs_the_analysis(client):
    response = client.get(f"/api/scans/{uuid.uuid4()}/overview")
    assert response.status_code == 404
