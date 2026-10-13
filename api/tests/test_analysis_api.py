"""Endpoints de análisis (F3) contra la DB real, con un análisis insertado por el test."""

import json
import uuid

import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import delete, text

from app.db import SessionLocal
from app.models import Job, RequestAnalysis
from app.routes.analysis import SCHEMA_PATH, report_validator
from tests.factories import _request

VERSION = "9.9.9"


def _reason(signal, weight, ref, level="EVIDENCIA"):
    return {"signal": signal, "weight": weight, "level": level, "evidence_ref": ref, "detail": "detalle"}


@pytest.fixture(scope="module")
def analyzed_scan(client):
    """4 requests: 1 first-party Bajo, 2 de la misma entidad (Alto, Moderado) y 1 sin entidad (Muy alto)."""
    job_id = uuid.uuid4()
    ids = {}

    async def insert():
        async with SessionLocal() as session:
            session.add(
                Job(id=job_id, url="http://site.example/", status="completed", analysis_status="completed",
                    result={"final_url": "http://site.example/", "http_status": 200, "title": "T", "capture": {"truncated": False}})
            )
            await session.flush()
            requests = [
                _request(job_id, 0, resource_type="document", is_navigation=True),
                _request(job_id, 1, host="a.metrics.example", registrable_domain="metrics.example", third_party=True),
                _request(job_id, 2, host="b.metrics-cdn.example", registrable_domain="metrics-cdn.example", third_party=True),
                _request(job_id, 3, host="x.unknown.example", registrable_domain="unknown.example", third_party=True),
            ]
            session.add_all(requests)
            await session.flush()
            for request in requests:
                ids[request.seq] = request.id
            rows = [
                (0, 0, "Bajo", "first-party", "document", "no_disponible", []),
                (1, 75, "Alto", "analytics", "pixel", "Metrics Corp", [_reason("list_easyprivacy", 40, ids[1]), _reason("id_sync", 25, ids[1]), _reason("mechanism_pixel", 10, ids[1], "INFERENCIA")]),
                (2, 45, "Moderado", "advertising", "script", "Metrics Corp", [_reason("list_easylist", 35, ids[2]), _reason("mechanism_pixel", 10, ids[2], "INFERENCIA")]),
                (3, 90, "Muy alto", "cross-site", "beacon", "no_disponible", [_reason("id_sync", 25, ids[3])]),
            ]
            session.add_all(
                RequestAnalysis(job_id=job_id, request_id=ids[seq], score=score, band=band, category=category,
                                mechanism=mechanism, entity=entity, list_matches=[], reasons=reasons, analyzer_version=VERSION)
                for seq, score, band, category, mechanism, entity, reasons in rows
            )
            await session.execute(
                text(
                    "INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version) VALUES "
                    "(:job, 'id_sync', 'EVIDENCIA', 'El mismo valor se envió a 2 dominios.', CAST(:refs AS jsonb), '{}', :v),"
                    "(:job, 'identifier_param', 'INFERENCIA', 'Nombre típico de identificador.', CAST(:ref1 AS jsonb), '{}', :v)"
                ),
                {"job": job_id, "refs": json.dumps([ids[1], ids[3]]), "ref1": json.dumps([ids[1]]), "v": VERSION},
            )
            await session.execute(
                text(
                    "INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown,"
                    " data_categories, mechanisms, summary, partial, duration_ms) VALUES (:job, :v, 'abc', CAST(:lists AS jsonb),"
                    " 34, 'Posible', CAST(:breakdown AS jsonb), CAST(:data AS jsonb), '{\"pixel\": 1}', '{\"trackers\": 3}', false, 12)"
                ),
                {
                    "job": job_id, "v": VERSION,
                    "lists": json.dumps([{"id": "entity_map", "version": "", "retrieved_at": None, "sha256": "x", "license": "CC-BY-NC-SA-4.0", "noncommercial": True}]),
                    "breakdown": json.dumps([{"component": "tracker_domains", "count": 3, "cap": 30, "k": 8, "points": 9.38}]),
                    "data": json.dumps([{"category": "NETWORK", "status": "observado", "item": "Conexiones a terceros.", "evidence_refs": [ids[1]]}]),
                },
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id), ids
    client.portal.call(cleanup)


def test_requests_include_analysis(client, analyzed_scan):
    job_id, _ = analyzed_scan
    items = client.get(f"/api/scans/{job_id}/requests").json()["items"]
    assert [(i["seq"], i["score"], i["band"], i["category"], i["mechanism"]) for i in items] == [
        (0, 0, "Bajo", "first-party", "document"),
        (1, 75, "Alto", "analytics", "pixel"),
        (2, 45, "Moderado", "advertising", "script"),
        (3, 90, "Muy alto", "cross-site", "beacon"),
    ]


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"band": "Bajo"}, [0]), ({"band": "Alto"}, [1]), ({"band": "Muy alto"}, [3]), ({"band": "Posible"}, []),
        ({"category": "analytics"}, [1]), ({"category": "no-existe"}, []),
        ({"band": "Moderado", "category": "advertising", "third_party": "true"}, [2]),
        ({"band": "Moderado", "category": "analytics"}, []),
    ],
)
def test_requests_filter_by_band_and_category(client, analyzed_scan, params, expected):
    body = client.get(f"/api/scans/{analyzed_scan[0]}/requests", params=params).json()
    assert [item["seq"] for item in body["items"]] == expected and body["total"] == len(expected)


def test_invalid_band_is_rejected(client, analyzed_scan):
    response = client.get(f"/api/scans/{analyzed_scan[0]}/requests", params={"band": "Altísimo"})
    assert response.status_code == 422 and response.json()["error_code"] == "REQUEST_INVALID"


def test_requests_without_analysis_have_null_scores_not_zero(client, scan):
    items = client.get(f"/api/scans/{scan}/requests").json()["items"]
    assert items and all(item["score"] is None and item["band"] is None for item in items)
    assert client.get(f"/api/scans/{scan}/requests", params={"band": "Bajo"}).json()["total"] == 0


def test_request_detail_includes_reasons(client, analyzed_scan):
    job_id, ids = analyzed_scan
    detail = client.get(f"/api/scans/{job_id}/requests/{ids[1]}").json()
    assert detail["score"] == 75 and detail["analyzer_version"] == VERSION
    assert [reason["signal"] for reason in detail["reasons"]] == ["list_easyprivacy", "id_sync", "mechanism_pixel"]
    assert all(reason["evidence_ref"] == ids[1] for reason in detail["reasons"])


def test_trackers_grouped_by_entity(client, analyzed_scan):
    job_id, ids = analyzed_scan
    body = client.get(f"/api/scans/{job_id}/trackers").json()
    assert body["min_band"] == "Moderado" and body["tracker_requests"] == 3
    entities = body["entities"]
    # Orden por score máximo; la request en banda Bajo no aparece.
    assert [(e["entity"], e["request_count"], e["max_score"], e["max_band"]) for e in entities] == [
        ("no_disponible", 1, 90, "Muy alto"),
        ("Metrics Corp", 2, 75, "Alto"),
    ]
    metrics = entities[1]
    assert metrics["domains"] == ["metrics.example", "metrics-cdn.example"]
    assert metrics["categories"] == ["analytics", "advertising"]
    assert [request["request_id"] for request in metrics["requests"]] == [ids[1], ids[2]]
    assert all(request["reasons"] for entity in entities for request in entity["requests"])


def test_trackers_of_scan_without_analysis(client, scan):
    body = client.get(f"/api/scans/{scan}/trackers").json()
    assert body["entities"] == [] and body["tracker_requests"] == 0 and body["analysis_status"] is None


def test_scan_summary_includes_analysis(client, analyzed_scan, scan):
    body = client.get(f"/api/scans/{analyzed_scan[0]}").json()
    assert body["analysis_status"] == "completed"
    assert body["analysis"]["site_exposure_score"] == 34 and body["analysis"]["analyzer_version"] == VERSION
    assert client.get(f"/api/scans/{scan}").json()["analysis"] is None


def test_report_validates_against_schema(client, analyzed_scan):
    job_id, ids = analyzed_scan
    response = client.get(f"/api/scans/{job_id}/report")
    assert response.status_code == 200, response.text
    report = response.json()
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []
    assert report["schema_version"] == schema["properties"]["schema_version"]["const"] == "1.7.0"
    assert report["analysis"]["analyzer_version"] == VERSION
    assert report["analysis"]["lists"][0]["noncommercial"] is True
    assert report["site"]["exposure_score"] == 34 and report["capture"]["total_requests"] == 4
    assert [finding["level"] for finding in report["findings"]] == ["EVIDENCIA", "INFERENCIA"]
    assert report["findings"][0]["evidence_refs"] == [ids[1], ids[3]]
    assert len(report["trackers"]) == 2 and report["limitations"]


def test_schema_rejects_findings_without_level_or_evidence(client, analyzed_scan):
    report = client.get(f"/api/scans/{analyzed_scan[0]}/report").json()
    validator = report_validator()
    for broken in (
        {"type": "x", "claim": "sin evidencia", "level": "EVIDENCIA", "evidence_refs": []},
        {"type": "x", "claim": "sin nivel", "evidence_refs": [1]},
        {"type": "x", "claim": "nivel inventado", "level": "SEGURO", "evidence_refs": [1]},
    ):
        assert list(validator.iter_errors({**report, "findings": [broken]})), broken
    assert list(validator.iter_errors({**report, "schema_version": "1.0.0"}))
    # Un hallazgo de fingerprinting sin ninguna referencia tampoco es válido.
    empty = {"script_url": "http://x/a.js", "heuristic": "canvas_fingerprinting", "level": "INFERENCIA", "claim": "x",
             "evidence_refs": {"calls": [], "requests": []}}
    script = {"script_url": "http://x/a.js", "entity": "no_disponible", "apis": [], "total_calls": 0,
              "fingerprinting_inferred": True, "heuristics": [empty]}
    assert list(validator.iter_errors({**report, "fingerprinting": {**report["fingerprinting"], "scripts": [script]}}))
    # Una exfiltración debe ser EVIDENCIA y traer tanto la llamada como la request.
    partial = {**empty, "heuristic": "exfiltration", "level": "EVIDENCIA", "evidence_refs": {"calls": [1], "requests": []}}
    assert list(validator.iter_errors({**report, "fingerprinting": {**report["fingerprinting"], "exfiltrations": [partial]}}))
    assert list(validator.iter_errors({**report, "site": {**report["site"], "exposure_score": 100}}))


def test_invalid_report_is_not_served(client, analyzed_scan):
    job_id, _ = analyzed_scan

    async def set_band(band):
        async with SessionLocal() as session:
            await session.execute(text("UPDATE site_analysis SET band = :band WHERE job_id = :job"), {"band": band, "job": uuid.UUID(job_id)})
            await session.commit()

    client.portal.call(set_band, "Inexistente")
    try:
        response = client.get(f"/api/scans/{job_id}/report")
        assert response.status_code == 500 and response.json()["error_code"] == "REPORT_INVALID"
    finally:
        client.portal.call(set_band, "Posible")


def test_report_before_analysis(client, scan):
    response = client.get(f"/api/scans/{scan}/report")
    assert response.status_code == 409 and response.json()["error_code"] == "ANALYSIS_NOT_READY"


def test_reanalyze_queues_without_touching_the_capture(client, analyzed_scan):
    job_id, _ = analyzed_scan

    async def state():
        async with SessionLocal() as session:
            row = (await session.execute(
                text("SELECT status, analysis_status, attempts, (SELECT count(*) FROM scan_requests WHERE job_id = :job) FROM jobs WHERE id = :job"),
                {"job": uuid.UUID(job_id)},
            )).one()
            # Se deja como estaba para que el worker real no analice este job de prueba.
            await session.execute(text("UPDATE jobs SET analysis_status = 'completed' WHERE id = :job"), {"job": uuid.UUID(job_id)})
            await session.commit()
            return tuple(row)

    response = client.post(f"/api/scans/{job_id}/reanalyze")
    assert response.status_code == 202 and response.json() == {"job_id": job_id, "analysis_status": "queued"}
    status, analysis_status, attempts, requests = client.portal.call(state)
    # El scan NO vuelve a la cola de navegación: sigue completed, sin intentos nuevos.
    assert status == "completed" and attempts == 0 and requests == 4
    assert analysis_status in ("queued", "running", "completed")


def test_reanalyze_conflicts(client, empty_scan):
    response = client.post(f"/api/scans/{empty_scan}/reanalyze")
    assert response.status_code == 409 and response.json()["error_code"] == "NO_CAPTURE"
    missing = client.post("/api/scans/00000000-0000-0000-0000-000000000000/reanalyze")
    assert missing.status_code == 404 and missing.json()["error_code"] == "JOB_NOT_FOUND"


# --- Fingerprinting (F4) ---


@pytest.fixture(scope="module")
def fp_scan(client, analyzed_scan):
    """Añade al scan analizado llamadas a APIs, hallazgos y atributos de fingerprinting."""
    job_id, ids = analyzed_scan
    job = uuid.UUID(job_id)
    call_ids = {}
    script = "http://site.example/r1?a=1&a=2"  # la URL de la request 1: así hereda su entidad

    async def insert():
        async with SessionLocal() as session:
            await session.execute(
                text("UPDATE jobs SET result = jsonb_set(result, '{capture,fingerprinting}', CAST(:meta AS jsonb)) WHERE id = :job"),
                {"job": job, "meta": json.dumps({"api_calls": 3, "available": ["canvas.toDataURL"], "truncated": False, "messages": 4, "rejected": 1})},
            )
            for api, url, count, details in (
                ("canvas.toDataURL", script, 2, {"reads": [{"kind": "canvas", "sha256": "ab" * 32, "length": 100}]}),
                ("webgl.UNMASKED_RENDERER_WEBGL", script, 1, {"value": "ANGLE (Test GPU)"}),
                ("navigator.userAgent", "", 7, {"value": "Mozilla/5.0 Test"}),
            ):
                call_ids[api] = await session.scalar(
                    text(
                        "INSERT INTO fp_api_calls (job_id, api, script_url, frame_url, count, details) "
                        "VALUES (:job, :api, :url, 'http://site.example/', :count, CAST(:details AS jsonb)) RETURNING id"
                    ),
                    {"job": job, "api": api, "url": url, "count": count, "details": json.dumps(details)},
                )
            for heuristic, level, calls, requests in (
                ("canvas_fingerprinting", "INFERENCIA", [call_ids["canvas.toDataURL"]], []),
                ("webgl_unmasked_read", "EVIDENCIA", [call_ids["webgl.UNMASKED_RENDERER_WEBGL"]], []),
                ("exfiltration", "EVIDENCIA", [call_ids["webgl.UNMASKED_RENDERER_WEBGL"]], [ids[3]]),
            ):
                await session.execute(
                    text(
                        "INSERT INTO fp_findings (job_id, script_url, heuristic, level, claim, call_refs, request_refs, details, analyzer_version) "
                        "VALUES (:job, :url, :h, :level, 'claim de prueba', CAST(:calls AS jsonb), CAST(:requests AS jsonb), '{}', :v)"
                    ),
                    {"job": job, "url": script, "h": heuristic, "level": level, "calls": json.dumps(calls), "requests": json.dumps(requests), "v": VERSION},
                )
            for attribute, status, value, calls, requests in (
                ("webgl_renderer", "OBSERVADO", "ANGLE (Test GPU)", [call_ids["webgl.UNMASKED_RENDERER_WEBGL"]], [ids[3]]),
                ("canvas", "UTILIZADO", None, [call_ids["canvas.toDataURL"]], []),
                ("audio", "DISPONIBLE", None, [], []),
                ("battery", "NO_DISPONIBLE", None, [], []),
            ):
                await session.execute(
                    text(
                        "INSERT INTO fp_attributes (job_id, attribute, status, value, scripts, call_refs, request_refs) "
                        "VALUES (:job, :a, :s, :v, '[]', CAST(:calls AS jsonb), CAST(:requests AS jsonb))"
                    ),
                    {"job": job, "a": attribute, "s": status, "v": value, "calls": json.dumps(calls), "requests": json.dumps(requests)},
                )
            await session.commit()

    client.portal.call(insert)
    return job_id, ids, call_ids, script


def test_fingerprinting_endpoint(client, fp_scan):
    job_id, ids, call_ids, script = fp_scan
    body = client.get(f"/api/scans/{job_id}/fingerprinting").json()
    assert body["instrumented"] is True and body["truncated"] is False and body["rejected_events"] == 1
    scripts = body["scripts"]
    # Primero los scripts con fingerprinting inferido. Sin URL de script, la llamada se atribuye a su frame.
    assert [(s["script_url"], s["fingerprinting_inferred"], s["total_calls"]) for s in scripts] == [(script, True, 3), ("(inline o eval en http://site.example/)", False, 7)]
    # v1.4.2: un script inline o eval es código del documento donde corrió: se atribuye a su organización o, si no se conoce, a su host.
    assert scripts[0]["entity"] == "Metrics Corp" and scripts[1]["entity"] == "site.example"
    assert scripts[0]["apis"] == [{"api": "canvas.toDataURL", "count": 2}, {"api": "webgl.UNMASKED_RENDERER_WEBGL", "count": 1}]
    assert [(h["heuristic"], h["level"]) for h in scripts[0]["heuristics"]] == [
        ("canvas_fingerprinting", "INFERENCIA"), ("webgl_unmasked_read", "EVIDENCIA"),
    ]
    assert {a["attribute"]: a["status"] for a in body["attributes"]} == {
        "webgl_renderer": "OBSERVADO", "canvas": "UTILIZADO", "audio": "DISPONIBLE", "battery": "NO_DISPONIBLE",
    }
    assert len(body["exfiltrations"]) == 1
    exfiltration = body["exfiltrations"][0]
    assert exfiltration["level"] == "EVIDENCIA"
    assert exfiltration["evidence_refs"] == {"calls": [call_ids["webgl.UNMASKED_RENDERER_WEBGL"]], "requests": [ids[3]]}


def test_fingerprinting_of_uninstrumented_scan(client, scan):
    body = client.get(f"/api/scans/{scan}/fingerprinting").json()
    # Sin instrumentación no se afirma "sin fingerprinting": se dice que no se midió.
    assert body["instrumented"] is False and body["truncated"] is None
    assert body["scripts"] == [] and body["exfiltrations"] == [] and body["attributes"] == []


def test_report_includes_fingerprinting_section(client, fp_scan):
    job_id = fp_scan[0]
    response = client.get(f"/api/scans/{job_id}/report")
    assert response.status_code == 200, response.text
    report = response.json()
    assert list(report_validator().iter_errors(report)) == []
    assert report["schema_version"] == "1.7.0"
    assert report["fingerprinting"]["scripts"][0]["fingerprinting_inferred"] is True
    assert report["fingerprinting"]["exfiltrations"][0]["evidence_refs"]["requests"]
