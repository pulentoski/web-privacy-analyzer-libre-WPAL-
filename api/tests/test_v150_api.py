"""v1.5.0 (docs/adr/038): condiciones de la medición, protocolo de visita (protocol_version) y cobertura por contexto en el
reporte; aviso del Panel y de la comparación cuando se mezclan protocolos."""

import json
import pathlib
import uuid
from functools import partial

import pytest
import yaml
from sqlalchemy import text

from app import measurement
from app.config import get_settings
from app.db import SessionLocal
from app.masking import mask_report
from app.models import Job
from app.report_html import render_scan_report
from app.routes import panel as panel_routes
from app.routes.analysis import limitations_for, report_validator
from app.routes.har import compare_protocol
from tests.factories import _request

STAGES = ["carga", "espera", "scroll", "espera", "cierre"]


def stage(index, *, completed=True, reason=None, seqs=(), **extra):
    planned = [{}, {"duration_s": 3}, {"max_s": 8, "step_interval_ms": 400}, {"duration_s": 3}, {"observe_s": 3}][index]
    default = ["network_idle", "duration_elapsed", "document_end", "duration_elapsed", "tab_closed"][index]
    return {"name": STAGES[index], "order": index + 1, "planned": planned, "completed": completed,
            "started_at": f"2026-10-18T12:00:0{index}.000+00:00", "ended_at": f"2026-10-18T12:00:0{index + 1}.000+00:00",
            "reason": reason or default, "requests": len(seqs), "request_seqs": list(seqs), **extra}


def worker_result(**overrides) -> dict:
    """jobs.result tal como lo deja el worker v1.5.0."""
    stages = [stage(0, seqs=(0, 1)), stage(1), stage(2, seqs=(2,), reached_end=True), stage(3, includes=["pre_close_dump"]),
              stage(4, seqs=(3,))]
    result = {
        "final_url": "https://v150.example/", "http_status": 200,
        "measurement": {
            "browser": {"name": "Chromium", "version": "153.0.8010.12"}, "browser_mode": "headful",
            "started_at": "2026-10-18T12:00:00.000+00:00",
            "visit_protocol": {"protocol_version": 1, "applies": True, "stages": stages},
            "egress_country": {"status": "ok", "country_code": "CL", "country": "Chile", "source": "DB-IP Lite 2026-10", "reason": None},
        },
    }
    result.update(overrides)
    return result


ANALYSIS = {"analyzer_version": "1.17.0", "lists_version": "abc123",
            "lists": [{"id": "easylist", "version": "202610062156", "noncommercial": False},
                      {"id": "entity_map", "version": "", "noncommercial": True}]}


# --- sección measurement (sin base de datos) ---


def test_section_from_a_v150_scan():
    section = measurement.section(worker_result(), "scan", started_at=None, analysis=ANALYSIS,
                                  requests={3: {"seq": 3, "method": "POST", "host": "t.example", "path": "/bye", "resource_type": "ping"}})
    assert section["protocol_version"] == 1
    assert section["conditions"] == {
        "browser": {"name": "Chromium", "version": "153.0.8010.12"}, "browser_mode": "headful",
        "measured_at": "2026-10-18T12:00:00.000+00:00", "analyzer_version": "1.17.0", "lists_version": "abc123",
        "lists": [{"id": "easylist", "version": "202610062156"}, {"id": "entity_map", "version": "no_disponible"}],
        "egress_country": {"status": "ok", "country_code": "CL", "country": "Chile", "source": "DB-IP Lite 2026-10", "reason": None},
    }
    protocol = section["visit_protocol"]
    assert protocol["applies"] is True and [item["name"] for item in protocol["stages"]] == STAGES
    assert all(item["completed"] for item in protocol["stages"]) and protocol["stages"][2]["reached_end"] is True
    assert protocol["stages"][3]["includes"] == ["incluye el volcado de la captura previo al cierre"]
    assert protocol["stages"][4]["reason_text"] == "la pestaña se cerró"
    assert protocol["closing_sends"] == [{"seq": 3, "method": "POST", "host": "t.example", "path": "/bye", "resource_type": "ping"}]
    assert "no garantiza capturar todos los beacons de salida" in protocol["closing_notice"]
    assert [row["id"] for row in section["coverage"]["contexts"]] == [
        "main_frame", "same_origin_iframe", "third_party_iframe", "dedicated_worker", "service_worker"]


def test_coverage_table_is_the_audited_yaml_and_feeds_the_limits():
    raw = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "coverage.yaml").read_text(encoding="utf-8"))
    table = measurement.coverage()
    assert [(row["id"], row["instrumentation"], row["apis_observed"], row["traffic_captured"]) for row in table["contexts"]] == [
        (row["id"], row["instrumentation"], row["apis_observed"], row["traffic_captured"]) for row in raw["contexts"]]
    limits = limitations_for(None)
    for row in raw["contexts"]:
        if "limitation" in row:
            assert row["limitation"] in limits
    assert raw["closing_limitation"] in limits
    assert not any("Web Workers" in item for item in limits)


@pytest.mark.parametrize("source, note", [
    ("har_import", "Captura HAR importada"), ("interactive", "Captura interactiva"), ("scan", "Scan anterior a v1.5.0")])
def test_without_protocol(source, note):
    result = {"final_url": "https://v150.example/"}
    if source == "interactive":
        result["measurement"] = {"browser": {"name": "Chromium", "version": "153.0.8010.12"}, "browser_mode": "headful",
                                 "started_at": "2026-10-18T12:00:00.000+00:00",
                                 "visit_protocol": {"protocol_version": None, "applies": False, "stages": []},
                                 "egress_country": {"status": "desconocido", "country_code": None, "country": "desconocido",
                                                    "source": None, "reason": "La consulta de la IP de salida falló."}}
    section = measurement.section(result, source, started_at="2026-10-01T10:00:00+00:00", analysis=ANALYSIS, requests={})
    assert section["protocol_version"] is None and section["visit_protocol"]["applies"] is False
    assert section["visit_protocol"]["note"].startswith(note) and section["visit_protocol"]["stages"] == []
    country = section["conditions"]["egress_country"]
    assert country["status"] == "desconocido" and country["country"] == "desconocido" and country["country_code"] is None
    if source == "har_import":
        assert section["conditions"]["browser"] == {"name": None, "version": "no_aplica"} and section["conditions"]["browser_mode"] == "no_aplica"
    elif source == "scan":
        # Scan anterior: lo que no se registró no se inventa; la hora es la del job.
        assert section["conditions"]["browser"]["version"] == "no_disponible" and section["conditions"]["browser_mode"] == "no_disponible"
        assert section["conditions"]["measured_at"] == "2026-10-01T10:00:00+00:00"
        assert country["reason"] == "Scan anterior a v1.5.0: no se registró la IP de salida."
    else:
        assert section["conditions"]["browser_mode"] == "headful" and country["reason"] == "La consulta de la IP de salida falló."


def test_hostile_stage_data_is_revalidated():
    hostile = worker_result()
    stages = hostile["measurement"]["visit_protocol"]["stages"]
    stages[0].update(reason="<script>", started_at="ayer", completed="sí", request_seqs=[0, -1, "2", True, 10**12])
    stages[2].update(name="scroll", reached_end="sí", planned={"max_s": "8", "evil": 1}, includes=["<b>", "consent_scenario"])
    del stages[4]
    hostile["measurement"]["browser"]["version"] = "153<script>"
    hostile["measurement"]["browser_mode"] = "cualquiera"
    hostile["measurement"]["egress_country"] = {"status": "ok", "country_code": "chile", "country": "Chile"}
    section = measurement.section(hostile, "scan", started_at=None, analysis=ANALYSIS, requests={})
    first = section["visit_protocol"]["stages"][0]
    assert first["completed"] is False and first["reason"] is None and first["reason_text"] == "no_disponible"
    assert first["started_at"] is None and first["request_seqs"] == [0]
    scroll = section["visit_protocol"]["stages"][2]
    assert scroll["reached_end"] is None and scroll["planned"] == {} and scroll["includes"] == ["incluye el escenario de consentimiento del Privacy Test"]
    # Una etapa que falta consta como no completada.
    assert section["visit_protocol"]["stages"][4]["completed"] is False and len(section["visit_protocol"]["stages"]) == 5
    assert section["conditions"]["browser"]["version"] == "no_disponible" and section["conditions"]["browser_mode"] == "no_disponible"
    assert section["conditions"]["egress_country"]["status"] == "desconocido"


def test_country_is_never_inferred_from_locale():
    # Sin consulta registrada, aunque el navegador esté en es-CL, el país es «desconocido».
    result = worker_result()
    del result["measurement"]["egress_country"]
    result["locale"] = "es-CL"
    country = measurement.section(result, "scan", started_at=None, analysis=ANALYSIS, requests={})["conditions"]["egress_country"]
    assert country["status"] == "desconocido" and country["country_code"] is None


def test_mixed_protocols_notice():
    assert measurement.mixed_protocols([1, 1, 1]) == {"versions": [1], "mixed": False, "note": None}
    mixed = measurement.mixed_protocols([1, None, 2, 1])
    assert mixed["versions"] == [None, 1, 2] and mixed["mixed"] is True
    assert "sin protocolo, 1, 2" in mixed["note"] and "no al sitio" in mixed["note"]
    assert measurement.mixed_protocols([])["mixed"] is False


def test_compare_with_a_har_always_mixes_protocols():
    assert compare_protocol(1)["mixed"] is True and "protocolo de visita 1" in compare_protocol(1)["note"]
    assert "anterior a v1.5.0" in compare_protocol(None)["note"] and "navegación libre del usuario" in compare_protocol(None)["note"]


def test_html_report_shows_conditions_protocol_and_coverage():
    section = measurement.section(worker_result(), "scan", started_at=None, analysis=ANALYSIS,
                                  requests={3: {"seq": 3, "method": "POST", "host": "t.example", "path": "/bye/<x>", "resource_type": "ping"}})
    report = {"scan": {"url": "https://v150.example/", "final_url": "https://v150.example/"}, "site": {}, "capture": {}, "analysis": {},
              "measurement": section, "limitations": measurement.coverage_limitations()}
    html = render_scan_report(report, "0" * 64)
    assert "Condiciones de la medición" in html and "Chromium 153.0.8010.12" in html and "headful" in html
    assert "Chile (CL)" in html and "2026-10-18 12:00:00 UTC" in html and "protocolo de visita 1" in html
    assert "Cierre de la pestaña" in html and "no garantiza capturar todos los beacons de salida" in html
    assert "Dedicated worker" in html and "Service worker" in html and "&lt;x&gt;" in html and "<x>" not in html


# --- reporte, Panel y comparación con la base de datos ---


async def _insert(job_id, url, result, *, source=None, score=50, requests=()):
    async with SessionLocal() as db:
        db.add(Job(id=job_id, url=url, status="completed", analysis_status="completed",
                   options={"source": source} if source else None, result=result))
        await db.flush()
        await db.execute(
            text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                 "VALUES (:job, '1.17.0', 'abc123', CAST(:lists AS jsonb), :score, 'Moderado', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 10)"),
            {"job": job_id, "score": score, "lists": json.dumps(ANALYSIS["lists"]),
             "summary": json.dumps({"requests": len(requests), "trackers": 0, "source": source or "scan", "blocking": {"blocked": False}, "entities": []})})
        for item in requests:
            db.add(item)
        await db.commit()


async def _delete(ids):
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": list(ids)})
        await db.commit()


@pytest.mark.needs_stack
def test_report_has_measurement_and_validates(client):
    job_id = uuid.uuid4()
    requests = [_request(job_id, seq) for seq in range(3)] + [
        _request(job_id, 3, method="POST", path="/bye/a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", resource_type="ping", url="http://site.example/bye")]
    client.portal.call(partial(_insert, job_id, "https://v150-report.example/", worker_result(), requests=requests))
    try:
        response = client.get(f"/api/scans/{job_id}/report")
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["schema_version"] == "1.11.0" and not list(report_validator().iter_errors(report))
        section = report["measurement"]
        assert section["protocol_version"] == 1 and section["conditions"]["egress_country"]["country_code"] == "CL"
        assert section["visit_protocol"]["closing_sends"] == [
            {"seq": 3, "method": "POST", "host": "site.example", "path": "/bye/a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", "resource_type": "ping"}]
        assert any("Service workers" in item for item in report["limitations"])
        masked = mask_report(report)
        assert "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e" not in masked["measurement"]["visit_protocol"]["closing_sends"][0]["path"]
    finally:
        client.portal.call(_delete, [job_id])


def test_panel_warns_when_ranking_mixes_protocols(client, monkeypatch):
    monkeypatch.setattr(panel_routes, "TOP_SITES", 10_000)
    ids = [uuid.uuid4(), uuid.uuid4()]
    client.portal.call(partial(_insert, ids[0], "https://v150-new.example/", worker_result(), score=60))
    client.portal.call(partial(_insert, ids[1], "https://v150-old.example/", {"final_url": "https://v150-old.example/"}, score=40))
    try:
        panel = client.get("/api/panel?include_tests=true").json()
        ranked = {item["job_id"]: item for item in panel["ranking"]}
        assert ranked[str(ids[0])]["protocol_version"] == 1 and ranked[str(ids[1])]["protocol_version"] is None
        assert panel["ranking_protocols"]["mixed"] is True and None in panel["ranking_protocols"]["versions"]
        assert "no al sitio" in panel["ranking_protocols"]["note"]
    finally:
        client.portal.call(_delete, ids)


def test_compare_reports_the_scan_protocol(client):
    scan_id, har_id = uuid.uuid4(), uuid.uuid4()
    client.portal.call(partial(_insert, scan_id, "https://v150-compare.example/", worker_result()))
    client.portal.call(partial(_insert, har_id, "https://v150-compare.example/", {"source": "har_import", "import": {}}, source="har_import"))
    try:
        response = client.get(f"/api/scans/{scan_id}/compare/{har_id}")
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["scan"]["protocol_version"] == 1 and result["protocol"]["mixed"] is True
        assert "protocolo de visita 1" in result["protocol"]["note"]
    finally:
        client.portal.call(_delete, [scan_id, har_id])
