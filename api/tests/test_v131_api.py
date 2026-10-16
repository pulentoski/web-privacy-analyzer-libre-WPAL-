"""v1.3.1 — limpieza de URL (AliExpress), índice parcial del HAR y comparación sin índice."""

import json
import uuid

import pytest
from sqlalchemy import text

from app.db import SessionLocal
from app.models import Job
from app.report_html import BLOCKING_BANNER, PARTIAL_BLOCK_BANNER, PARTIAL_INDEX_LABEL, _blocking_banner, _telemetry_section, executive_summary
from app.routes.har import compare_sides
from app.url_cleaning import clean_url, is_tracking_param

# --- 3. Limpieza de URL ---


@pytest.mark.parametrize("name", ["algo_pvid", "algo_exp_id", "pdp_npi", "pdp_ext_f", "utparam", "gatewayAdapt"])
def test_aliexpress_tracking_parameters_are_removed(name):
    assert is_tracking_param(name)
    cleaned, removed = clean_url(f"https://es.aliexpress.com/item/1005012085176766.html?sku=7&{name}=abc")
    assert cleaned == "https://es.aliexpress.com/item/1005012085176766.html?sku=7" and removed == [name.lower()]


def test_real_item_url_is_reduced_to_the_item():
    url = ("https://es.aliexpress.com/item/1005012085176766.html?spm=a2g0o.home.1.2&algo_pvid=c543f21e-14&algo_exp_id=c543f21e-0"
           "&pdp_npi=6%40dis%21CLP%211&pdp_ext_f=%7B%22order%22%3A%221%22%7D&utparam-url=scene%3Asearch&utparam=x&gatewayAdapt=glo2esp")
    cleaned, removed = clean_url(url)
    # utparam-url no está en la lista: no se quita por parecerse a utparam.
    assert cleaned == "https://es.aliexpress.com/item/1005012085176766.html?utparam-url=scene%3Asearch"
    assert removed == ["spm", "algo_pvid", "algo_exp_id", "pdp_npi", "pdp_ext_f", "utparam", "gatewayadapt"]


# --- 2. Índice parcial del HAR ---


def _report(source):
    return {"scan": {"source": source, "url": "https://tienda.example/", "final_url": "https://tienda.example/"},
            "site": {"exposure_score": 49, "band": "Alto", "summary": {}}, "capture": {"requests": 10, "third_party": 2}}


def test_executive_summary_calls_the_har_index_partial():
    har = " ".join(executive_summary(_report("har_import"))["found"])
    assert "Índice parcial (sin cookies ni fingerprinting): 49 de 99" in har and "no es comparable con el índice de un scan" in har
    assert "Índice de exposición estimado" not in har
    scan = " ".join(executive_summary(_report("scan"))["found"])
    assert "Índice de exposición estimado: 49 de 99" in scan and PARTIAL_INDEX_LABEL not in scan.lower()


@pytest.fixture()
def panel_jobs(client):
    """Dos sitios: uno con scan y otro cuyo único registro es un HAR importado (índice más alto)."""
    ids = {"scan": uuid.uuid4(), "har_import": uuid.uuid4()}

    async def insert():
        async with SessionLocal() as session:
            for source, job_id in ids.items():
                session.add(Job(id=job_id, url=f"https://v131-{source.replace('_', '-')}.example/", status="completed", analysis_status="completed",
                                options={"source": source} if source == "har_import" else None, result={"source": source}))
                await session.flush()
                await session.execute(
                    text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                         "VALUES (:job, '1.8.0', 'abc', '[]', :score, 'Alto', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 10)"),
                    {"job": job_id, "score": 98 if source == "scan" else 99,
                     "summary": json.dumps({"requests": 10, "trackers": 3, "source": source, "blocking": {"blocked": False}})},
                )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": list(ids.values())})
            await session.commit()

    client.portal.call(insert)
    yield {key: str(value) for key, value in ids.items()}
    client.portal.call(cleanup)


def test_panel_ranking_excludes_har_imports_and_lists_them_as_partial(client, panel_jobs):
    # Los hosts .example son de pruebas: el Panel solo los muestra con include_tests (stack de pruebas).
    panel = client.get("/api/panel?include_tests=true").json()
    ranked = {item["job_id"] for item in panel["ranking"]}
    assert panel_jobs["scan"] in ranked and panel_jobs["har_import"] not in ranked
    partial = [item for item in panel["partial_sites"] if item["job_id"] == panel_jobs["har_import"]]
    assert partial == [{"site": "v131-har-import.example", "job_id": panel_jobs["har_import"], "site_exposure_score": 99, "band": "Alto", "source": "har_import"}]
    assert panel["totals"]["partial_sites"] == len(panel["partial_sites"]) >= 1
    listing = {item["job_id"]: item for item in client.get("/api/scans?limit=100").json()["items"]}
    assert listing[panel_jobs["har_import"]]["source"] == "har_import" and listing[panel_jobs["scan"]]["source"] == "scan"


# --- 2. Comparación: requests de rastreo y organizaciones, no el índice ---

WAVE = {"available": True, "detected": False, "requests": 0, "organizations": 0, "initiator": None, "domains": []}


def _side(source, trackers, organizations, blocked=False):
    return {"job_id": "x", "url": "https://tienda.example/", "source": source, "analyzer_version": "1.9.0", "finished_at": None, "requests": 100,
            "import": None, "sync_wave": WAVE, "trackers": trackers, "possibly_blocked": blocked,
            "organizations": {name: {"requests": 1, "blocked": 0, "domains": [name.lower()]} for name in organizations}}


def test_compare_reports_tracking_requests_and_organizations_not_the_index():
    result = compare_sides(_side("scan", 2, ["Google"], blocked=True), _side("har_import", 67, ["Google", "Criteo", "Taboola"]))
    assert result["tracking"]["scan"] == {"trackers": 2, "organizations": 1, "possibly_blocked": True}
    assert result["tracking"]["har"] == {"trackers": 67, "organizations": 3}
    assert "índice parcial (sin cookies ni fingerprinting)" in result["tracking"]["index_note"]
    conclusion = result["conclusion"]["text"]
    assert "Requests de rastreo: 67 en el HAR y 2 en el scan." in conclusion and "posiblemente bloqueada" in conclusion and "\n" not in conclusion
    assert "score" not in json.dumps(result) and "exposure" not in json.dumps(result)


def test_compare_does_not_invent_missing_tracking_counts():
    result = compare_sides(_side("scan", None, []), _side("har_import", 5, []))
    assert result["tracking"]["scan"]["trackers"] is None and "Requests de rastreo" not in result["conclusion"]["text"]


# --- v1.3.2: bloqueo parcial ---


def test_partial_block_is_informational_in_the_report():
    report = _report("scan")
    report["site"]["summary"]["blocking"] = {"blocked": False, "partial": True, "signals": [{"signal": "challenge_component", "detail": "Firma <b>punish</b>."}]}
    found = " ".join(executive_summary(report)["found"])
    assert PARTIAL_BLOCK_BANNER in found and BLOCKING_BANNER not in found
    banner = _blocking_banner(report)
    assert "Bloqueo parcial: un componente mostró verificación antibot." in banner and "&lt;b&gt;punish&lt;/b&gt;" in banner and "<b>punish" not in banner
    report["site"]["summary"]["blocking"] = {"blocked": True, "partial": False, "signals": []}
    assert BLOCKING_BANNER in " ".join(executive_summary(report)["found"]) and PARTIAL_BLOCK_BANNER not in _blocking_banner(report)


def test_partial_block_stays_in_the_ranking_and_is_listed_in_history(client, panel_jobs):
    async def mark():
        async with SessionLocal() as session:
            await session.execute(text("UPDATE site_analysis SET summary = jsonb_set(summary, '{blocking}', CAST(:b AS jsonb)) WHERE job_id = :job"),
                                  {"job": panel_jobs["scan"], "b": json.dumps({"blocked": False, "partial": True, "signals": []})})
            await session.commit()

    client.portal.call(mark)
    panel = client.get("/api/panel?include_tests=true").json()
    assert panel_jobs["scan"] in {item["job_id"] for item in panel["ranking"]} and "v131-scan.example" not in panel["blocked_sites"]
    listing = {item["job_id"]: item for item in client.get("/api/scans?limit=100").json()["items"]}
    assert listing[panel_jobs["scan"]]["partial_block"] is True and listing[panel_jobs["scan"]]["blocked"] is False


# --- v1.3.4: telemetría propia ---

TELEMETRY = {"requests": 54, "endpoints": 9, "scripts": 7, "by_kind": {"path": 16, "known": 38},
             "endpoint_list": [{"host": "api.tienda.example", "path": "/melidata/tracks/<b>x</b>", "kind": "known", "name": "Melidata (Mercado Libre)", "requests": 12}],
             "script_list": [{"host": "cdn.tienda.example", "path": "/melidata.min.js", "kind": "script", "name": "Melidata (Mercado Libre)", "requests": 1}]}


def test_report_shows_first_party_telemetry_apart_from_third_parties():
    report = _report("scan")
    report["site"]["summary"] = {"first_party_telemetry": TELEMETRY,
                                 "blocking": {"blocked": False, "partial": False, "signals": [], "note": {"signal": "low_third_party_tracking", "detail": "x"}}}
    found = " ".join(executive_summary(report)["found"])
    assert "Telemetría propia: 54 requests de eventos se enviaron al propio sitio o a su misma organización (9 endpoints); scripts de analítica propia cargados: 7." in found
    assert "No son terceros, pero sí un método de recolección." in found
    assert "Rastreo de terceros bajo; telemetría propia detectada" in found and BLOCKING_BANNER not in found
    section = _telemetry_section(report)
    assert "Telemetría propia (no son terceros)" in section and "lvl-INFERENCIA" in section and "analítica propia conocida · Melidata (Mercado Libre)" in section
    assert "&lt;b&gt;x&lt;/b&gt;" in section and "<b>x</b>" not in section
    # Sin la medición (análisis anterior) o sin telemetría: ni sección ni frase.
    empty = _report("scan")
    assert _telemetry_section(empty) == "" and "Telemetría propia" not in " ".join(executive_summary(empty)["found"])


def test_explanations_cover_the_new_findings():
    from app.explain import explanations
    explainer = explanations()
    phrase = explainer.finding_phrase({"type": "first_party_telemetry", "level": "INFERENCIA", "details": {"requests": 54, "hosts": ["api.tienda.example"]}})
    assert phrase["text"].startswith("Telemetría propia: 54 requests al propio sitio") and "es compatible con" in phrase["text"] and phrase["step"] == "navegacion"
    phrase = explainer.finding_phrase({"type": "first_party_analytics_script", "level": "EVIDENCIA", "details": {"names": ["Melidata (Mercado Libre)"]}})
    assert "Melidata (Mercado Libre)" in phrase["text"]
