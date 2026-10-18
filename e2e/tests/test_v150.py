"""v1.5.0 (docs/adr/038): un scan real del sitio de fixtures sigue el protocolo de visita completo; el Resumen muestra
las condiciones de la medición (navegador, modo, país de la IP de salida) y cada etapa, y «Límites de la medición» la
tabla de cobertura por contexto. El HTML exportado lleva lo mismo."""

from playwright.sync_api import expect

from .conftest import ensure_scan
from .test_reports import download
from .test_v12 import assert_wording, get_json

PAGE = "http://site.fixtures.test/v150/scroll/"


def test_summary_shows_conditions_protocol_and_coverage(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v150", PAGE)
    report = get_json(session.page, f"/api/scans/{job_id}/report")
    section = report["measurement"]
    assert section["protocol_version"] == 1
    assert [stage["completed"] for stage in section["visit_protocol"]["stages"]] == [True] * 5
    assert section["conditions"]["browser"]["name"] == "Chromium" and section["conditions"]["browser_mode"] == "headful"
    # El stack de pruebas consulta la IP de salida al sitio de fixtures (8.8.8.8, geolocalizada con DB-IP).
    assert section["conditions"]["egress_country"]["country_code"] == "US"
    assert "8.8.8.8" not in str(report)

    session.goto(f"#/scan/{job_id}")
    page = session.page
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    expect(page.get_by_test_id("measurement-browser")).to_contain_text("Chromium")
    expect(page.get_by_test_id("measurement-mode")).to_have_text("con ventana (headful)")
    expect(page.get_by_test_id("measurement-country")).to_contain_text("(US)")
    stages = page.get_by_test_id("visit-stage")
    expect(stages).to_have_count(5)
    expect(page.locator("[data-testid=visit-stage][data-completed=true]")).to_have_count(5)
    expect(page.get_by_test_id("closing-notice")).to_contain_text("no garantiza capturar todos los beacons de salida")

    page.get_by_test_id("limits-toggle").click()
    rows = page.get_by_test_id("coverage-row")
    expect(rows).to_have_count(5)
    expect(page.locator("[data-testid=coverage-row][data-context=service_worker]")).to_contain_text("Service workernoningunano")
    expect(page.get_by_test_id("limits-content")).to_contain_text("Dedicated workers: la instrumentación no se instala")
    assert_wording(session, "Resumen con condiciones de la medición")
    session.assert_clean("Resumen v1.5.0")


def test_html_report_has_conditions_protocol_and_coverage(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v150", PAGE)
    session.goto(f"#/scan/{job_id}")
    expect(session.page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
    _, body = download(session.page, "download-html")
    html = body.decode("utf-8")
    assert "Condiciones de la medición" in html and "Protocolo de visita 1" in html
    assert "Cobertura por contexto" in html and "no garantiza capturar todos los beacons de salida" in html
    assert "país de la IP de salida: US" in html
