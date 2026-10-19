"""v1.4.5: «Servicios de terceros sin señales de rastreo» en Rastreadores, Resumen y reportes; hallazgo de varias
cuentas de analítica y nota de servicio descontinuado; un recuadro que no carga no deja rastro de la página de error
del navegador; nada de lo capturado se ejecuta y la redacción se mantiene."""

import re

from playwright.sync_api import expect

from .conftest import ensure_scan
from .test_reports import download
from .test_v12 import assert_wording, get_json

PAGE = "http://site.fixtures.test/v145/"
ACCOUNTS = ["G-FIXTAAA111", "G-FIXTBBB222", "UA-1234567-1"]


def test_third_party_services_in_trackers_and_summary(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v145", PAGE)
    report = get_json(session.page, f"/api/scans/{job_id}/report")
    services = report["site"]["summary"]["third_party_services"]
    row = next(item for item in services["items"] if "cdn-b.fixtures.test" in item["hosts"])
    assert row["requests"] == 3 and row["organization"] == "no_disponible" and row["service_label"] is None and row["evidence_refs"]
    assert services["level"] == "EVIDENCIA"

    session.goto(f"#/scan/{job_id}/trackers")
    panel = session.page.get_by_test_id("third-party-services")
    expect(panel).to_be_visible()
    expect(panel).to_contain_text("Servicios de terceros sin señales de rastreo")
    service = panel.locator("[data-testid=third-party-service]", has_text="cdn-b.fixtures.test")
    expect(service).to_have_count(1)
    expect(service.get_by_test_id("third-party-service-org")).to_have_text("Organización no disponible")
    expect(service.get_by_test_id("service-type")).to_have_text("tipo no identificado")
    # La evidencia lleva a la request.
    service.get_by_test_id("third-party-service-ref").first.click()
    expect(session.page).to_have_url(re.compile(rf"#/scan/{job_id}/request/\d+"))
    session.assert_clean("servicios de terceros → request")

    session.goto(f"#/scan/{job_id}")
    expect(session.page.get_by_test_id("dashboard")).to_be_visible()
    # v1.6.0: en el Resumen los servicios van plegados al final.
    session.page.get_by_test_id("fold-services").locator("summary").click()
    summary = session.page.get_by_test_id("third-party-services")
    expect(summary).to_be_visible()
    expect(summary.locator("[data-testid=third-party-service]", has_text="cdn-b.fixtures.test")).to_have_count(1)
    assert_wording(session, "Resumen con servicios de terceros")
    session.assert_clean("Resumen")


def test_several_analytics_accounts_and_discontinued_tag(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v145", PAGE)
    report = get_json(session.page, f"/api/scans/{job_id}/report")
    by_type = {finding["type"]: finding for finding in report["findings"]}
    accounts, note = by_type["analytics_accounts"], by_type["discontinued_tag"]
    assert accounts["level"] == "EVIDENCIA" and accounts["evidence_refs"] and accounts["details"]["accounts"] == ACCOUNTS
    assert accounts["claim"].startswith("Los datos de la visita se enviaron a 3 cuentas de Google Analytics")
    assert accounts["plain"].startswith("Varias cuentas de analítica: los datos de la visita se enviaron a 3 cuentas de Google Analytics")
    assert note["level"] == "EVIDENCIA" and note["evidence_refs"] and note["details"]["accounts"] == ["UA-1234567-1"]
    assert note["plain"].startswith("Etiqueta de un servicio descontinuado: el sitio aún carga 1 etiqueta de Universal Analytics")
    assert report["site"]["summary"]["analytics_accounts"][0]["discontinued"] == ["UA-1234567-1"]

    session.goto(f"#/scan/{job_id}/findings")
    body = session.page.locator("body")
    expect(body).to_contain_text("los datos de la visita se enviaron a 3 cuentas de Google Analytics")
    expect(body).to_contain_text("Etiqueta de un servicio descontinuado")
    assert_wording(session, "Hallazgos con varias cuentas")
    session.assert_clean("Hallazgos")


def test_a_frame_that_does_not_load_leaves_no_browser_error_page_behind(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v145", PAGE)
    fingerprinting = get_json(session.page, f"/api/scans/{job_id}/fingerprinting")
    assert "chrome-error" not in repr(fingerprinting["scripts"]) and "chrome-error" not in repr(fingerprinting["calls"])
    assert "chrome-error" not in repr(fingerprinting["browser_attributes"])
    report = get_json(session.page, f"/api/scans/{job_id}/report")
    assert "chrome-error" not in repr(report["findings"]) and "chrome-error" not in repr(report["story"])
    frames = report["site"]["summary"]["error_frames"]
    assert frames["observed"] is True and frames["ignored_messages"] >= 1 and frames["ignored_calls"] == 0

    session.goto(f"#/scan/{job_id}/fingerprinting")
    expect(session.page.get_by_test_id("fp-intro")).to_be_visible()
    expect(session.page.locator("body")).not_to_contain_text("chrome-error")
    note = session.page.get_by_test_id("fp-error-frame")
    expect(note).to_contain_text("Un recuadro (iframe) de la página no cargó")
    assert_wording(session, "Fingerprinting con un recuadro que no carga")
    session.assert_clean("Fingerprinting")


def test_html_report_has_the_section(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v145", PAGE)
    session.goto(f"#/scan/{job_id}")
    expect(session.page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
    _, html_bytes = download(session.page, "download-html")
    html = html_bytes.decode("utf-8")
    assert "Servicios de terceros sin señales de rastreo" in html and "cdn-b.fixtures.test" in html
    assert "Los datos de la visita se enviaron a 3 cuentas de Google Analytics" in html
    assert "chrome-error" not in html and "<script" not in html.lower()
