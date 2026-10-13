"""v1.3 — Importar HAR (navegador real del usuario), exportar HAR, comparar scan vs HAR, imagen de
«Analizar un sitio» y título del Panel. El HAR es sintético (har_fixture.py): trae cookies,
bloqueos por extensión, un término de búsqueda, dos páginas y payloads XSS."""

import pathlib
import re

import pytest
from playwright.sync_api import expect

from . import har_fixture
from .conftest import BASE_URL, CSP_HOOK, SCAN_TIMEOUT_MS, Session, ensure_scan

FIXTURE = "http://site.fixtures.test/"
SHOTS = pathlib.Path("/tmp/screenshots")
HAR_FILE = {"name": "sintetico.har", "mimeType": "application/json", "buffer": har_fixture.as_bytes()}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.ipify.org; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def import_har(session):
    """Sube el HAR sintético desde «Analizar un sitio» y devuelve el job_id cuando termina el análisis."""
    page = session.page
    session.goto("#/analyze")
    page.get_by_test_id("har-file").set_input_files(HAR_FILE)
    expect(page.get_by_test_id("har-inspection")).to_be_visible()
    page.get_by_test_id("har-submit").click()
    expect(page.get_by_test_id("scan-url")).to_be_visible(timeout=15_000)
    job_id = re.search(r"#/scan/([0-9a-f-]{36})", page.url).group(1)
    assert session.wait_finished() == "done"
    expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=SCAN_TIMEOUT_MS)
    return job_id


@pytest.fixture(scope="module")
def har_job(browser):
    """El HAR sintético importado una vez para el módulo; se borra al terminar (su sitio es de pruebas
    y no debe quedar como un «sitio» más en el Panel de las demás suites)."""
    context = browser.new_context(viewport={"width": 1366, "height": 900}, locale="es-CL")
    context.add_init_script(CSP_HOOK)
    session = Session(context.new_page())
    session.page.set_default_timeout(20_000)
    job_id = import_har(session)
    session.assert_clean("importar HAR")
    yield job_id
    assert session.page.request.delete(f"{BASE_URL}/api/scans/{job_id}").ok
    context.close()


def test_import_shows_loads_sensitive_warning_and_default_selection(session):
    page = session.page
    session.goto("#/analyze")
    panel = page.get_by_test_id("har-import")
    expect(panel).to_contain_text("Importar archivo HAR")
    expect(panel).to_contain_text("Máximo 50 MB")
    expect(page.get_by_test_id("har-source-note")).to_contain_text("Captura importada: navegador real del usuario.")
    expect(page.get_by_test_id("har-source-note")).to_contain_text("sin fingerprinting instrumentado")
    page.get_by_test_id("har-file").set_input_files(HAR_FILE)
    rows = page.get_by_test_id("har-load")
    expect(rows).to_have_count(3)
    # Varias cargas: por defecto la que tiene documento y más requests; se puede elegir otra.
    selected = page.locator("[data-testid=har-load][data-selected=true]")
    expect(selected).to_have_attribute("data-load", "page:0")
    expect(selected).to_contain_text("2026-01-15 10:00:00 UTC")
    cells = selected.locator("td").all_inner_texts()
    assert cells[3] == "12" and cells[4] == "2" and "pageref" in cells[5], cells
    expect(page.locator("[data-testid=har-load][data-load='time:0']")).to_contain_text("sin página: agrupadas por tiempo")
    page.get_by_test_id("har-load-page:1").check()
    expect(page.locator("[data-testid=har-load][data-selected=true]")).to_have_attribute("data-load", "page:1")
    # Cookie, Set-Cookie y Authorization: se advierte y se dice que se descartan.
    warning = page.get_by_test_id("har-sensitive")
    expect(warning).to_have_attribute("data-sensitive", "true")
    expect(warning).to_contain_text("Cookie: 2 · Set-Cookie: 1 · Authorization: 1")
    expect(warning).to_contain_text("descartan antes de guardar")
    body = page.locator("body").inner_text()
    assert not any(secret in body for secret in har_fixture.SECRETS)
    # El título de la página 2 y el creador son payloads XSS: se ven como texto.
    assert har_fixture.XSS in body
    session.assert_clean("inspección del HAR")


def test_invalid_or_oversized_file_is_rejected_with_a_message(session):
    page = session.page
    session.goto("#/analyze")
    page.get_by_test_id("har-file").set_input_files({"name": "roto.har", "mimeType": "application/json", "buffer": b"<script>alert('har-xss')</script>"})
    expect(page.locator("[data-testid=har-import] [role=alert]")).to_contain_text("JSON válido")
    expect(page.get_by_test_id("har-submit")).to_be_disabled()  # v1.3.1: visible desde el inicio, deshabilitado
    response = page.request.post(f"{BASE_URL}/api/har/inspect", data=b"x" * (51 * 1024 * 1024), headers={"Content-Type": "application/json"})
    assert response.status == 413
    session.assert_clean("HAR inválido")


def test_imported_har_goes_through_the_same_analyzer(session, har_job):
    page = session.page
    job_id = har_job
    session.goto(f"#/scan/{job_id}")
    banner = page.get_by_test_id("har-banner")
    expect(banner).to_contain_text("Captura importada: navegador real del usuario.")
    expect(banner).to_contain_text("Sin fingerprinting instrumentado")
    expect(page.get_by_test_id("har-blocked")).to_have_text("2 bloqueadas por una extensión del navegador")
    expect(page.get_by_test_id("har-removed")).to_contain_text("Cookie 2, Set-Cookie 1, Authorization 1")
    expect(page.get_by_test_id("card-blocked-client")).to_contain_text("2")
    report = page.request.get(f"{BASE_URL}/api/scans/{job_id}/report").json()
    assert report["scan"]["source"] == "har_import" and report["capture"]["total_requests"] == 12 and report["capture"]["blocked_by_client"] == 2
    assert report["fingerprinting"]["instrumented"] is False
    kinds = {finding["type"]: finding for finding in report["findings"]}
    leak = kinds["search_leak"]
    assert leak["level"] == "EVIDENCIA" and leak["evidence_refs"] and leak["details"]["term"] == har_fixture.SEARCH_TERM
    assert leak["details"]["host"] == "stats.medidor-uno.example" and leak["plain"].startswith("Fuga de búsqueda:")
    wave = report["site"]["summary"]["sync_wave"]
    assert wave["detected"] and wave["requests"] == 5 and wave["initiator"] == "frame.syncer-uno.example"
    assert kinds["sync_wave"]["level"] == "EVIDENCIA"
    # Nada sensible llegó a guardarse: ni en el reporte ni en ninguna request.
    everything = page.request.get(f"{BASE_URL}/api/scans/{job_id}/report").text()
    items = page.request.get(f"{BASE_URL}/api/scans/{job_id}/requests?page_size=100").json()["items"]
    for item in items:
        everything += page.request.get(f"{BASE_URL}/api/scans/{job_id}/requests/{item['request_id']}").text()
    assert not any(secret in everything for secret in har_fixture.SECRETS) and "CUERPO-DE-RESPUESTA" not in everything
    # Hallazgos: la fuga de búsqueda se ve en la interfaz.
    session.goto(f"#/scan/{job_id}/findings")
    expect(page.locator("body")).to_contain_text("Fuga de búsqueda: el término de búsqueda «zapatillas rojas» se envió a stats.medidor-uno.example")
    # Tabla de requests: bloqueos por extensión nombrados aparte.
    session.goto(f"#/scan/{job_id}/requests")
    expect(page.locator("body")).to_contain_text("bloqueada por una extensión del navegador")
    # Detalle del documento: la cabecera Cookie conserva el nombre y el largo, no el valor.
    document = next(item for item in items if item["resource_type"] == "document")
    session.goto(f"#/scan/{job_id}/request/{document['request_id']}")
    expect(page.get_by_test_id("request-detail")).to_be_visible()
    session.open_tech()
    redacted = page.get_by_test_id("header-redacted")
    expect(redacted.first).to_contain_text(f"valor descartado al importar ({len(har_fixture.SECRET_COOKIE)} caracteres)")
    # Payloads XSS de cabeceras: texto, sin ejecutarse.
    expect(page.locator("body")).to_contain_text(har_fixture.XSS_SCRIPT)
    session.assert_clean("scan importado")
    # Historial: se distingue de un scan.
    session.goto("#/history")
    expect(page.get_by_test_id("history-har").first).to_contain_text("captura importada (HAR)")
    session.assert_clean("historial")


def test_scan_can_be_downloaded_as_har_without_cookies(session, shared, browser):
    page = session.page
    job_id = ensure_scan(shared, browser, "fixture", FIXTURE)
    session.goto(f"#/scan/{job_id}")
    link = page.get_by_test_id("export-har")
    expect(link).to_have_text("Descargar HAR")
    with page.expect_download() as download:
        link.click()
    assert download.value.suggested_filename == f"scan-{job_id}.har"
    response = page.request.get(f"{BASE_URL}/api/scans/{job_id}/har")
    assert response.ok and response.headers["content-type"].startswith("application/json")
    log = response.json()["log"]
    assert log["version"] == "1.2" and len(log["entries"]) > 3 and "sin las cabeceras Cookie" in log["comment"]
    names = {header["name"].lower() for entry in log["entries"] for side in ("request", "response") for header in entry[side]["headers"]}
    assert not names & {"cookie", "set-cookie", "authorization"} and "user-agent" in names
    # Se puede reimportar: mismo formato.
    again = page.request.post(f"{BASE_URL}/api/har/inspect", data=response.body(), headers={"Content-Type": "application/json"})
    assert again.ok and again.json()["loads"][0]["requests"] == len(log["entries"])
    session.assert_clean("exportar HAR")


def test_compare_scan_with_imported_har(session, shared, browser, har_job):
    page = session.page
    scan_job = ensure_scan(shared, browser, "fixture", FIXTURE)
    session.goto(f"#/scan/{scan_job}")
    toggle = page.get_by_test_id("compare-toggle")
    expect(toggle).to_have_text("Comparar con HAR importado")
    toggle.click()
    page.get_by_test_id("compare-select").select_option(har_job)
    page.get_by_test_id("compare-run").click()
    result = page.get_by_test_id("compare-result")
    expect(result).to_be_visible()
    conclusion = page.get_by_test_id("compare-conclusion").inner_text()
    assert "\n" not in conclusion.strip()
    assert "ola de sincronización (5 requests a 5 organizaciones, iniciada por frame.syncer-uno.example) que el scan automatizado no observó" in conclusion
    assert "Una extensión del navegador bloqueó 2 requests en el HAR." in conclusion
    expect(page.get_by_test_id("compare-wave")).to_have_attribute("data-state", "only_har")
    expect(page.get_by_test_id("compare-only-har")).to_contain_text("medidor-uno.example")
    expect(page.get_by_test_id("compare-blocked")).to_contain_text("bloqueado-uno.example")
    expect(page.get_by_test_id("compare-blocked")).to_contain_text("(2)")
    data = page.request.get(f"{BASE_URL}/api/scans/{scan_job}/compare/{har_job}").json()
    assert data["sync_wave"]["state"] == "only_har" and data["conclusion"]["level"] == "EVIDENCIA"
    only_har = {item["organization"] for item in data["organizations"]["only_har"]}
    assert {"medidor-uno.example", "socio-a.example"} <= only_har and not only_har & {item["organization"] for item in data["organizations"]["only_scan"]}
    SHOTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(SHOTS / "comparar-scan-har.png"), full_page=True)
    session.assert_clean("comparación")
    # Desde el HAR importado, el botón compara contra un scan.
    session.goto(f"#/scan/{har_job}")
    expect(page.get_by_test_id("compare-toggle")).to_have_text("Comparar con un scan")
    session.assert_clean("comparación desde el HAR")


def test_analyze_image_is_local_optimised_and_readable_in_every_mode(session):
    page = session.page
    session.goto("#/analyze")
    image = page.locator("[data-testid=analyze-art] img")
    expect(image).to_be_visible()
    state = lambda: image.evaluate("""(img) => ({src: new URL(img.currentSrc || img.src).pathname, origin: new URL(img.currentSrc || img.src).origin === location.origin,
      natural: img.naturalWidth, width: img.getBoundingClientRect().width, background: getComputedStyle(img).backgroundColor, radius: getComputedStyle(img).borderTopLeftRadius,
      formLeft: document.querySelector('#url').getBoundingClientRect().left, left: img.getBoundingClientRect().left,
      top: img.getBoundingClientRect().top, formTop: document.querySelector('#url').getBoundingClientRect().top})""")  # noqa: E731
    page.wait_for_function("document.querySelector('[data-testid=analyze-art] img').naturalWidth > 0")
    normal = state()
    assert normal["src"] in ("/analizar-720.webp", "/analizar-720.jpg") and normal["origin"] and normal["natural"] == 720, normal
    # Junto al formulario (a su derecha, a la misma altura), sobre fondo blanco propio.
    assert normal["left"] > normal["formLeft"] and abs(normal["top"] - normal["formTop"]) < 120 and normal["width"] >= 200, normal
    assert normal["background"] == "rgb(255, 255, 255)"
    for theme in ("purple", "classic"):
        session.set_theme(theme)
        expect(image).to_be_visible()
        assert state()["background"] == "rgb(255, 255, 255)" and state()["natural"] == 720
        assert state()["radius"] == "50%", f"marco circular en {theme}"
        SHOTS.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(SHOTS / f"analizar-imagen-{theme}.png"))
    page.get_by_test_id("presentation-toggle").click()
    expect(image).to_be_visible()
    assert state()["width"] > normal["width"]
    page.screenshot(path=str(SHOTS / "analizar-imagen-presentacion.png"))
    page.get_by_test_id("presentation-toggle").click()
    for path, magic, limit in (("/analizar-720.webp", b"RIFF", 60_000), ("/analizar-720.jpg", b"\xff\xd8", 100_000)):
        response = page.request.get(f"{BASE_URL}{path}")
        assert response.ok and response.headers["content-type"].startswith("image/") and response.body()[: len(magic)] == magic, path
        assert len(response.body()) < limit, f"{path}: {len(response.body())} bytes"
    assert page.request.get(f"{BASE_URL}/").headers["content-security-policy"] == CSP
    session.assert_clean("imagen de Analizar")


def test_panel_has_the_new_title_and_subtitle(session):
    page = session.page
    session.goto("")
    expect(page.get_by_test_id("panel-heading")).to_have_text("Panel de recolección de datos")
    expect(page.get_by_test_id("panel-heading-subtitle")).to_have_text("Métodos, destinos y organizaciones observados en los sitios analizados")
    assert "Cómo recopilan información" not in page.locator("body").inner_text()
    session.assert_clean("panel")
