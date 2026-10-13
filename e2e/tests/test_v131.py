"""v1.3.1 — botón visible para elegir el HAR, índice parcial del HAR (Historial, Resumen, Panel,
comparación) e imagen del Historial."""

import re

from playwright.sync_api import expect

from . import har_fixture
from .conftest import BASE_URL, ensure_scan
from .test_v13 import CSP, FIXTURE, HAR_FILE, SHOTS, har_job  # noqa: F401  (fixture de módulo)

PARTIAL = "índice parcial (sin cookies ni fingerprinting)"


def test_har_picker_is_a_visible_button_usable_by_keyboard_in_every_mode(session):
    page = session.page
    session.goto("#/analyze")
    choose, submit, name = page.get_by_test_id("har-choose"), page.get_by_test_id("har-submit"), page.get_by_test_id("har-file-name")
    # Desde el inicio: botón propio, nombre vacío y «Importar y analizar» visible pero deshabilitado.
    expect(choose).to_be_visible()
    expect(choose).to_have_text("Seleccionar archivo .har")
    expect(name).to_have_text("Ningún archivo seleccionado")
    expect(submit).to_be_visible()
    expect(submit).to_have_text("Importar y analizar")
    expect(submit).to_be_disabled()
    expect(page.get_by_test_id("har-file")).to_be_hidden()  # el selector nativo (texto plano) ya no se muestra
    assert page.get_by_test_id("har-file").get_attribute("accept") == ".har,application/json"
    looks = lambda: choose.evaluate("""(b) => { const s = getComputedStyle(b), r = b.getBoundingClientRect();
      return {tag: b.tagName, border: parseFloat(s.borderTopWidth), style: s.borderTopStyle, cursor: s.cursor, height: r.height, width: r.width}; }""")  # noqa: E731
    SHOTS.mkdir(parents=True, exist_ok=True)
    for theme in ("purple", "classic"):
        session.set_theme(theme)
        expect(choose).to_be_visible()
        expect(submit).to_be_visible()
        look = looks()
        assert look["tag"] == "BUTTON" and look["border"] >= 1 and look["style"] == "solid" and look["cursor"] == "pointer" and look["height"] >= 24, (theme, look)
        page.get_by_test_id("har-import").screenshot(path=str(SHOTS / f"har-boton-{theme}.png"))
    page.get_by_test_id("presentation-toggle").click()
    expect(choose).to_be_visible()
    expect(submit).to_be_visible()
    assert looks()["border"] >= 1
    page.get_by_test_id("har-import").screenshot(path=str(SHOTS / "har-boton-presentacion.png"))
    page.get_by_test_id("presentation-toggle").click()
    # Teclado: el botón recibe foco y Enter abre el selector de archivos.
    choose.focus()
    assert page.evaluate("document.activeElement.dataset.testid") == "har-choose"
    with page.expect_file_chooser() as chooser:
        page.keyboard.press("Enter")
    chooser.value.set_files(HAR_FILE)
    expect(name).to_have_text("sintetico.har")
    expect(page.get_by_test_id("har-inspection")).to_be_visible()
    expect(submit).to_be_enabled()
    # Un archivo inválido deja el botón de importar visible y deshabilitado; el nombre es texto.
    page.get_by_test_id("har-file").set_input_files({"name": "<img src=x onerror=window.__XSS=1>.har", "mimeType": "application/json", "buffer": b"no es json"})
    expect(name).to_contain_text("<img src=x")
    expect(submit).to_be_disabled()
    session.assert_clean("selector de HAR")


def test_har_index_is_shown_as_partial_and_left_out_of_the_ranking(session, har_job):  # noqa: F811
    page = session.page
    # Resumen del HAR importado.
    session.goto(f"#/scan/{har_job}")
    expect(page.get_by_test_id("exposure-partial")).to_contain_text("Índice parcial (sin cookies ni fingerprinting)")
    # Historial.
    session.goto("#/history")
    row = page.locator("tr", has=page.get_by_test_id("history-har")).first
    expect(row.get_by_test_id("partial-index")).to_contain_text(PARTIAL)
    # Panel: fuera del ranking, listado aparte con su índice parcial.
    # (El host del HAR sintético es .example: el Panel solo lo muestra en el stack de pruebas, con ?fixtures=1.)
    panel = page.request.get(f"{BASE_URL}/api/panel?include_tests=true").json()
    assert har_job not in {item["job_id"] for item in panel["ranking"]}
    assert har_job in {item["job_id"] for item in panel["partial_sites"]}
    session.goto("#/?fixtures=1")
    partial = page.get_by_test_id("panel-partial-sites")
    expect(partial).to_contain_text(PARTIAL)
    expect(partial.get_by_test_id("panel-partial-item").filter(has_text="tienda-sintetica.example")).to_have_count(1)
    expect(page.get_by_test_id("panel-ranking-item").filter(has_text="tienda-sintetica.example")).to_have_count(0)
    # Reporte HTML.
    assert page.request.post(f"{BASE_URL}/api/scans/{har_job}/export").ok
    html = page.request.get(f"{BASE_URL}/api/scans/{har_job}/export/html").text()
    assert "Índice parcial (sin cookies ni fingerprinting):" in html and "Índice de exposición estimado" not in html
    session.assert_clean("índice parcial")


def test_comparison_uses_tracking_requests_and_organizations_not_the_index(session, shared, browser, har_job):  # noqa: F811
    page = session.page
    scan_job = ensure_scan(shared, browser, "fixture", FIXTURE)
    result = page.request.get(f"{BASE_URL}/api/scans/{scan_job}/compare/{har_job}").json()
    assert isinstance(result["tracking"]["har"]["trackers"], int) and isinstance(result["tracking"]["scan"]["trackers"], int)
    session.goto(f"#/scan/{scan_job}")
    page.get_by_test_id("compare-toggle").click()
    page.get_by_test_id("compare-select").select_option(har_job)
    page.get_by_test_id("compare-run").click()
    expect(page.get_by_test_id("compare-trackers-har")).to_have_text(str(result["tracking"]["har"]["trackers"]))
    expect(page.get_by_test_id("compare-trackers-scan")).to_have_text(str(result["tracking"]["scan"]["trackers"]))
    expect(page.get_by_test_id("compare-index-note")).to_contain_text("El índice de exposición no se compara")
    expect(page.get_by_test_id("compare-conclusion")).to_contain_text(re.compile(r"Requests de rastreo: \d+ en el HAR y \d+ en el scan\."))
    session.assert_clean("comparación sin índice")


def test_history_image_is_local_optimised_and_readable_in_every_mode(session):
    page = session.page
    session.goto("#/history")
    image = page.locator("[data-testid=history-art] img")
    expect(image).to_be_visible()
    page.wait_for_function("document.querySelector('[data-testid=history-art] img').naturalWidth > 0")
    state = lambda: image.evaluate("""(img) => ({src: new URL(img.currentSrc || img.src).pathname, origin: new URL(img.currentSrc || img.src).origin === location.origin,
      natural: img.naturalWidth, width: img.getBoundingClientRect().width, background: getComputedStyle(img).backgroundColor, radius: getComputedStyle(img).borderTopLeftRadius})""")  # noqa: E731
    normal = state()
    assert normal["src"] in ("/historial-720.webp", "/historial-720.jpg") and normal["origin"] and normal["natural"] == 720 and normal["width"] >= 170, normal
    assert normal["background"] == "rgb(255, 255, 255)"
    assert "Historial" in image.get_attribute("alt")
    SHOTS.mkdir(parents=True, exist_ok=True)
    for theme in ("purple", "classic"):
        session.set_theme(theme)
        expect(image).to_be_visible()
        assert state()["background"] == "rgb(255, 255, 255)" and state()["natural"] == 720
        assert state()["radius"] == "50%", f"marco circular en {theme}"
        page.screenshot(path=str(SHOTS / f"historial-imagen-{theme}.png"))
    page.get_by_test_id("presentation-toggle").click()
    expect(image).to_be_visible()
    assert state()["width"] > normal["width"]
    page.screenshot(path=str(SHOTS / "historial-imagen-presentacion.png"))
    page.get_by_test_id("presentation-toggle").click()
    for path, magic, limit in (("/historial-720.webp", b"RIFF", 70_000), ("/historial-720.jpg", b"\xff\xd8", 110_000)):
        response = page.request.get(f"{BASE_URL}{path}")
        assert response.ok and response.headers["content-type"].startswith("image/") and response.body()[: len(magic)] == magic, path
        assert len(response.body()) < limit, f"{path}: {len(response.body())} bytes"
    assert page.request.get(f"{BASE_URL}/").headers["content-security-policy"] == CSP
    session.assert_clean("imagen del Historial")
