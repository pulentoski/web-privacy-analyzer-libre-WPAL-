"""Recorre todas las vistas de un scan ya hecho y falla si alguna no carga.

    docker compose exec e2e python check_views.py <job_id> <prefijo-capturas>

Sirve para comprobar la interfaz con datos reales (p. ej. un scan de un sitio de noticias)
y para generar capturas de pantalla en /tmp/screenshots.
"""

import pathlib
import sys

from playwright.sync_api import expect, sync_playwright

from tests.conftest import BASE_URL, CSP_HOOK, Session

job_id, prefix = sys.argv[1], sys.argv[2]
shots = pathlib.Path("/tmp/screenshots")
shots.mkdir(exist_ok=True)

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    context = browser.new_context(viewport={"width": 1366, "height": 900}, locale="es-CL")
    context.add_init_script(CSP_HOOK)
    session = Session(context.new_page())
    page = session.page
    page.set_default_timeout(30_000)
    summary = {}

    def view(name, route, test_id, full_page=True):
        session.goto(f"#/scan/{job_id}{route}")
        expect(page.get_by_test_id(test_id)).to_be_visible()
        page.wait_for_timeout(600)
        assert page.get_by_test_id("error").count() == 0, f"{name}: la vista muestra un error"
        session.assert_clean(name)
        page.screenshot(path=str(shots / f"{prefix}-{name}.png"), full_page=full_page)

    view("dashboard", "", "dashboard")
    summary["exposición"] = page.get_by_test_id("exposure-score").inner_text()
    for card in ("trackers", "third", "orgs", "fp", "exfil", "leaks"):
        summary[card] = page.get_by_test_id(f"card-{card}").locator(".text-3xl").inner_text()
    summary["nodos del grafo"] = page.get_by_test_id("graph").locator("g[data-kind]").count()
    view("requests", "/requests?sort=-score", "requests-table")
    summary["requests"] = page.get_by_test_id("requests-total").inner_text()
    summary["render tabla (ms)"] = page.get_by_test_id("render-ms").inner_text()
    page.get_by_test_id("request-link").first.click()
    expect(page.get_by_test_id("request-detail")).to_be_visible()
    summary["frase técnica de la request"] = page.get_by_test_id("request-summary").get_by_test_id("request-plain").locator(".bubble-text").inner_text()
    session.open_tech()
    page.wait_for_timeout(400)
    session.assert_clean("detalle")
    summary["razones en el detalle"] = page.get_by_test_id("reasons").locator("tbody tr").count()
    page.screenshot(path=str(shots / f"{prefix}-detalle-request.png"), full_page=True)
    view("trackers", "/trackers", "trackers")
    summary["grupos de trackers"] = page.get_by_test_id("tracker-group").count()
    view("fingerprinting", "/fingerprinting", "fingerprinting")
    summary["scripts con llamadas"] = page.get_by_test_id("fp-script").count()
    summary["scripts con FP inferido"] = page.locator("[data-testid=fp-script][data-inferred=true]").count()
    view("hallazgos", "/findings", "findings")
    summary["hallazgos"] = page.get_by_test_id("finding").count()
    # «Hallazgos por grupo»: los siete pasos, con su conteo (None = paso fijo).
    session.open_all("story-detail")
    steps = page.get_by_test_id("story-step").all()
    assert len(steps) == 7, f"se esperaban 7 pasos, hay {len(steps)}"
    summary["pasos"] = {
        step.get_by_test_id("story-title").inner_text(): (int(step.get_by_test_id("story-count").inner_text()) if step.get_by_test_id("story-count").count() else None)
        for step in steps
    }
    summary["frases de los pasos"] = [node.locator(".bubble-text").inner_text() for node in page.get_by_test_id("story-sentence").all()]
    page.wait_for_timeout(300)
    session.assert_clean("hallazgos por grupo")
    page.screenshot(path=str(shots / f"{prefix}-hallazgos-por-grupo.png"), full_page=True)
    page.get_by_test_id("presentation-toggle").click()
    page.set_viewport_size({"width": 1920, "height": 1080})
    view("modo-presentacion", "", "dashboard", full_page=False)
    browser.close()

print("VISTAS OK", job_id, summary)
