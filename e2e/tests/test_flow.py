"""Flujo completo: scan → progreso → dashboard → tabla → detalle → hallazgo → evidencia → export."""

import json
import pathlib
import re

from playwright.sync_api import expect

from .conftest import BASE_URL, ensure_scan

FIXTURE = "http://site.fixtures.test/"
FP_PAGE = "http://site.fixtures.test/fp/article?ref=campaign42"
FLOOD = "http://site.fixtures.test/flood"
SHOTS = pathlib.Path("/tmp/screenshots")


def shot(page, name):
    SHOTS.mkdir(exist_ok=True)
    page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)


def test_home_shows_system_status_and_recent_scans(session):
    """v1.2: el estado del sistema está en «Analizar un sitio» y la lista de scans en «Historial»."""
    session.goto("#/analyze")
    health = session.page.get_by_test_id("health")
    expect(health).to_contain_text("operativo")
    expect(health).to_contain_text("Worker: activo")
    session.goto("#/history")
    expect(session.page.get_by_test_id("recent")).to_be_visible()
    session.assert_clean("inicio")


def test_client_side_validation(session):
    session.goto("#/analyze")
    for value, message in (("", "Escriba una URL"), ("ejemplo.cl", "http://"), ("javascript:alert(1)", "http://"), ("https://example.com:8443", "puertos")):
        session.page.fill("#url", value)
        session.page.click("button[type=submit]")
        expect(session.page.get_by_test_id("field-error")).to_contain_text(message)
    assert "#/scan/" not in session.page.url


def test_forbidden_url_shows_a_clear_error(session):
    """La URL pasa la validación del cliente; el servidor la rechaza y el error se ve."""
    session.goto("#/analyze")
    session.page.fill("#url", "http://169.254.169.254/latest/meta-data/")
    session.page.click("button[type=submit]")
    error = session.page.get_by_test_id("error")
    expect(error).to_be_visible()
    expect(error).to_contain_text("rango prohibido")
    expect(error).to_contain_text("IP_FORBIDDEN")
    assert "#/scan/" not in session.page.url
    session.assert_clean("url prohibida")


def test_full_flow(session):
    page = session.page
    # --- scan y progreso ---
    job_id = session.start_scan(FIXTURE)
    progress = page.get_by_test_id("progress")
    expect(progress).to_be_visible()
    seen = set()
    # Etapa y paso resaltado se leen en la misma instantánea del DOM (la página se actualiza sola).
    snapshot = """() => {
      const stage = document.querySelector('[data-testid=scan-stage]');
      const current = document.querySelector('[data-testid=progress] [data-state=current]');
      const requests = document.querySelector('[data-testid=progress-requests]');
      const max = document.querySelector('[data-testid=progress-max]');
      const progress = document.querySelector('[data-testid=progress]');
      return {stage: stage ? stage.dataset.stage : null, current: current ? current.dataset.testid : null,
              requests: requests ? requests.textContent : null, max: max ? max.textContent : null, text: progress ? progress.textContent : ''};
    }"""
    counts = []
    for _ in range(600):
        state = page.evaluate(snapshot)
        stage = state["stage"]
        seen.add(stage)
        if state["requests"] is not None:
            counts.append((stage, int(state["requests"])))
        if stage in ("done", "failed"):
            break
        if state["current"]:
            assert state["current"] == f"stage-{stage}"
        if stage == "capturing":
            # Tiempo real frente al máximo configurado (SCAN_TIMEOUT_S), sin porcentajes.
            assert state["max"] == "90" and "%" not in state["text"], state
        page.wait_for_timeout(100)
    order = ["queued", "opening", "capturing", "analyzing", "building", "done"]
    assert "done" in seen and seen <= set(order), seen
    # Criterio 2: al menos 3 etapas distintas observadas durante el scan del fixture.
    assert len(seen) >= 3 and "capturing" in seen, f"etapas observadas: {seen}"
    # El contador es el de requests realmente capturadas: nunca baja y termina en las 21 del fixture.
    values = [count for _, count in counts]
    assert values and values == sorted(values) and values[-1] == 21, counts
    print(f"\nPROGRESO etapas observadas: {[stage for stage in order if stage in seen]} | contador de requests: {sorted(set(values))}")

    # --- dashboard ---
    expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
    # v1.2: el bloque de limitaciones queda plegado («Límites de la medición»).
    limits = page.get_by_test_id("limits-notice")
    expect(limits.locator("summary")).to_have_text("Límites de la medición")
    expect(page.get_by_test_id("limits-content")).to_be_hidden()
    limits.locator("summary").click()
    expect(page.get_by_test_id("limits-content")).to_be_visible()
    expect(limits).to_contain_text("no significa que no salgan datos")
    limits.locator("summary").click()
    score = int(page.get_by_test_id("exposure-score").inner_text())
    assert 1 <= score <= 99
    expect(page.get_by_test_id("card-exposure")).to_contain_text("Dominios de terceros con tracking")
    assert int(page.get_by_test_id("card-trackers").locator(".text-3xl").inner_text()) >= 10
    assert int(page.get_by_test_id("card-third").locator(".text-3xl").inner_text()) == 2
    assert int(page.get_by_test_id("card-leaks").locator(".text-3xl").inner_text()) >= 1
    for chart in ("chart-category", "chart-org"):
        expect(page.get_by_test_id(chart).locator("svg.recharts-surface").first).to_be_visible()
    graph = page.get_by_test_id("graph")
    expect(graph).to_contain_text("tracker-a.fixtures.test")
    assert graph.locator("g[data-kind=tracker]").count() == 2 and graph.locator("g[data-kind=firstParty]").count() == 1
    expect(page.get_by_test_id("data-categories")).to_contain_text("Observado")
    shot(page, "dashboard")

    # --- tabla ---
    page.get_by_test_id("tab-requests").click()
    expect(page.get_by_test_id("requests-total")).to_have_text("21")
    page.get_by_test_id("filter-band").select_option("Muy alto")
    expect(page.get_by_test_id("requests-total")).to_have_text("3")
    page.get_by_test_id("filter-band").select_option("")
    page.get_by_test_id("filter-third").select_option("false")
    expect(page.get_by_test_id("requests-total")).to_have_text("7")
    page.get_by_test_id("filter-third").select_option("")
    page.get_by_test_id("filter-mechanism").select_option("beacon")
    expect(page.get_by_test_id("requests-total")).to_have_text("1")
    page.get_by_test_id("filter-mechanism").select_option("")
    page.get_by_test_id("filter-domain").fill("cdn-b")
    page.get_by_test_id("filter-domain").press("Enter")
    expect(page.get_by_test_id("requests-total")).to_have_text("5")
    page.get_by_test_id("filter-domain").fill("")
    page.get_by_test_id("filter-domain").press("Enter")
    expect(page.get_by_test_id("requests-total")).to_have_text("21")
    page.get_by_test_id("sort-score").click()
    page.get_by_test_id("sort-score").click()  # descendente
    expect(page.get_by_test_id("request-row").first).to_contain_text("100 · Muy alto")

    # --- detalle ---
    page.get_by_test_id("filter-domain").fill("tracker-a")
    page.get_by_test_id("filter-domain").press("Enter")
    page.get_by_test_id("request-row").filter(has_text="pixel.gif?uid=").get_by_test_id("request-link").click()
    detail = page.get_by_test_id("request-detail")
    # Primero la frase técnica, con su nivel; el detalle técnico queda a un clic.
    plain = page.get_by_test_id("request-summary").get_by_test_id("request-plain")
    expect(plain).to_be_visible()
    expect(plain.locator("[data-level]")).to_be_visible()
    assert len(plain.locator(".bubble-text").inner_text()) > 25
    expect(page.get_by_test_id("request-tech-content")).to_have_count(0)
    expect(page.get_by_test_id("reasons")).to_have_count(0)
    session.open_tech()
    expect(detail).to_contain_text("pixel.gif?uid=")
    expect(detail).to_contain_text("tercero")
    expect(detail).to_contain_text("tracker-a.fixtures.test/tracker.js")  # initiator
    reasons = page.get_by_test_id("reasons")
    expect(reasons.locator("[data-level=EVIDENCIA]").first).to_be_visible()
    expect(reasons.locator("[data-level=INFERENCIA]").first).to_be_visible()
    assert "título" not in (reasons.locator("[data-level=EVIDENCIA]").first.get_attribute("title") or "x")
    assert len(reasons.locator("[data-level=EVIDENCIA]").first.get_attribute("title")) > 30
    expect(page.get_by_test_id("parameters")).to_contain_text("identity")
    expect(page.get_by_test_id("cookies")).to_be_visible()
    shot(page, "detalle-request")

    # --- hallazgo relacionado → evidencia ---
    page.get_by_test_id("related-finding").first.click()
    focused = page.get_by_test_id("finding-focused")
    expect(focused).to_be_visible()
    expect(focused.get_by_test_id("finding-plain")).to_be_visible()
    expect(focused.locator(".badge[data-level]")).to_be_visible()
    page.get_by_test_id("level-EVIDENCIA").click()
    expect(page.locator("[data-testid=finding] [data-level=INFERENCIA]")).to_have_count(0)
    assert page.get_by_test_id("finding").count() >= 4
    page.get_by_test_id("level-all").click()
    expect(page.locator("[data-testid=finding] [data-level=INFERENCIA]").first).to_be_visible()
    first_ref = page.get_by_test_id("finding").first.get_by_test_id("ref-request").first
    ref_id = first_ref.inner_text().lstrip("#")
    first_ref.click()
    expect(page.get_by_test_id("request-detail")).to_be_visible()
    assert page.url.endswith(f"/request/{ref_id}")
    # Quien ya abrió un detalle técnico lo sigue viendo abierto en la siguiente request.
    expect(page.get_by_test_id("request-tech-content")).to_be_visible()

    # --- decodificaciones (POST con Base64 de JSON) ---
    page.goto(f"{BASE_URL}/#/scan/{job_id}/requests?domain=tracker-a&mechanism=fetch%2Fxhr")
    page.get_by_test_id("request-link").first.click()
    session.open_tech()
    expect(page.get_by_test_id("decodings")).to_contain_text("base64 → json")
    expect(page.get_by_test_id("decodings")).to_contain_text("usr-7f3a9c21d4")

    # --- trackers ---
    page.get_by_test_id("tab-trackers").click()
    groups = page.get_by_test_id("tracker-group")
    expect(groups).to_have_count(2)
    groups.first.locator("summary").first.click()
    for summary in groups.first.locator("[data-testid=tracker-bundle] > summary").all():  # v1.4.2: requests del mismo tipo en una fila
        summary.click()
    expect(groups.first.get_by_test_id("tracker-plain").first).to_be_visible()
    expect(groups.first.locator("[data-level]").first).to_be_visible()

    # --- export ---
    with page.expect_download() as download:
        page.get_by_test_id("export").click()
    report = json.loads(pathlib.Path(download.value.path()).read_text())
    assert download.value.suggested_filename == f"reporte-{job_id}.json"
    assert report["schema_version"] == "1.11.0" and report["scan"]["job_id"] == job_id
    assert report["site"]["exposure_score"] == score
    session.assert_clean("flujo completo")


def test_fingerprinting_view_and_navigable_evidence(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    session.goto(f"#/scan/{job_id}/fingerprinting")
    expect(page.get_by_test_id("fingerprinting")).to_be_visible()
    assert page.locator("[data-testid=fp-script][data-inferred=true]").count() == 3
    assert page.locator("[data-testid=fp-script][data-inferred=false]").count() == 2
    fp_script = page.get_by_test_id("fp-script").filter(has_text="tracker-a.fixtures.test/fp.js")
    expect(fp_script).to_contain_text("canvas.toDataURL")
    assert fp_script.get_by_test_id("fp-heuristic").count() == 5
    expect(page.get_by_test_id("fp-attributes")).to_contain_text("Observado en una request")
    exfiltrations = page.get_by_test_id("exfiltration")
    assert exfiltrations.count() >= 2
    expect(exfiltrations.first.get_by_test_id("exfiltration-plain")).to_contain_text("Exfiltración de atributos: un script leyó")
    expect(exfiltrations.first.locator(".badge[data-level=EVIDENCIA]").first).to_be_visible()
    shot(page, "fingerprinting")
    # evidence_refs navegables: a la llamada...
    call = exfiltrations.first.get_by_test_id("ref-call").first
    call_id = call.inner_text().lstrip("#")
    call.click()
    highlighted = page.get_by_test_id("call-highlighted")
    expect(highlighted).to_be_visible()
    expect(highlighted).to_contain_text(call_id)
    # ...y a la request.
    page.get_by_test_id("exfiltration").first.get_by_test_id("ref-request").first.click()
    session.open_tech()
    expect(page.get_by_test_id("request-detail")).to_contain_text("fp-collect.gif")
    expect(page.get_by_test_id("request-detail")).to_contain_text("Solo el origen del sitio")  # Referer
    session.assert_clean("fingerprinting")


def test_presentation_mode(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    size = lambda: page.evaluate("parseFloat(getComputedStyle(document.documentElement).fontSize)")  # noqa: E731
    normal = size()
    page.get_by_test_id("presentation-toggle").click()
    assert page.evaluate("document.documentElement.classList.contains('presentation')")
    assert size() >= normal * 1.3
    assert page.evaluate("getComputedStyle(document.body).color") == "rgb(0, 0, 0)"
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(255, 255, 255)"
    page.set_viewport_size({"width": 1920, "height": 1080})
    shot(page, "modo-presentacion")
    # Se recuerda al recargar y se puede salir.
    page.reload()
    assert page.evaluate("document.documentElement.classList.contains('presentation')")
    page.get_by_test_id("presentation-toggle").click()
    assert not page.evaluate("document.documentElement.classList.contains('presentation')")
    session.assert_clean("modo presentación")


def test_flood_table_is_navigable(session, shared, browser):
    """1500 requests: paginación en el servidor, el navegador nunca recibe más de 200 filas."""
    job_id = ensure_scan(shared, browser, "flood", FLOOD)
    page = session.page
    session.goto(f"#/scan/{job_id}/requests?page_size=200")
    expect(page.get_by_test_id("requests-total")).to_have_text("1500")
    expect(page.get_by_test_id("page-count")).to_have_text("8")
    expect(page.get_by_test_id("request-row")).to_have_count(200)
    times = [int(page.get_by_test_id("render-ms").inner_text())]
    for expected in ("2", "3"):
        page.get_by_test_id("page-next").click()
        expect(page.get_by_test_id("page-current")).to_have_text(expected)
        expect(page.get_by_test_id("request-row").first).to_be_visible()
        times.append(int(page.get_by_test_id("render-ms").inner_text()))
    page.get_by_test_id("page-last").click()
    expect(page.get_by_test_id("page-current")).to_have_text("8")
    expect(page.get_by_test_id("request-row")).to_have_count(100)
    page.get_by_test_id("sort-time").click()
    # El hilo principal responde enseguida: la página no quedó bloqueada.
    started = page.evaluate("performance.now()")
    page.evaluate("new Promise((resolve) => requestAnimationFrame(() => resolve()))")
    frame_ms = page.evaluate("performance.now()") - started
    print(f"\nFLOOD render de 200 filas (ms): {times} | un frame tras ordenar: {frame_ms:.0f} ms")
    assert max(times) < 1500 and frame_ms < 1000
    session.assert_clean("flood")
