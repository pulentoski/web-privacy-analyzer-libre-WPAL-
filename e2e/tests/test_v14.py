"""v1.4: captura interactiva (noVNC real contra el Chromium del worker) e indicador de recursos."""

import json
import re

from playwright.sync_api import expect

from .conftest import BASE_URL, CSP_HOOK, Session

SITE = "http://site.fixtures.test/"
XSS_PAGE = "http://site.fixtures.test/xss/"
HOSTILE = '<img src=x onerror="window.__XSS=1">'


def api(page, path):
    return page.request.get(f"{BASE_URL}{path}").json()


def canvas_colors(page):
    """Cuántos colores distintos hay en la pantalla remota (un canvas vacío tiene uno solo)."""
    return page.evaluate(
        """() => {
            const canvas = document.querySelector('[data-testid=vnc-screen] canvas');
            if (!canvas || !canvas.width) return 0;
            const data = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
            const seen = new Set();
            for (let i = 0; i < data.length; i += 4 * 97) seen.add((data[i] << 16) | (data[i + 1] << 8) | data[i + 2]);
            return seen.size;
        }"""
    )


# --- indicador de recursos ---


def test_resource_indicator_on_every_page_with_detail(session):
    page = session.page
    for path in ("#/", "#/analyze", "#/history", "#/glossary", "#/exposure"):
        session.goto(path)
        indicator = page.get_by_test_id("resources")
        expect(indicator).to_be_visible()
        expect(page.get_by_test_id("resources-memory")).to_have_text(re.compile(r"RAM\s*\d"))
        expect(page.get_by_test_id("resources-scans")).to_have_text(re.compile(r"SCANS\s*\d+\s*INTERACTIVA: NO"))
        expect(page.get_by_test_id("resources-interactive")).to_have_attribute("data-active", "false")
    # La CPU es una diferencia entre dos muestras: aparece con la segunda lectura.
    expect(page.get_by_test_id("resources-cpu")).to_have_text(re.compile(r"CPU\s*\d+(,\d)? %"), timeout=15_000)
    expect(indicator).to_have_attribute("data-alert", "false")
    expect(page.get_by_test_id("resources-detail")).to_have_count(0)
    page.get_by_test_id("resources-toggle").click()
    rows = page.get_by_test_id("resources-row")
    expect(rows).to_have_count(5)
    assert [row.get_attribute("data-service") for row in rows.all()] == ["frontend", "api", "worker", "db", "egress-proxy"]
    for row in rows.all():
        expect(row).to_contain_text(re.compile(r"\d+ MB de \d"))
    page.get_by_test_id("resources-toggle").click()
    expect(page.get_by_test_id("resources-detail")).to_have_count(0)
    session.assert_clean("indicador de recursos")


def test_resource_indicator_polls_every_5s_only_while_visible(session):
    page = session.page
    calls = []
    page.on("request", lambda request: calls.append(request.url) if request.url.endswith("/api/resources") else None)
    session.goto("#/glossary")
    expect(page.get_by_test_id("resources")).to_be_visible()
    page.wait_for_timeout(11_000)
    assert 2 <= len(calls) <= 4, f"se esperaban ~3 consultas en 11 s, hubo {len(calls)}"
    # Pestaña oculta: el sondeo se detiene.
    page.evaluate("() => { Object.defineProperty(document, 'visibilityState', {value: 'hidden', configurable: true}); document.dispatchEvent(new Event('visibilitychange')); }")
    hidden_at = len(calls)
    page.wait_for_timeout(11_000)
    assert len(calls) == hidden_at, "el indicador siguió consultando con la pestaña oculta"
    # Visible otra vez: consulta de inmediato y retoma el intervalo.
    page.evaluate("() => { Object.defineProperty(document, 'visibilityState', {value: 'visible', configurable: true}); document.dispatchEvent(new Event('visibilitychange')); }")
    page.wait_for_timeout(1_500)
    assert len(calls) == hidden_at + 1


def test_resource_indicator_warns_above_85_percent_and_renders_text_only(session):
    page = session.page
    real = api(page, "/api/resources")
    worker = next(item for item in real["services"] if item["service"] == "worker")
    worker.update(memory_bytes=int(worker["memory_limit_bytes"] * 0.9), memory_percent=90.0, alert=True)
    # Un nombre de servicio hostil no puede llegar desde la api (lista fija), pero la vista igual lo trata como texto.
    real["services"].append({**worker, "service": HOSTILE, "alert": True})
    real["alerts"] = [{"service": "worker", "memory_percent": 90.0}, {"service": HOSTILE, "memory_percent": 90.0}]
    page.route("**/api/resources", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(real)))
    session.goto("#/")
    expect(page.get_by_test_id("resources")).to_have_attribute("data-alert", "true")
    expect(page.get_by_test_id("resources-alert")).to_contain_text("ALERTA")
    expect(page.get_by_test_id("resources-alert")).to_contain_text("RAM sobre 85 % del límite: worker")
    page.get_by_test_id("resources-toggle").click()
    row = page.locator("[data-testid=resources-row][data-service=worker]")
    expect(row).to_have_attribute("data-alert", "true")
    expect(row).to_contain_text("90 % ⚠")
    expect(page.get_by_test_id("resources-detail")).to_contain_text("<img src=x onerror=")
    page.wait_for_timeout(300)
    session.assert_clean("indicador con aviso y nombre hostil")


def test_resource_indicator_hides_missing_data_instead_of_inventing_it(session):
    page = session.page
    real = api(page, "/api/resources")
    real["services"][0].update(status="no_disponible", cpu_percent=None, memory_bytes=None, memory_percent=None, pids=None)
    real["totals"].update(cpu_percent=None, services_reporting=4)
    page.route("**/api/resources", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(real)))
    session.goto("#/")
    expect(page.get_by_test_id("resources-cpu")).to_have_text(re.compile(r"CPU\s*—"))
    page.get_by_test_id("resources-toggle").click()
    expect(page.locator("[data-testid=resources-row][data-service=frontend]")).to_contain_text("no disponible")
    expect(page.get_by_test_id("resources-detail")).to_contain_text("Informan 4 de 5 contenedores")


# --- captura interactiva ---


def test_interactive_capture_end_to_end_with_hostile_page(session, browser):
    page = session.page
    session.goto("#/analyze")
    expect(page.get_by_test_id("interactive-warning")).to_contain_text("No inicie sesión con cuentas reales si va a compartir el reporte")
    # Sin URL válida no se inicia nada.
    page.get_by_test_id("interactive-start").click()
    expect(page.get_by_test_id("interactive-problem")).to_be_visible()
    page.fill("#url", SITE)
    page.get_by_test_id("interactive-start").click()
    job_id = None
    try:
        expect(page.get_by_test_id("interactive-session")).to_have_attribute("data-state", "ready", timeout=60_000)
        job_id = api(page, "/api/interactive")["session"]["job_id"]
        # noVNC conectado a través de nginx (127.0.0.1) → api → VNC del worker, con la CSP de producción.
        expect(page.get_by_test_id("vnc-state")).to_have_attribute("data-state", "connected", timeout=30_000)
        canvas = page.locator("[data-testid=vnc-screen] canvas")
        expect(canvas).to_be_visible()
        page.wait_for_function("() => { const c = document.querySelector('[data-testid=vnc-screen] canvas'); return c && c.width >= 1000; }", timeout=15_000)
        page.wait_for_timeout(2_000)
        assert canvas_colors(page) > 3, "la pantalla remota está vacía"
        session.assert_clean("visor de la captura interactiva")
        expect(page.get_by_test_id("interactive-remaining")).to_have_text(re.compile(r"^(29|30):\d\d$"))
        expect(page.get_by_test_id("interactive-idle")).to_have_text(re.compile(r"^(9|10):\d\d$"))
        expect(page.get_by_test_id("resources-interactive")).to_have_attribute("data-active", "true", timeout=12_000)

        # Otra ventana del mismo equipo ve que hay una sesión, pero no la pantalla (no tiene el token).
        other = browser.new_context(viewport={"width": 1366, "height": 900})
        other.add_init_script(CSP_HOOK)
        observer = Session(other.new_page())
        observer.goto("#/analyze")
        expect(observer.page.get_by_test_id("interactive-elsewhere")).to_be_visible(timeout=15_000)
        expect(observer.page.get_by_test_id("vnc-screen")).to_have_count(0)
        expect(observer.page.get_by_test_id("interactive-start")).to_have_count(0)  # una sesión a la vez
        other.close()

        # El usuario navega con teclado y ratón reales por el visor: barra de direcciones → página hostil.
        before = api(page, "/api/interactive")["session"]["requests"]
        canvas.scroll_into_view_if_needed()
        box = canvas.bounding_box()
        page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        page.keyboard.press("Control+l")
        page.wait_for_timeout(500)
        page.keyboard.type(XSS_PAGE, delay=60)
        page.keyboard.press("Enter")
        page.wait_for_function(
            "async (before) => { const s = (await (await fetch('/api/interactive')).json()).session; return s && s.requests > before; }",
            arg=before, timeout=30_000, polling=1000,
        )
        page.wait_for_timeout(3_000)
        session.assert_clean("visor tras navegar a la página hostil")

        page.get_by_test_id("interactive-stop").click()
        # Al cerrarse la sesión la interfaz pasa sola a la página del scan.
        page.wait_for_url(re.compile(rf"#/scan/{job_id}"), timeout=60_000)
        assert session.wait_finished() == "done"
        expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
        banner = page.get_by_test_id("interactive-banner")
        expect(banner).to_contain_text("Captura interactiva")
        expect(page.get_by_test_id("interactive-end")).to_have_text("detenida por el usuario")
        rows = page.get_by_test_id("interactive-timeline-row")
        assert rows.count() >= 2
        expect(rows.first).to_contain_text(SITE)
        expect(page.get_by_test_id("interactive-timeline")).to_contain_text(XSS_PAGE)
        # El título de la página hostil llega a la línea de tiempo como texto.
        expect(page.get_by_test_id("interactive-timeline")).to_contain_text("<img src=x onerror=")
        expect(page.get_by_test_id("scan-title")).to_contain_text("<script>window.__XSS=1</script>")
        expect(page.get_by_test_id("interactive-masked")).to_contain_text("No se detectaron campos de contraseña")
        page.wait_for_timeout(300)
        session.assert_clean("resumen de la captura interactiva")
        for theme in ("purple", "classic"):
            session.set_theme(theme)
            session.assert_clean(f"resumen de la captura interactiva ({theme})")

        report = api(page, f"/api/scans/{job_id}/report")
        assert report["scan"]["source"] == "interactive" and report["fingerprinting"]["instrumented"] is True
        urls = [entry["url"] for entry in report["scan"]["interactive"]["timeline"]]
        assert urls[0] == SITE and XSS_PAGE in urls
        # Mismo analizador: los requests de la página hostil están en la captura con su análisis.
        assert report["capture"]["total_requests"] > 20 and report["site"]["exposure_score"] is not None

        session.goto("#/history")
        row = page.get_by_test_id("recent-row").filter(has=page.get_by_test_id("history-interactive")).first
        expect(row.get_by_test_id("history-interactive")).to_contain_text("captura interactiva")
        page.wait_for_timeout(300)
        session.assert_clean("historial con la captura interactiva")
        # v1.4.1: en el Panel la captura interactiva va fuera del ranking por índice, aparte y marcada.
        panel = api(page, "/api/panel?include_tests=true")
        assert job_id not in {item["job_id"] for item in panel["ranking"]}
        assert {"job_id": job_id, "source": "interactive"}.items() <= next(item for item in panel["partial_sites"] if item["job_id"] == job_id).items()
        session.goto("#/?fixtures=1")
        apart = page.locator("[data-testid=panel-partial-item][data-source=interactive]").filter(has_text="site.fixtures.test")
        expect(apart).to_have_count(1)
        expect(apart.get_by_test_id("panel-interactive-index")).to_contain_text("captura interactiva")
        expect(page.get_by_test_id("panel-ranking-item").filter(has_text="site.fixtures.test")).to_have_count(0)
        session.assert_clean("panel con la captura interactiva aparte")
        # Recursos liberados: no queda sesión y se puede iniciar otra.
        assert api(page, "/api/interactive")["session"] is None
        session.goto("#/analyze")
        expect(page.get_by_test_id("interactive-start")).to_be_enabled()
        expect(page.get_by_test_id("resources-interactive")).to_have_attribute("data-active", "false", timeout=12_000)
    finally:
        active = api(page, "/api/interactive")["session"]
        if active:
            page.request.post(f"{BASE_URL}/api/interactive/{active['job_id']}/stop")
            page.wait_for_function("async () => !(await (await fetch('/api/interactive')).json()).session", timeout=60_000, polling=1000)


def test_interactive_start_rejects_internal_targets_in_the_ui(session):
    page = session.page
    session.goto("#/analyze")
    for target in ("http://169.254.169.254/latest/meta-data/", "http://db:5432/", "http://127.0.0.1:8000/"):
        page.fill("#url", target)
        page.get_by_test_id("interactive-start").click()
        expect(page.get_by_test_id("interactive").get_by_role("alert")).to_be_visible()
        expect(page.get_by_test_id("interactive-session")).to_have_count(0)
    assert api(page, "/api/interactive")["session"] is None
