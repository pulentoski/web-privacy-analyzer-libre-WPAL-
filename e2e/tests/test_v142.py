"""v1.4.2: modos de «Analizar un sitio» con su acento (contraste AA), consola de recursos, hallazgos y rastreadores
agrupados, registro de interacción (escucha, payloads y correlación en una captura interactiva real), textos coherentes."""

import json
import pathlib
import re

import pytest
from playwright.sync_api import expect

from .conftest import BASE_URL, CSP_HOOK, Session, ensure_scan
from .test_v12 import OUTSIDE_TEXT, assert_wording, get_json

INTERACT = "http://site.fixtures.test/interact/"
SHOTS = pathlib.Path("/tmp/screenshots")
MODES = {"scan": "Scan simple", "advanced": "Opciones avanzadas", "consent": "Consentimiento", "profile": "Perfil del navegador",
         "runs": "Corridas por combinación", "interactive": "Captura interactiva", "har": "Importar archivo HAR", "status": "Estado del sistema"}

# Contraste WCAG 2.x entre dos colores CSS, y fondo efectivo de un elemento (el primer ancestro con fondo opaco).
COLOR_JS = """
(() => {
  const parse = (value) => { const m = value.match(/[\\d.]+/g).map(Number); return {r: m[0], g: m[1], b: m[2], a: m.length > 3 ? m[3] : 1}; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  window.__contrast = (a, b) => { const la = lum(parse(a)), lb = lum(parse(b)); return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05); };
  window.__background = (node) => { for (let el = node; el; el = el.parentElement) { const c = getComputedStyle(el).backgroundColor; if (parse(c).a >= 0.99) return c; } return 'rgb(255, 255, 255)'; };
})();
"""
MODE_JS = """() => [...document.querySelectorAll('[data-mode]')].filter((node) => node.checkVisibility()).map((node) => {
  const title = node.querySelector(':scope > .mode-title, :scope > .panel-head .mode-title, :scope > legend.mode-title, :scope > label.mode-title, :scope > summary.mode-title');
  const style = getComputedStyle(node), titleStyle = title ? getComputedStyle(title) : null;
  const button = [...node.querySelectorAll('.btn-mode')].find((item) => item.closest('[data-mode]') === node && !item.disabled);
  const icon = title ? title.querySelector('svg') : null;
  return {
    mode: node.dataset.mode, title: title ? title.innerText.trim() : null, icon: icon ? icon.dataset.icon : null,
    accent: style.borderLeftColor, titleColor: titleStyle ? titleStyle.color : null,
    iconColor: icon ? getComputedStyle(icon).color : null,
    titleContrast: title ? window.__contrast(titleStyle.color, window.__background(title)) : 0,
    borderContrast: window.__contrast(style.borderLeftColor, window.__background(node.parentElement)),
    borderWidth: parseFloat(style.borderLeftWidth),
    buttonContrast: button ? window.__contrast(getComputedStyle(button).color, getComputedStyle(button).backgroundColor) : null,
    buttonBackground: button ? getComputedStyle(button).backgroundColor : null,
  };
})"""


def shot(page, name, locator=None):
    SHOTS.mkdir(parents=True, exist_ok=True)
    (locator or page).screenshot(path=str(SHOTS / f"{name}.png"), **({} if locator else {"full_page": True}))


# --- 11. Analizar un sitio: cada modo con su acento ---


@pytest.mark.parametrize("theme", ["classic", "purple"])
def test_each_analyze_mode_has_its_own_accent_title_and_icon_with_aa_contrast(session, theme):
    page = session.page
    session.goto("#/analyze?advanced=1")
    session.set_theme(theme)
    expect(page.get_by_test_id("mode-status")).to_be_visible()
    expect(page.get_by_test_id("profile-incoherent")).to_be_visible()
    page.evaluate(COLOR_JS)
    modes = {item["mode"]: item for item in page.evaluate(MODE_JS)}
    assert set(modes) == set(MODES), set(modes) ^ set(MODES)
    for mode, title in MODES.items():
        item = modes[mode]
        # No solo color: título propio e ícono.
        assert item["title"] and item["title"].lower().startswith(title.lower()), (mode, item["title"])  # Unidad Púrpura los pone en mayúsculas
        assert item["icon"], f"{mode}: sin ícono"
        # El acento es el mismo en borde, título e ícono.
        assert item["accent"] == item["titleColor"] == item["iconColor"], (mode, item)
        assert item["borderWidth"] >= 4
        assert item["titleContrast"] >= 4.5, f"{theme}/{mode}: título {item['titleContrast']:.2f}:1"
        assert item["borderContrast"] >= 3, f"{theme}/{mode}: borde {item['borderContrast']:.2f}:1"
    # Ocho acentos distintos.
    assert len({item["accent"] for item in modes.values()}) == 8, {mode: item["accent"] for mode, item in modes.items()}
    # Botón principal de cada modo que tiene uno: del color del modo y legible.
    page.fill("#url", "http://site.fixtures.test/")
    modes = {item["mode"]: item for item in page.evaluate(MODE_JS)}
    for mode in ("scan", "interactive"):
        assert modes[mode]["buttonBackground"] == modes[mode]["accent"], mode
        assert modes[mode]["buttonContrast"] >= 4.5, f"{theme}/{mode}: botón {modes[mode]['buttonContrast']:.2f}:1"
    # Perfil incoherente: naranja de advertencia, con texto que lo dice.
    incoherent = page.get_by_test_id("profile-incoherent")
    expect(incoherent).to_contain_text("⚠ incoherente")
    color, ratio = incoherent.evaluate("(node) => [getComputedStyle(node).color, window.__contrast(getComputedStyle(node).color, window.__background(node))]")
    assert ratio >= 4.5 and color != modes["profile"]["accent"], (color, ratio)
    # Aviso de privacidad de la captura interactiva: franja de advertencia.
    warning = page.get_by_test_id("interactive-warning")
    assert "repeating-linear-gradient" in warning.evaluate("(node) => getComputedStyle(node).backgroundImage")
    assert warning.evaluate("(node) => window.__contrast(getComputedStyle(node).color, window.__background(node))") >= 4.5
    # Los acentos salen de tokens CSS (un solo lugar): cambiar el token cambia el modo.
    page.evaluate("document.documentElement.style.setProperty('--acc-har', 'rgb(1, 2, 3)')")
    assert page.locator("[data-mode=har]").evaluate("(node) => getComputedStyle(node).borderLeftColor") == "rgb(1, 2, 3)"
    page.evaluate("document.documentElement.style.removeProperty('--acc-har')")
    page.wait_for_timeout(200)
    assert page.evaluate(OUTSIDE_TEXT) == []
    session.assert_clean(f"analizar ({theme})")
    assert_wording(session, f"analizar ({theme})")
    page.fill("#url", "")
    page.set_viewport_size({"width": 1366, "height": 900})
    shot(page, f"v142-analizar-{theme}")


# --- 12. indicador: consola de mando ---


def console_state(page):
    return page.evaluate("""() => {
      const root = document.querySelector('[data-testid=resources]');
      const full = root.querySelector('.rc-full'), core = root.querySelector('.rc-core').getBoundingClientRect();
      const rect = (id) => root.querySelector(`[data-testid=${id}]`).getBoundingClientRect();
      const style = (selector) => getComputedStyle(root.querySelector(selector));
      const center = (r) => ({x: r.left + r.width / 2, y: r.top + r.height / 2});
      return {
        background: getComputedStyle(full).backgroundColor, border: getComputedStyle(full).borderTopColor, text: getComputedStyle(full).color,
        font: getComputedStyle(full).fontFamily, plate: style('.rc-plate').backgroundColor, plateInk: style('.rc-plate').color,
        core: style('.rc-core').backgroundColor, coreRound: style('.rc-core').borderRadius, tilt: style('.rc-plate-b').transform,
        cpu: center(rect('plate-cpu')), ram: center(rect('plate-ram')), scans: center(rect('plate-scans')), coreCenter: center(core),
        textContrast: window.__contrast(getComputedStyle(full).color, getComputedStyle(full).backgroundColor),
        plateContrast: window.__contrast(style('.rc-plate').color, style('.rc-plate').backgroundColor),
      };
    }""")


def test_resource_console_mini_and_full_view_in_both_themes(session):
    page = session.page
    session.goto("#/glossary")
    session.set_theme("purple")
    page.evaluate(COLOR_JS)
    mini = page.get_by_test_id("resources-toggle")
    expect(mini).to_be_visible()
    # Versión mini: tres cuadros pequeños, en la esquina inferior derecha.
    assert mini.locator(".rc-box b").all_inner_texts() == ["CPU", "RAM", "SCANS"]
    box, viewport = mini.bounding_box(), page.viewport_size
    assert box["width"] < 330 and box["height"] < 70 and viewport["width"] - (box["x"] + box["width"]) < 20 and viewport["height"] - (box["y"] + box["height"]) < 20
    expect(page.get_by_test_id("resources-console")).to_have_count(0)
    mini.click()
    expect(page.get_by_test_id("resources-console")).to_be_visible()
    expect(page.get_by_test_id("plate-cpu")).to_have_text(re.compile(r"(\d+(,\d)? %|—)\s*CPU"), timeout=15_000)
    expect(page.get_by_test_id("plate-ram")).to_have_text(re.compile(r"\d+(,\d+)? (MB|GB)\s*RAM"))
    expect(page.get_by_test_id("plate-scans")).to_have_text(re.compile(r"\d+\s*SCANS\s*INTERACTIVA: NO"))
    expect(page.get_by_test_id("resources-status")).to_have_text(re.compile(r"STACK: (OK|DEGRADADO)\s*WORKER: ACTIVO\s*ACTUALIZADO: \d\d:\d\d:\d\d"))
    expect(page.get_by_test_id("resources-row")).to_have_count(5)
    expect(page.get_by_test_id("resources-alert-box")).to_have_count(0)
    state = console_state(page)
    # Unidad Púrpura: fondo negro, marco y texto naranja, placas verde menta con texto negro, monoespaciado.
    assert state["background"] == "rgb(0, 0, 0)" and state["border"] == state["text"] == state["core"] == "rgb(255, 122, 26)", state
    assert state["plate"] == "rgb(127, 255, 212)" and state["plateInk"] == "rgb(0, 0, 0)" and "mono" in state["font"].lower()
    assert state["textContrast"] >= 4.5 and state["plateContrast"] >= 4.5
    # Tres placas en triángulo alrededor del círculo: CPU arriba al centro, RAM y SCANS abajo a cada lado; inclinadas.
    assert state["cpu"]["y"] < state["coreCenter"]["y"] < min(state["ram"]["y"], state["scans"]["y"])
    assert state["ram"]["x"] < state["coreCenter"]["x"] < state["scans"]["x"] and abs(state["cpu"]["x"] - state["coreCenter"]["x"]) < 12
    assert state["tilt"] != "none" and state["coreRound"] == "50%"
    page.wait_for_timeout(300)
    session.assert_clean("consola de recursos (Unidad Púrpura)")
    assert page.evaluate(OUTSIDE_TEXT) == []
    assert_wording(session, "consola de recursos")
    shot(page, "v142-indicador-purple", page.get_by_test_id("resources"))
    # Clásico: versión sobria, mismos datos y misma disposición.
    session.set_theme("classic")
    sober = console_state(page)
    assert sober["background"] == "rgb(255, 255, 255)" and sober["tilt"] in ("none", "matrix(1, 0, 0, 1, 0, 0)") and sober["plate"] != "rgb(127, 255, 212)"
    assert sober["textContrast"] >= 4.5 and sober["plateContrast"] >= 4.5
    assert sober["cpu"]["y"] < sober["coreCenter"]["y"] < min(sober["ram"]["y"], sober["scans"]["y"])
    expect(page.get_by_test_id("resources-status")).to_have_text(re.compile(r"STACK: (OK|DEGRADADO)\s*WORKER: ACTIVO\s*ACTUALIZADO: \d\d:\d\d:\d\d"))
    shot(page, "v142-indicador-classic", page.get_by_test_id("resources"))
    mini.click()
    expect(page.get_by_test_id("resources-console")).to_have_count(0)


def test_alert_box_blinks_only_above_85_percent_and_respects_reduced_motion(browser):
    def alerted(route):
        body = route.fetch().json()
        worker = next(item for item in body["services"] if item["service"] == "worker")
        worker.update(memory_bytes=int(worker["memory_limit_bytes"] * 0.9), memory_percent=90.0, alert=True)
        body["alerts"] = [{"service": "worker", "memory_percent": 90.0}]
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    for reduced, expected in (("no-preference", "rc-blink"), ("reduce", "none")):
        context = browser.new_context(viewport={"width": 1366, "height": 900}, reduced_motion=reduced)
        context.add_init_script(CSP_HOOK)
        session = Session(context.new_page())
        page = session.page
        page.route("**/api/resources", alerted)
        session.goto("#/glossary")
        session.set_theme("purple")
        page.evaluate(COLOR_JS)
        expect(page.get_by_test_id("resources")).to_have_attribute("data-alert", "true")
        expect(page.get_by_test_id("resources-alert")).to_contain_text("ALERTA")
        page.get_by_test_id("resources-toggle").click()
        box = page.get_by_test_id("resources-alert-box")
        expect(box).to_contain_text("ALERTA")
        expect(box).to_contain_text("RAM sobre 85 % del límite: worker")
        style = box.evaluate("(node) => { const s = getComputedStyle(node); return {animation: s.animationName, color: s.color, contrast: window.__contrast(s.color, window.__background(node))}; }")
        assert style["animation"] == expected, (reduced, style)
        assert style["color"] == "rgb(255, 45, 45)" and style["contrast"] >= 4.5, style
        expect(page.locator("[data-testid=resources-row][data-service=worker]")).to_have_attribute("data-alert", "true")
        session.assert_clean(f"consola con alerta ({reduced})")
        context.close()


# --- 2, 5, 6, 8. hallazgos agrupados, librería benigna, script inline y escucha de interacción ---


def test_scan_groups_repeated_findings_and_reports_interaction_listeners(session, shared, browser):
    job_id = ensure_scan(shared, browser, "interact", INTERACT)
    page = session.page
    report = get_json(page, f"/api/scans/{job_id}/report")
    findings = get_json(page, f"/api/scans/{job_id}/findings")
    assert report["schema_version"] == "1.7.0" and len(report["story"]["steps"]) == 8
    # Scan automático: se registra quién escucha, pero no hubo interacción del usuario.
    assert report["site"]["summary"]["interaction"]["available"] is False
    assert "La visita fue automatizada" in report["story"]["steps"][-1]["sentences"][1]["text"]
    listeners = [item for item in findings["items"] if item["type"] == "interaction_listener"]
    assert any("interact.js" in (item["script_url"] or "") and item["level"] == "EVIDENCIA" for item in listeners)
    # Librería conocida: lectura registrada (Evidencia), sin inferir fingerprinting.
    types = [item["type"] for item in findings["items"]]
    assert "canvas_read_benign" in types and "canvas_fingerprinting" not in types
    # Script inline de la página: atribuido al propio sitio.
    fingerprinting = get_json(page, f"/api/scans/{job_id}/fingerprinting")
    inline = next(script for script in fingerprinting["scripts"] if script["script_url"] == INTERACT)
    assert inline["entity"] == "site.fixtures.test"
    assert all(not api["api"].startswith("events.") for script in fingerprinting["scripts"] for api in script["apis"])

    session.goto(f"#/scan/{job_id}/findings")
    story = page.get_by_test_id("story")
    expect(story.get_by_test_id("story-step")).to_have_count(8)
    step = story.locator("[data-step=interaccion]")
    expect(step.get_by_test_id("story-title")).to_have_text("7. Registro de interacción")
    expect(step).to_contain_text("escuchan la interacción del usuario")
    expect(page.get_by_test_id("interaction-unavailable")).to_be_visible()
    # Lista técnica: una fila por grupo (aquí no hay hallazgos repetidos: cada uno conserva su fila).
    rows = int(page.get_by_test_id("findings-row-count").inner_text())
    assert rows == len(findings["groups"]) <= len(findings["items"])
    assert page.get_by_test_id("finding").count() == len(findings["items"])
    page.wait_for_timeout(200)
    session.assert_clean("hallazgos")
    assert_wording(session, "hallazgos")
    assert page.evaluate(OUTSIDE_TEXT) == []

    # Fingerprinting: el script inline no aparece como «Organización no disponible».
    session.goto(f"#/scan/{job_id}/fingerprinting")
    expect(page.get_by_test_id("fingerprinting")).to_be_visible()
    expect(page.locator("main")).to_contain_text("site.fixtures.test")


# --- 1, 7, 8. captura interactiva: interacción real por el visor ---


def test_interactive_capture_correlates_user_interaction_with_sends(session):
    page = session.page
    session.goto("#/analyze")
    page.fill("#url", INTERACT)
    page.get_by_test_id("interactive-start").click()
    job_id = None
    try:
        expect(page.get_by_test_id("vnc-state")).to_have_attribute("data-state", "connected", timeout=90_000)
        job_id = page.request.get(f"{BASE_URL}/api/interactive").json()["session"]["job_id"]
        canvas = page.locator("[data-testid=vnc-screen] canvas")
        page.wait_for_function("() => { const c = document.querySelector('[data-testid=vnc-screen] canvas'); return c && c.width >= 1000; }", timeout=15_000)
        canvas.scroll_into_view_if_needed()
        page.wait_for_timeout(4_000)  # separa la carga de la página de la primera interacción
        box = canvas.bounding_box()
        x, y = box["x"] + box["width"] * 0.6, box["y"] + box["height"] * 0.6
        for _ in range(3):  # tres clics en la página, espaciados
            page.mouse.click(x, y)
            page.wait_for_timeout(2_700)
        page.mouse.move(x, y)
        page.mouse.wheel(0, 400)  # desplazamiento
        page.wait_for_timeout(2_700)
        page.keyboard.type("hola", delay=80)  # teclas: solo se registra que hubo, no cuáles
        page.wait_for_timeout(2_700)
        session.assert_clean("visor durante la interacción")
        page.get_by_test_id("interactive-stop").click()
        page.wait_for_url(re.compile(rf"#/scan/{job_id}"), timeout=60_000)
        assert session.wait_finished() == "done"
        expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)

        # 1. Textos coherentes: rótulo del encabezado, «Durante la sesión» y grupo fijo sin «visita automatizada».
        expect(page.get_by_test_id("scan-interactive-label")).to_have_text("captura interactiva · 1 página")
        expect(page.get_by_test_id("summary-plain")).to_contain_text("Durante la sesión se realizaron")
        report = get_json(page, f"/api/scans/{job_id}/report")
        last = report["story"]["steps"][-1]
        assert "automatizada" not in json.dumps(last, ensure_ascii=False) and "Hubo navegación humana" in last["sentences"][1]["text"]

        # 8. Interacción registrada por el relé (hora y tipo) y correlacionada con los envíos.
        interaction = report["site"]["summary"]["interaction"]
        assert interaction["available"] is True and interaction["interactions"].get("click", 0) >= 3, interaction["interactions"]
        assert interaction["interactions"].get("scroll", 0) >= 1 and interaction["interactions"].get("key", 0) >= 1
        scan = get_json(page, f"/api/scans/{job_id}")
        recorded = scan["result"]["interactive"]["interactions"]
        assert all(set(item) == {"ts", "kind"} for item in recorded) and "hola" not in json.dumps(scan, ensure_ascii=False)
        flagged = [item for item in interaction["organizations"] if item["flagged"]]
        assert [item["organization"] for item in flagged] == ["tracker-a.fixtures.test"], interaction["organizations"]
        findings = get_json(page, f"/api/scans/{job_id}/findings")["items"]
        sent = [item for item in findings if item["type"] == "interaction_sent"]
        assert len(sent) == 1 and sent[0]["level"] == "EVIDENCIA" and sent[0]["plain"].startswith("Su interacción se envió a tracker-a.fixtures.test")
        assert {"interaction_listener", "interaction_payload"} <= {item["type"] for item in findings}

        session.goto(f"#/scan/{job_id}/findings")
        step = page.get_by_test_id("story").locator("[data-step=interaccion]")
        expect(step).to_have_attribute("data-observed", "true")
        expect(page.get_by_test_id("story").locator("[data-step=no_visible]")).to_contain_text("Hubo navegación humana")
        expect(page.get_by_test_id("story").locator("[data-step=no_visible]")).not_to_contain_text("automatizada")
        panel = page.get_by_test_id("interaction")
        expect(panel.get_by_test_id("interaction-counts")).to_contain_text(re.compile(r"[3-9] clics"))
        expect(panel.get_by_test_id("interaction-organization")).to_have_count(1)
        expect(panel.get_by_test_id("interaction-organization")).to_contain_text("tracker-a.fixtures.test")
        panel.get_by_test_id("interaction-timeline-toggle").click()
        kinds = [row.get_attribute("data-kind") for row in panel.get_by_test_id("interaction-row").all()]
        assert kinds.count("click") >= 3 and "scroll" in kinds and "key" in kinds
        expect(panel.get_by_test_id("interaction-row").first).to_contain_text("tracker-a.fixtures.test")
        expect(panel.get_by_test_id("interaction-payloads")).to_contain_text("coordenadas del puntero")
        page.wait_for_timeout(200)
        session.assert_clean("registro de interacción")
        assert_wording(session, "registro de interacción")
        assert page.evaluate(OUTSIDE_TEXT) == []

        # 2. Hallazgos repetidos en una fila: mismo tipo y misma organización, con conteo y desplegable al detalle.
        grouped = get_json(page, f"/api/scans/{job_id}/findings")
        rows = int(page.get_by_test_id("findings-row-count").inner_text())
        assert rows == len(grouped["groups"]) < len(grouped["items"])
        group = page.locator("[data-testid=finding-group][data-type=interaction_payload]").first
        count = int(group.get_attribute("data-count"))
        assert count >= 3
        expect(group.get_by_test_id("finding-group-count")).to_have_text(f"× {count}")
        expect(group.get_by_test_id("finding")).to_have_count(count)
        expect(group.get_by_test_id("finding").first).to_be_hidden()
        group.locator("summary").click()
        expect(group.get_by_test_id("finding").first).to_be_visible()
        assert page.get_by_test_id("finding").count() == len(grouped["items"])
        # Rastreadores: requests del mismo tipo en una fila, desplegable.
        session.goto(f"#/scan/{job_id}/trackers")
        tracker = page.get_by_test_id("tracker-group").first
        tracker.locator("summary").first.click()
        bundle = tracker.get_by_test_id("tracker-bundle").first
        expect(bundle).to_be_visible()
        bundled = int(bundle.get_by_test_id("tracker-bundle-count").inner_text().replace("×", "").strip())
        assert bundled >= 2
        expect(tracker.get_by_test_id("tracker-rows")).to_contain_text(re.compile(r"\d+ filas? para \d+ requests"))
        bundle.locator("summary").click()
        expect(bundle.get_by_test_id("tracker-plain")).to_have_count(bundled)
        session.assert_clean("rastreadores agrupados")
        assert page.evaluate(OUTSIDE_TEXT) == []

        # 7. HAR exportado: una página por página visitada y la versión real.
        har = get_json(page, f"/api/scans/{job_id}/har")["log"]
        timeline = report["scan"]["interactive"]["timeline"]
        assert har["creator"]["version"] == "1.4.6" and len(har["pages"]) == len(timeline) == 1
        assert {entry["pageref"] for entry in har["entries"]} == {"page_1"}
        # Reporte exportado: grupo y sección de interacción.
        exported = page.request.post(f"{BASE_URL}/api/scans/{job_id}/export")
        assert exported.ok
    finally:
        active = page.request.get(f"{BASE_URL}/api/interactive").json()["session"]
        if active:
            page.request.post(f"{BASE_URL}/api/interactive/{active['job_id']}/stop")
            page.wait_for_function("async () => !(await (await fetch('/api/interactive')).json()).session", timeout=60_000, polling=1000)
