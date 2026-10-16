"""F10 de extremo a extremo: borrado del historial, menú, glosario, «Hallazgos por grupo»,
frases técnicas, temas, contraste y CSP. Con navegador real contra el stack real."""

import json
import pathlib
import re

from playwright.sync_api import expect

from .conftest import BASE_URL, ensure_scan
from .test_flow import FIXTURE, FP_PAGE, shot
from .test_privacy import COOKIELESS, start_test, wait_result
from .test_reports import F8_PAGE

SHOTS = pathlib.Path("/tmp/screenshots")
STEP_TITLES = ["1. Identificadores persistentes", "2. Fingerprinting", "3. Fugas de URL y Referer", "4. Exfiltración de atributos",
               "5. Sincronización de identificadores", "6. Consentimiento (TCF / Consent Mode)", "7. Registro de interacción", "8. Fuera del alcance observable"]
TABS = [
    ("summary", "Resumen", None, "Índice de exposición, terceros contactados y categorías de datos"),
    ("findings", "Hallazgos", None, "Ocho grupos técnicos, con nivel de evidencia y requests de respaldo"),
    ("trackers", "Rastreadores", None, "Requests con señales de seguimiento, agrupadas por organización"),
    ("fingerprinting", "Fingerprinting", None, "Lectura de atributos del dispositivo mediante APIs del navegador"),
    ("requests", "Tráfico", "requests", "Todas las requests capturadas durante la visita"),
]
GLOSSARY_TERMS = ["Request", "Tercero", "Tracker", "Pixel", "Beacon", "Cookie", "Cookie persistente", "Sincronización de identificadores", "Referer",
                  "User-Agent", "Base64", "URL codificada", "Canvas", "WebGL", "Fingerprinting", "Exfiltración", "Evidencia", "Inferencia",
                  "Posible", "Desconocido", "CMP / TCF", "Consent Mode",
                  # v1.4.2
                  "Rastreo del lado del servidor", "Registro de interacción", "DMP", "Broker de datos",
                  "Librería en CDN público", "Propósito de una cookie", "Alias de organización",
                  # v1.4.8
                  "WebRTC", "Candidato ICE"]
HEDGE = re.compile(r"podría|podrían|es compatible con|son compatibles con|es posible que|no se sabe|no se pudo", re.I)
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self' https://api.ipify.org; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

# Contraste WCAG 2.x de cada texto visible contra su fondo efectivo. La cuadrícula hexagonal de
# «Unidad Púrpura» se evalúa en su peor caso: contra el tono claro de la cuadrícula (--dot), no solo el del fondo.
CONTRAST_JS = """
() => {
  // Cualquier color CSS (rgb, oklch de Tailwind...) se normaliza pintándolo en un canvas de 1 píxel.
  const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
  const context = canvas.getContext('2d', {willReadFrequently: true});
  const cache = new Map();
  const parse = (value) => {
    if (cache.has(value)) return cache.get(value);
    context.clearRect(0, 0, 1, 1); context.fillStyle = '#000'; context.fillStyle = value; context.fillRect(0, 0, 1, 1);
    const d = context.getImageData(0, 0, 1, 1).data;
    const a = d[3] / 255;
    const color = a === 0 ? {r: 0, g: 0, b: 0, a: 0} : {r: d[0], g: d[1], b: d[2], a};
    cache.set(value, color); return color;
  };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const over = (top, bottom) => ({r: top.r * top.a + bottom.r * (1 - top.a), g: top.g * top.a + bottom.g * (1 - top.a), b: top.b * top.a + bottom.b * (1 - top.a), a: 1});
  const root = getComputedStyle(document.documentElement);
  const hex = (value) => { const v = value.trim().replace('#', ''); return {r: parseInt(v.slice(0, 2), 16), g: parseInt(v.slice(2, 4), 16), b: parseInt(v.slice(4, 6), 16), a: 1}; };
  const dots = getComputedStyle(document.querySelector('.app-root')).backgroundImage !== 'none' ? hex(root.getPropertyValue('--dot')) : null;
  // Fondos posibles detrás de un elemento: sube por los ancestros componiendo colores; si llega
  // al fondo de la aplicación con puntos, devuelve también el color de los puntos.
  const backgrounds = (element) => {
    const layers = []; let onDots = false;
    for (let node = element; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      const color = parse(style.backgroundColor);
      if (color && color.a > 0) { layers.push(color); if (color.a === 1) { onDots = false; break; } }
      if (node.classList && node.classList.contains('app-root')) onDots = true;
    }
    const compose = (base) => layers.reduceRight((acc, layer) => over(layer, acc), base);
    const white = {r: 255, g: 255, b: 255, a: 1};
    const out = [compose(white)];
    if (onDots && dots) out.push(layers.slice(0, -1).reduceRight((acc, layer) => over(layer, acc), dots));
    return out;
  };
  const failures = []; let checked = 0;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.textContent.trim();
    const element = node.parentElement;
    if (!text || !element) continue;
    if (element.closest('svg, [aria-hidden=true], [disabled], [role=tooltip], option')) continue;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    if (style.visibility === 'hidden' || style.display === 'none' || rect.width === 0 || rect.height === 0) continue;
    if (element.closest('details:not([open]) > :not(summary)')) continue;
    const color = parse(style.color);
    if (!color) continue;
    const size = parseFloat(style.fontSize), weight = parseInt(style.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const needed = large ? 3 : 4.5;
    checked += 1;
    const worst = Math.min(...backgrounds(element).map((background) => ratio(over(color, background), background)));
    if (worst < needed) failures.push({text: text.slice(0, 50), ratio: Math.round(worst * 100) / 100, needed, color: style.color, cls: (element.className && element.className.baseVal === undefined ? element.className : '').toString().slice(0, 60)});
  }
  return {checked, failures};
}
"""


def api(page, method, path, **kwargs):
    return getattr(page.request, method)(f"{BASE_URL}{path}", **kwargs)


# --- Criterio 1: borrar un scan y borrar todo ---


def test_delete_one_scan_from_its_page(session):
    """Un scan con reporte exportado se borra desde su página; se informa cuánto se liberó y todo desaparece."""
    page = session.page
    job_id = session.scan(COOKIELESS)
    assert api(page, "post", f"/api/scans/{job_id}/export").status == 202
    assert api(page, "get", f"/api/scans/{job_id}/export/html").ok
    before = api(page, "get", "/api/history").json()
    assert before["delete_enabled"] is True
    page.get_by_test_id("delete-scan").click()
    confirm = page.get_by_test_id("delete-scan-confirm")
    expect(confirm).to_contain_text("No se puede deshacer")
    # Cancelar no borra nada.
    page.get_by_test_id("delete-scan-no").click()
    assert api(page, "get", f"/api/scans/{job_id}").ok
    page.get_by_test_id("delete-scan").click()
    page.get_by_test_id("delete-scan-yes").click()
    notice = page.get_by_test_id("deleted-summary")
    expect(notice).to_be_visible()
    text = notice.inner_text()
    match = re.search(r"Se borr(?:ó|aron) 1 scan y (\d+) reportes? exportados?\. Se liberaron ([\d.]+) (B|KB|MB) de datos\.", text)
    assert match and int(match.group(1)) == 3 and float(match.group(2)) > 0, text
    expect(page.get_by_test_id("deleted-notice")).to_contain_text("backups/")
    # Datos y reportes eliminados.
    for path in ("", "/requests", "/report", "/findings", "/export/html", "/export/json"):
        assert api(page, "get", f"/api/scans/{job_id}{path}").status == 404, path
    after = api(page, "get", "/api/history").json()
    assert after["scans"] == before["scans"] - 1 and after["reports"] == before["reports"] - 3
    page.get_by_test_id("back-home").click()
    expect(page.get_by_test_id("panel")).to_be_visible()
    session.goto("#/history")
    expect(page.get_by_test_id("recent")).to_be_visible()
    assert job_id not in page.get_by_test_id("recent").inner_html()
    print(f"\nBORRAR UN SCAN: «{text}»")
    session.assert_clean("borrar un scan")


def test_delete_scan_from_the_recent_list(session):
    page = session.page
    job_id = session.scan(COOKIELESS)
    session.goto("#/history")
    row = page.get_by_test_id("recent-row").filter(has=page.locator(f'a[href="#/scan/{job_id}"]'))
    expect(row).to_have_count(1)
    row.get_by_test_id("delete-scan").click()
    row.get_by_test_id("delete-scan-yes").click()
    expect(page.get_by_test_id("deleted-summary")).to_contain_text("Se liberaron")
    expect(page.locator(f'a[href="#/scan/{job_id}"]')).to_have_count(0)
    assert api(page, "get", f"/api/scans/{job_id}").status == 404
    session.assert_clean("borrar desde la lista")


def test_delete_all_needs_the_word_BORRAR(session):
    """La confirmación explícita, en la interfaz y en la API. La respuesta del borrado total se simula
    aquí para no vaciar la base del equipo: el borrado real lo ejercitan la suite de la api y el
    criterio de aceptación manual."""
    page = session.page
    calls = []

    def fake_delete_all(route):
        request = route.request
        if request.method == "DELETE":
            calls.append(request.post_data)
            route.fulfill(status=200, content_type="application/json", body=json.dumps(
                {"deleted": {"scans": 12, "groups": 2, "reports": 9, "bytes_freed": 5 * 1024 * 1024}, "note": "Los respaldos de backups/ no se tocan."}))
        else:
            route.continue_()

    page.route(re.compile(r"/api/scans$"), fake_delete_all)
    session.goto("#/history")
    history = page.get_by_test_id("history")
    expect(history).to_be_visible()
    stored = int(page.get_by_test_id("history-scans").inner_text())
    assert stored >= 1 and re.search(r"\d+(\.\d+)? (KB|MB)", page.get_by_test_id("history-disk").inner_text())
    page.get_by_test_id("delete-all-open").click()
    expect(page.get_by_test_id("delete-all-form")).to_contain_text("No se puede deshacer")
    expect(page.get_by_test_id("delete-all-count")).to_have_text(str(stored))
    confirm = page.get_by_test_id("delete-all-confirm")
    for wrong in ("", "borrar", "BORRA", "BORRAR!", "SI"):
        page.get_by_test_id("delete-all-input").fill(wrong)
        expect(confirm).to_be_disabled()
    page.get_by_test_id("delete-all-input").press("Enter")  # con la palabra mal escrita, Enter no envía nada
    assert calls == []
    page.get_by_test_id("delete-all-input").fill("BORRAR")
    expect(confirm).to_be_enabled()
    confirm.click()
    expect(page.get_by_test_id("deleted-summary")).to_have_text("Se borraron 12 scans, 2 grupos de Opciones avanzadas y 9 reportes exportados. Se liberaron 5.0 MB de datos.")
    assert calls == ['{"confirm":"BORRAR"}']
    page.unroute(re.compile(r"/api/scans$"))
    # La API real exige la misma palabra (nada se borra con estas llamadas).
    for body in ({}, {"confirm": "borrar"}, {"confirm": ""}):
        response = api(page, "delete", "/api/scans", data=json.dumps(body), headers={"Content-Type": "application/json"})
        assert response.status == 400 and response.json()["error_code"] == "CONFIRMATION_REQUIRED"
    assert api(page, "get", "/api/history").json()["scans"] == stored
    session.assert_clean("borrar todo")


# --- Criterio 3: menú ---


def test_scan_menu_has_icons_clear_names_and_subtitles(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    session.goto(f"#/scan/{job_id}")
    menu = page.get_by_test_id("tab-menu")
    assert "Orden de lectura sugerido" not in menu.inner_text()  # v1.2: sin párrafos explicativos; el orden lo dan los números
    links = menu.get_by_role("link")
    expect(links).to_have_count(5)
    tops = []
    for index, (key, title, technical, subtitle) in enumerate(TABS):
        tab = page.get_by_test_id(f"tab-{key}")
        assert links.nth(index).get_attribute("data-testid") == f"tab-{key}", "el orden del menú es el orden de lectura"
        expect(tab.get_by_test_id("tab-title")).to_have_text(title if technical is None else f"{title} ({technical})")
        expect(tab.get_by_test_id("tab-subtitle")).to_have_text(subtitle)
        icon = tab.locator("svg[data-icon]")
        expect(icon).to_be_visible()
        box = icon.bounding_box()
        assert box["width"] >= 20 and box["height"] >= 20
        tops.append(tab.bounding_box()["y"])
    assert tops == sorted(tops) and len(set(tops)) == 5, "las secciones se leen de arriba hacia abajo"
    assert len({page.get_by_test_id(f"tab-{key}").locator("svg[data-icon]").get_attribute("data-icon") for key, *_ in TABS}) == 5
    expect(page.get_by_test_id("tab-summary")).to_have_attribute("aria-current", "page")
    shot(page, "menu-clasico")
    menu.screenshot(path=str(SHOTS / "menu-detalle.png"))
    # Cada pestaña abre su vista y queda marcada.
    for key, view in (("findings", "story"), ("trackers", "trackers"), ("fingerprinting", "fingerprinting"), ("requests", "requests"), ("summary", "dashboard")):
        page.get_by_test_id(f"tab-{key}").click()
        expect(page.get_by_test_id(view)).to_be_visible()
        expect(page.get_by_test_id(f"tab-{key}")).to_have_attribute("aria-current", "page")
    session.set_theme("purple")
    shot(page, "menu-unidad-purpura")
    session.set_theme("classic")
    session.assert_clean("menú")


# --- Criterio 6: «¿Qué es esto?» y glosario ---


def test_every_tab_explains_itself_and_the_glossary_is_complete(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    panels = {}
    for route, panel in (("", "summary"), ("/findings", "story"), ("/trackers", "trackers"), ("/fingerprinting", "fingerprinting"), ("/requests", "traffic")):
        session.goto(f"#/scan/{job_id}{route}")
        what = page.locator(f"[data-testid=what-is-this][data-panel={panel}]")
        expect(what).to_be_visible()
        expect(what.locator("summary")).to_contain_text("¿Qué es esto?")
        what.locator("summary").click()
        definition = what.get_by_test_id("what-definition").inner_text()
        method = what.get_by_test_id("what-method").inner_text()
        assert definition.startswith("Contenido.") and len(definition) > 80 and method.startswith("Método.") and len(method) > 50
        expect(what.get_by_test_id("what-analogy")).to_have_count(0)
        assert not re.search(r"[¡!]|En simple", what.inner_text()), "redacción técnica, sin analogías ni exclamaciones"
        assert what.get_by_test_id("term").count() >= 4
        panels[panel] = method
    assert "La lectura es Evidencia" in panels["fingerprinting"] and "siempre una Inferencia" in panels["fingerprinting"]
    # Tooltip de un término: aparece al pasar el cursor y al enfocarlo con el teclado.
    session.goto(f"#/scan/{job_id}/fingerprinting")
    term = page.locator("[data-testid=term][data-term=canvas]:visible").first
    tip = term.get_by_role("tooltip")
    expect(tip).to_be_hidden()
    term.hover()
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("valor característico del dispositivo")
    page.mouse.move(0, 0)
    expect(tip).to_be_hidden()
    term.focus()
    expect(tip).to_be_visible()
    assert term.get_attribute("aria-describedby") == tip.get_attribute("id")
    shot(page, "tooltip-glosario")
    # Glosario completo.
    page.get_by_test_id("nav-glossary").click()
    expect(page.get_by_test_id("glossary")).to_be_visible()
    listed = [text.split(" — ")[0].strip() for text in page.locator("[data-testid=glossary-term] dt").all_inner_texts()]
    assert listed == GLOSSARY_TERMS, listed
    for item in page.get_by_test_id("glossary-term").all():
        assert len(item.locator("dd").first.inner_text()) > 40
    shot(page, "glosario")
    print(f"\nGLOSARIO: {len(listed)} términos; paneles «¿Qué es esto?»: {sorted(panels)}")
    session.assert_clean("glosario")


# --- Criterios 4 y 5: frase técnica y «Hallazgos por grupo» ---


def read_story(session, job_id):
    page = session.page
    # Pasa por otra vista: así no se lee, por un instante, los grupos del scan anterior.
    session.goto("#/glossary")
    expect(page.get_by_test_id("glossary")).to_be_visible()
    session.goto(f"#/scan/{job_id}/findings")
    story = page.get_by_test_id("story")
    expect(story.get_by_test_id("story-step")).to_have_count(8)
    assert story.get_by_test_id("story-title").all_inner_texts() == STEP_TITLES
    session.open_all("story-detail")
    steps = []
    for step in story.get_by_test_id("story-step").all():
        sentences = [(node.get_attribute("data-level"), node.locator(".bubble-text").inner_text()) for node in step.get_by_test_id("story-sentence").all()]
        items = [(node.get_attribute("data-level"), node.get_by_test_id("story-item-plain").locator(".bubble-text").inner_text(), node.get_by_test_id("evidence-refs").count())
                 for node in step.get_by_test_id("story-item").all()]
        steps.append({"id": step.get_attribute("data-step"), "observed": step.get_attribute("data-observed") == "true", "sentences": sentences, "items": items,
                      "count": int(step.get_by_test_id("story-count").inner_text()) if step.get_by_test_id("story-count").count() else None,
                      "none": step.get_by_test_id("story-none").count()})
    return steps


def assert_story(steps):
    assert [step["id"] for step in steps] == ["etiquetado", "equipo", "navegacion", "datos", "identificador", "consentimiento", "interaccion", "no_visible"]
    for step in steps[:6]:
        if step["observed"]:
            assert step["count"] == len(step["items"]) >= 1 and step["sentences"] and step["none"] == 0, step
            for level, text, refs in step["items"]:
                assert level in ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO") and len(text) > 20 and refs == 1, (step["id"], level, text)
        else:
            # Los pasos sin hallazgos se muestran igual, diciendo que no se observó.
            assert step["count"] == 0 and step["items"] == [] and step["none"] == 1 and step["sentences"] == [], step
        for level, text in step["sentences"] + [(level, text) for level, text, _ in step["items"]]:
            if level != "EVIDENCIA":
                assert HEDGE.search(text), f"una frase de nivel {level} se redacta como hecho: {text}"
    last = steps[7]
    assert last["count"] is None and len(last["sentences"]) == 2 and all(level == "DESCONOCIDO" for level, _ in last["sentences"])
    assert "no es observable" in last["sentences"][0][1] and "sin inicio de sesión, búsquedas ni clics" in last["sentences"][1][1]


def test_story_has_seven_steps_on_the_fixture(session, shared, browser):
    fixture = ensure_scan(shared, browser, "main", FIXTURE)
    steps = read_story(session, fixture)
    assert_story(steps)
    by_id = {step["id"]: step for step in steps}
    # El fixture principal: cookies de terceros, fuga de URL e identificador compartido.
    assert by_id["etiquetado"]["observed"] and by_id["navegacion"]["observed"] and by_id["identificador"]["observed"]
    assert any(text.startswith("Fuga de URL: la URL de la página se envió a") for _, text, _ in by_id["navegacion"]["items"])
    assert any("recibieron el mismo identificador" in text for _, text, _ in by_id["identificador"]["items"])
    shot(session.page, "hallazgos-por-grupo")
    # El de fingerprinting: lectura (Evidencia) y propósito (Inferencia) separados; exfiltración.
    fp = {step["id"]: step for step in read_story(session, ensure_scan(shared, browser, "fp", FP_PAGE))}
    levels = [level for level, _, _ in fp["equipo"]["items"]]
    assert "EVIDENCIA" in levels and "INFERENCIA" in levels
    assert [level for level, _ in fp["equipo"]["sentences"]] == ["EVIDENCIA", "INFERENCIA"]
    assert any(text.startswith("Lectura de atributos: un script de") for level, text, _ in fp["equipo"]["items"] if level == "EVIDENCIA")
    assert any(HEDGE.search(text) and "fingerprinting" in text for level, text, _ in fp["equipo"]["items"] if level == "INFERENCIA")
    assert fp["datos"]["observed"] and any(text.startswith("Exfiltración de atributos: un script leyó") and "se transmitió a" in text for _, text, _ in fp["datos"]["items"])
    # El de consentimiento (F8): TCF y Consent Mode en su paso.
    f8 = {step["id"]: step for step in read_story(session, ensure_scan(shared, browser, "f8", F8_PAGE))}
    assert f8["consentimiento"]["observed"] and any("TCF" in text for _, text, _ in f8["consentimiento"]["items"])
    shot(session.page, "hallazgos-por-grupo-consentimiento")
    summary = {step["id"]: (step["count"], len(step["sentences"])) for step in steps}
    print(f"\nGRUPOS (fixture): {summary}")
    session.assert_clean("hallazgos por grupo")


def test_every_request_and_finding_shows_the_plain_phrase_before_the_detail(session, shared, browser):
    job_id = ensure_scan(shared, browser, "main", FIXTURE)
    page = session.page
    # Tabla: una frase por fila, antes de la URL; las inferencias llevan su matiz.
    session.goto(f"#/scan/{job_id}/requests?page_size=200")
    rows = page.get_by_test_id("request-row")
    expect(rows.first).to_be_visible()
    assert rows.count() == 21
    levels = {}
    for row in rows.all():
        plain = row.get_by_test_id("request-plain")
        level, text = plain.get_attribute("data-level"), plain.locator(".bubble-text").inner_text()
        assert len(text) > 20 and level in ("EVIDENCIA", "INFERENCIA")
        if level != "EVIDENCIA":
            assert HEDGE.search(text), f"inferencia redactada como hecho en la tabla: {text}"
        # La frase está antes que la URL dentro de la celda.
        assert row.evaluate("(row) => { const p = row.querySelector('[data-testid=request-plain]'); const u = p.parentElement.querySelector('.captured'); return Boolean(p.compareDocumentPosition(u) & Node.DOCUMENT_POSITION_FOLLOWING); }")
        levels[level] = levels.get(level, 0) + 1
    assert levels.get("EVIDENCIA", 0) >= 10 and levels.get("INFERENCIA", 0) >= 1, levels
    texts = " ".join(page.get_by_test_id("request-plain").all_inner_texts())
    for expected in ("Fuga de URL:", "la URL de la página se envió a", "Request de primera parte: conexión con el sitio analizado"):
        assert expected in texts, expected
    # Detalle de una request: frase, luego botón, luego lo técnico.
    page.get_by_test_id("request-row").filter(has_text="pixel.gif?uid=").get_by_test_id("request-link").click()
    expect(page.get_by_test_id("request-summary").get_by_test_id("request-plain")).to_be_visible()
    toggle = page.get_by_test_id("request-tech-toggle")
    if page.get_by_test_id("request-tech").get_attribute("data-open") == "true":
        toggle.click()
    expect(toggle).to_have_text("Ver detalle técnico")
    expect(page.get_by_test_id("reasons")).to_have_count(0)
    toggle.click()
    for block in ("reasons", "parameters", "decodings", "cookies"):
        expect(page.get_by_test_id(block)).to_be_visible()
    expect(page.get_by_test_id("request-detail")).to_contain_text("Cabeceras de la request")
    assert page.evaluate("() => Boolean(document.querySelector('[data-testid=request-plain]').compareDocumentPosition(document.querySelector('[data-testid=reasons]')) & Node.DOCUMENT_POSITION_FOLLOWING)")
    shot(page, "frase-tecnica-request")
    # Hallazgos: cada uno con su frase antes del detalle técnico.
    session.goto(f"#/scan/{job_id}/findings")
    findings = page.get_by_test_id("finding")
    expect(findings.first).to_be_attached()
    # v1.4.2: los hallazgos repetidos van plegados en una fila; se abren para revisar cada uno.
    for group in page.locator("[data-testid=finding-group] > details > summary").all():
        group.click()
    expect(findings.first).to_be_visible()
    finding_count = findings.count()
    assert finding_count >= 8
    for item in findings.all():
        plain = item.get_by_test_id("finding-plain")
        level, text = plain.get_attribute("data-level"), plain.locator(".bubble-text").inner_text()
        assert len(text) > 20
        if level != "EVIDENCIA":
            assert HEDGE.search(text), f"hallazgo {level} redactado como hecho: {text}"
        assert item.evaluate("(item) => item.firstElementChild.dataset.testid === 'finding-plain'")
    # Rastreadores: frase técnica y detalle a un clic.
    session.goto(f"#/scan/{job_id}/trackers")
    expect(page.get_by_test_id("tracker-group").first).to_be_visible()
    for summary in page.locator("[data-testid=tracker-group] > summary").all():
        summary.click()
    for summary in page.locator("[data-testid=tracker-bundle] > summary").all():  # v1.4.2: requests del mismo tipo en una fila
        summary.click()
    assert page.get_by_test_id("tracker-plain").count() >= 10
    expect(page.locator("[data-testid=tracker-detail][data-open=true]")).to_have_count(0)
    print(f"\nFRASES CLARAS: 21 requests ({levels}), {finding_count} hallazgos")
    session.assert_clean("frases técnicas")


# --- Criterio 2: mismo componente de progreso en los grupos ---


def test_privacy_test_group_shows_run_k_of_n_with_real_stages(session):
    page = session.page
    start_test(session, COOKIELESS, runs=2)
    seen_runs, seen_stages = set(), set()
    for _ in range(900):
        state = page.evaluate("""() => {
          const done = document.querySelector('[data-testid=privacy-progress]');
          const boxes = [...document.querySelectorAll('[data-testid=group-progress]')].map((box) => ({
            run: box.querySelector('[data-testid=progress-run]').textContent, stage: box.dataset.stage,
            current: box.querySelector('[data-state=current]') ? box.querySelector('[data-state=current]').dataset.testid : null}));
          return {boxes, status: done ? done.dataset.status : null};
        }""")
        if state["status"] == "completed":
            break
        for box in state["boxes"]:
            seen_runs.add(box["run"])
            seen_stages.add(box["stage"])
            if box["current"]:
                assert box["current"] == f"stage-{box['stage']}"
        page.wait_for_timeout(100)
    wait_result(session)
    assert seen_runs == {"Corrida 1 de 2", "Corrida 2 de 2"}, seen_runs
    assert len(seen_stages) >= 3 and seen_stages <= {"queued", "opening", "capturing", "analyzing", "building"}, seen_stages
    expect(page.get_by_test_id("group-progress")).to_have_count(0)
    print(f"\nPROGRESO DE GRUPO: {sorted(seen_runs)} | etapas {sorted(seen_stages)}")
    session.assert_clean("progreso de grupo")


# --- Criterio 8: temas, presentación, contraste, fuentes locales y CSP ---


def font_state(page):
    return page.evaluate("""async () => {
      await document.fonts.ready;
      const families = [...document.fonts].filter((font) => font.status === 'loaded').map((font) => font.family.replace(/"/g, ''));
      const files = performance.getEntriesByType('resource').map((entry) => entry.name).filter((name) => /\\.woff2?($|\\?)/.test(name));
      return {body: getComputedStyle(document.body).fontFamily, heading: getComputedStyle(document.querySelector('h2')).fontFamily,
              loaded: [...new Set(families)].sort(), files, origin: location.origin,
              theme: document.documentElement.dataset.theme, shadow: getComputedStyle(document.querySelector('.panel')).boxShadow,
              border: getComputedStyle(document.querySelector('.panel')).borderTopWidth,
              halftone: getComputedStyle(document.querySelector('.app-root')).backgroundImage};
    }""")


def test_classic_is_the_default_theme_and_purple_unit_is_optional(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    # Cabeceras: la CSP no cambió y sigue exigiendo fuentes del mismo origen.
    index = page.request.get(f"{BASE_URL}/")
    assert index.headers["content-security-policy"] == CSP
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    # El selector ofrece solo Clásico y Unidad Púrpura; el tema Cómic ya no existe.
    assert page.locator("[data-testid=theme-selector] button").all_inner_texts() == ["Clásico", "Unidad Púrpura"]
    expect(page.get_by_test_id("theme-comic")).to_have_count(0)
    # Clásico por defecto: sobrio, sin las tipografías del otro tema.
    classic = font_state(page)
    assert classic["theme"] == "classic", "clásico es el tema por defecto"
    assert classic["border"] == "1px" and classic["shadow"] == "none" and classic["halftone"] == "none"
    assert "Barlow Condensed" not in classic["heading"] and "JetBrains Mono" not in classic["body"]
    expect(page.get_by_test_id("theme-classic")).to_have_attribute("aria-pressed", "true")
    expect(page.get_by_test_id("summary-plain")).to_be_visible()
    shot(page, "tema-clasico-resumen")
    # Unidad Púrpura: opcional, solo estilo visual; se recuerda al recargar.
    session.set_theme("purple")
    purple = font_state(page)
    look = page.evaluate("""() => {
      const css = (selector, property) => { const node = document.querySelector(selector); return node ? getComputedStyle(node)[property] : null; };
      const pseudo = getComputedStyle(document.querySelector('.panel'), '::before');
      return {paper: css('.app-root', 'backgroundColor'), surface: css('.panel', 'backgroundColor'), radius: css('.panel', 'borderTopLeftRadius'),
              cut: pseudo.content !== 'none' && pseudo.backgroundImage.includes('linear-gradient'), captured: css('.captured', 'fontFamily'),
              hazard: css('[data-testid=limits-notice]', 'backgroundImage'), logo: css('.logo', 'backgroundColor'), logoRadius: css('.logo', 'borderTopLeftRadius'),
              clip: css('.btn', 'clipPath'), scheme: css('html', 'colorScheme')};
    }""")
    assert purple["heading"].startswith('"Barlow Condensed"') and look["captured"].startswith('"JetBrains Mono"'), (purple, look)
    assert {"Barlow Condensed", "JetBrains Mono"} <= set(purple["loaded"]), purple["loaded"]
    assert not {"Bangers", "Comic Neue"} & set(purple["loaded"])
    # Tipografías servidas por este mismo origen, y su respuesta trae la misma CSP.
    assert purple["files"] and all(name.startswith(f"{purple['origin']}/assets/") for name in purple["files"]), purple["files"]
    assert not any("bangers" in name.lower() or "comic" in name.lower() for name in purple["files"])
    font = page.request.get(purple["files"][0])
    assert font.ok and font.headers["content-type"] in ("font/woff2", "font/woff", "application/font-woff2") and len(font.body()) > 5000
    # Fondo casi negro con cuadrícula hexagonal (solo gradientes), paneles de línea fina con esquinas cortadas,
    # franjas diagonales en «Límites de la medición» y logo en círculo blanco.
    assert look["paper"] == "rgb(11, 6, 20)" and "conic-gradient" in purple["halftone"] and "url(" not in purple["halftone"], (look, purple["halftone"][:80])
    assert purple["border"] == "1px" and look["radius"] == "0px" and look["cut"] and look["clip"].startswith("polygon("), (purple, look)
    assert "repeating-linear-gradient" in look["hazard"], look
    assert look["logo"] == "rgb(255, 255, 255)" and look["logoRadius"] == "50%" and look["scheme"] == "dark", look
    # Mismos textos que en clásico: sin frases añadidas ni exclamaciones.
    assert not re.search(r"[¡!]", page.get_by_test_id("dashboard").inner_text())
    expect(page.get_by_test_id("theme-purple")).to_have_attribute("aria-pressed", "true")
    # Lo capturado no se transforma (una URL distingue mayúsculas), ni siquiera dentro de un título en mayúsculas.
    assert page.locator("h1 .captured, h2 .captured").first.evaluate("node => getComputedStyle(node).textTransform") == "none"
    # El botón del tema activo sigue legible con el cursor encima (el recorrido de contraste no pasa el cursor).
    page.get_by_test_id("theme-purple").hover()
    hovered = page.get_by_test_id("theme-purple").evaluate("""(node) => { const s = getComputedStyle(node);
      const rgb = (v) => v.match(/[\\d.]+/g).slice(0, 3).map(Number);
      const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
      const a = lum(rgb(s.color)), b = lum(rgb(s.backgroundColor)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); }""")
    assert hovered >= 4.5, f"contraste del botón de tema activo con el cursor encima: {hovered:.2f}"
    page.mouse.move(0, 0)
    shot(page, "tema-unidad-purpura-resumen")
    page.reload()
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    assert page.evaluate("document.documentElement.dataset.theme") == "purple"
    # Quien tenía guardado el tema Cómic pasa a Unidad Púrpura, y la preferencia guardada se actualiza.
    page.evaluate("window.localStorage.setItem('theme', 'comic')")
    page.reload()
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    assert page.evaluate("[document.documentElement.dataset.theme, window.localStorage.getItem('theme')]") == ["purple", "purple"]
    # Los badges de nivel dicen lo mismo en ambos temas (los colores son los de cada tema; el contraste AA se prueba aparte).
    session.goto(f"#/scan/{job_id}/findings")
    expect(page.get_by_test_id("finding").first).to_be_visible()
    badges = """() => [...new Set([...document.querySelectorAll('.badge[data-level]')].map((node) => [node.dataset.level, node.textContent.trim()].join('|')))].sort()"""
    in_purple = page.evaluate(badges)
    session.set_theme("classic")
    assert page.evaluate(badges) == in_purple and len(in_purple) >= 2
    assert {entry.split("|")[1] for entry in in_purple} <= {"Evidencia", "Inferencia", "Posible", "Desconocido"}
    assert session.page.evaluate("window.__cspViolations") == []
    print(f"\nTEMA: fuentes cargadas {purple['loaded']} desde {sorted({name.rsplit('/', 1)[-1] for name in purple['files']})} | CSP sin cambios")
    session.assert_clean("temas")


def test_contrast_is_aa_in_both_themes_and_in_presentation_mode(session, shared, browser):
    job_id = ensure_scan(shared, browser, "main", FIXTURE)
    page = session.page
    results = {}
    views = [("panel", "", "panel-exposure"), ("analizar", "#/analyze?advanced=1", "runs"), ("historial", "#/history", "recent"), ("resumen", f"#/scan/{job_id}", "dashboard"), ("hallazgos", f"#/scan/{job_id}/findings", "story"),
             ("rastreadores", f"#/scan/{job_id}/trackers", "trackers"), ("fingerprinting", f"#/scan/{job_id}/fingerprinting", "fingerprinting"),
             ("tráfico", f"#/scan/{job_id}/requests", "requests-table"), ("glosario", "#/glossary", "glossary"), ("mi exposición", "#/exposure", "combined-hash")]
    session.goto("")
    for theme in ("purple", "classic"):
        for presentation in (False, True):
            session.goto("")
            session.set_theme(theme)
            if page.evaluate("document.documentElement.classList.contains('presentation')") != presentation:
                page.get_by_test_id("presentation-toggle").click()
            assert page.evaluate("document.documentElement.classList.contains('presentation')") == presentation
            total = 0
            for name, route, test_id in views:
                session.goto(route)
                expect(page.get_by_test_id(test_id).first).to_be_visible()
                if name == "hallazgos":
                    session.open_all("story-detail")
                if name == "rastreadores":
                    expect(page.get_by_test_id("tracker-group").first).to_be_visible()
                    for summary in page.locator("[data-testid=tracker-group] > summary").all():
                        summary.click()
                    for summary in page.locator("[data-testid=tracker-bundle] > summary").all():
                        summary.click()
                for summary in page.locator("[data-testid=what-is-this] summary").all():
                    summary.click()
                page.wait_for_timeout(300)
                outcome = page.evaluate(CONTRAST_JS)
                assert outcome["checked"] > 15, (name, outcome["checked"])
                assert outcome["failures"] == [], f"{theme}{' + presentación' if presentation else ''} · {name}: {outcome['failures'][:8]}"
                total += outcome["checked"]
            label = f"{theme}{'+presentación' if presentation else ''}"
            results[label] = total
            if presentation:
                session.goto(f"#/scan/{job_id}")
                expect(page.get_by_test_id("dashboard")).to_be_visible()
                page.set_viewport_size({"width": 1920, "height": 1080})
                assert page.evaluate("parseFloat(getComputedStyle(document.documentElement).fontSize)") >= 22
                page.screenshot(path=str(SHOTS / f"presentacion-{'unidad-purpura' if theme == 'purple' else theme}.png"))
                page.set_viewport_size({"width": 1366, "height": 900})
    if page.evaluate("document.documentElement.classList.contains('presentation')"):
        page.get_by_test_id("presentation-toggle").click()
    session.set_theme("classic")
    assert set(results) == {"purple", "purple+presentación", "classic", "classic+presentación"}
    print(f"\nCONTRASTE AA: textos revisados sin fallos, por combinación: {results}")
    session.assert_clean("contraste")
