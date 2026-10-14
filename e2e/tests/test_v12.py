"""v1.2 — Claridad y precisión: menú, Panel, Analizar (URL limpia), Historial, tabla de Fingerprinting,
IDs de cuenta del sitio, texto suelto, logo, XSS y redacción de las vistas nuevas."""

import json
import pathlib
import re

from playwright.sync_api import expect

from .conftest import BASE_URL, ensure_scan
from .test_privacy import FORBIDDEN_WORDS

FIXTURE = "http://site.fixtures.test/"
FP_PAGE = "http://site.fixtures.test/fp/article?ref=campaign42"
XSS_PAGE = "http://site.fixtures.test/xss/"
ACCOUNTS = "http://site.fixtures.test/accounts/"
SHOTS = pathlib.Path("/tmp/screenshots")
# Redacción: trato de usted. Solo formas inequívocas de «tú» («intenta» o «revisa» también son tercera
# persona: «no se intenta obtener»), y sin la palabra vetada.
INFORMAL = re.compile(r"\b(tú|tu|tus|ti|contigo|puedes|quieres|tienes|debes|necesitas|haz|ten|ve a)\b", re.IGNORECASE)
BANNED = re.compile(r"charla", re.IGNORECASE)


def get_json(page, path):
    response = page.request.get(f"{BASE_URL}{path}")
    assert response.ok, f"{path}: {response.status}"
    return response.json()


# Texto visible de la interfaz SIN lo capturado del sitio (`.captured`): un título como «Tu experiencia de
# compra» es del sitio analizado, no de la interfaz. Se ocultan esos nodos un instante y se restauran.
UI_TEXT_JS = """() => {
  const nodes = [...document.querySelectorAll('.captured')];
  const previous = nodes.map((node) => node.style.display);
  nodes.forEach((node) => { node.style.display = 'none'; });
  const text = document.body.innerText;
  nodes.forEach((node, index) => { node.style.display = previous[index]; });
  return text;
}"""


def assert_wording(session, where):
    text = session.page.evaluate(UI_TEXT_JS)
    for pattern, what in ((FORBIDDEN_WORDS, "promete anonimato"), (INFORMAL, "tutea"), (BANNED, "usa la palabra vetada")):
        found = pattern.findall(text)
        assert found == [], f"{where}: la interfaz {what}: {found}"


KNOWN_SITE = "panel-sintetico.example"
# Dominios cuyo dueño está en el mapa de entidades de ambos perfiles de licencias.
KNOWN_ORGANIZATION_URLS = ("https://www.google-analytics.com/g/collect?v=2&tid=G-TEST", "https://stats.g.doubleclick.net/j/collect?v=1",
                           "https://connect.facebook.net/en_US/fbevents.js", "https://www.facebook.com/tr?id=1&ev=PageView")


def import_known_organizations(page):
    """Importa un HAR sintético de un sitio .example con requests a organizaciones conocidas y espera su análisis."""
    def entry(url, kind, mime, second):
        return {"startedDateTime": f"2026-01-15T10:00:0{second}.000Z", "time": 10, "pageref": "page_1", "_resourceType": kind,
                "request": {"method": "GET", "url": url, "httpVersion": "HTTP/2", "headers": [], "queryString": [], "cookies": [], "headersSize": 100, "bodySize": 0},
                "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/2", "headers": [], "cookies": [], "content": {"size": 10, "mimeType": mime},
                             "redirectURL": "", "headersSize": 80, "bodySize": 10},
                "cache": {}, "timings": {"send": 0, "wait": 8, "receive": 2}}

    page_url = f"https://www.{KNOWN_SITE}/"
    har = {"log": {"version": "1.2", "creator": {"name": "test_v12", "version": "1"},
                   "pages": [{"id": "page_1", "startedDateTime": "2026-01-15T10:00:00.000Z", "title": page_url, "pageTimings": {}}],
                   "entries": [entry(page_url, "document", "text/html", 0)] + [entry(url, "image", "image/gif", index + 1) for index, url in enumerate(KNOWN_ORGANIZATION_URLS)]}}
    inspected = page.request.post(f"{BASE_URL}/api/har/inspect", headers={"Content-Type": "application/json"}, data=json.dumps(har))
    assert inspected.ok, inspected.text()
    imported = page.request.post(f"{BASE_URL}/api/har/import?load={inspected.json()['default_load']}&name=panel.har",
                                 headers={"Content-Type": "application/json"}, data=json.dumps(har))
    assert imported.status == 202, imported.text()
    job_id = imported.json()["job_id"]
    for _ in range(120):
        scan = get_json(page, f"/api/scans/{job_id}")
        if scan["analysis_status"] in ("completed", "failed") or scan["status"] == "failed":
            break
        page.wait_for_timeout(500)
    assert scan["status"] == "completed" and scan["analysis_status"] == "completed", scan
    return job_id


# --- 1. Menú principal ---


def test_main_menu_has_the_four_entries_and_old_routes_redirect(session):
    page = session.page
    session.goto("")
    nav = page.get_by_test_id("main-nav")
    expect(nav).to_be_visible()
    assert nav.get_by_role("link").all_inner_texts() == ["Panel", "Analizar un sitio", "Historial", "Glosario"]
    assert "Privacy Test" not in page.locator("body").inner_text() and "Mi exposición" not in nav.inner_text()
    for test_id, landmark, current in (("nav-scans", "analyze", "Analizar un sitio"), ("nav-history", "history-view", "Historial"),
                                       ("nav-glossary", "glossary", "Glosario"), ("nav-panel", "panel", "Panel")):
        page.get_by_test_id(test_id).click()
        expect(page.get_by_test_id(landmark)).to_be_visible()
        assert nav.locator("[aria-current=page]").all_inner_texts() == [current]
    # #/privacy redirige a «Analizar un sitio» con las opciones avanzadas abiertas; #/exposure se mantiene.
    session.goto("#/privacy")
    expect(page).to_have_url(re.compile(r"#/analyze\?advanced=1$"))
    expect(page.get_by_test_id("advanced")).to_have_attribute("open", "")
    page.go_back()
    assert "#/privacy" not in page.url, "la redirección reemplaza la entrada del historial"
    session.goto("#/exposure")
    expect(page.get_by_test_id("exposure")).to_be_visible()
    session.assert_clean("menú")


# --- 7a. URL de entrada ---


def test_tracking_parameters_are_detected_and_the_clean_url_is_scanned(session):
    page = session.page
    dirty = f"{FIXTURE}?page=2&gclid=EAIaIQobChMI&utm_source=boletin&utm_medium=correo&fbclid=IwAR0"
    session.goto("#/analyze")
    assert page.get_by_test_id("tracking-notice").count() == 0
    page.fill("#url", f"{FIXTURE}?page=2")
    page.wait_for_timeout(600)
    assert page.get_by_test_id("tracking-notice").count() == 0, "sin parámetros de seguimiento no hay aviso"
    page.fill("#url", dirty)
    notice = page.get_by_test_id("tracking-notice")
    expect(notice).to_be_visible()
    expect(page.get_by_test_id("tracking-params")).to_have_text("gclid, utm_source, utm_medium, fbclid")
    # Por defecto se limpia; se puede mantener.
    expect(page.get_by_test_id("keep-url")).not_to_be_checked()
    expect(page.get_by_test_id("tracking-decision")).to_contain_text(f"sin ellos: {FIXTURE}?page=2")
    page.get_by_test_id("keep-url").check()
    expect(page.get_by_test_id("tracking-decision")).to_contain_text("tal como está")
    page.get_by_test_id("keep-url").uncheck()
    session.assert_clean("aviso de URL")
    assert_wording(session, "analizar")
    page.click("button[type=submit]")
    expect(page.get_by_test_id("scan-url")).to_have_text(f"{FIXTURE}?page=2", timeout=15_000)
    job_id = re.search(r"#/scan/([0-9a-f-]{36})", page.url).group(1)
    cleaned = page.get_by_test_id("scan-url-cleaned")
    expect(cleaned).to_contain_text("se quitaron gclid, utm_source, utm_medium, fbclid")
    # Se guardaron las dos URL.
    scan = get_json(page, f"/api/scans/{job_id}")
    assert scan["url"] == f"{FIXTURE}?page=2" and scan["original_url"] == dirty and scan["url_cleaned"] is True
    assert session.wait_finished() == "done"
    # El botón «Limpiar URL» deja la URL limpia en el campo y el aviso desaparece.
    session.goto("#/analyze")
    page.fill("#url", dirty)
    page.get_by_test_id("clean-url").click()
    expect(page.locator("#url")).to_have_value(f"{FIXTURE}?page=2")
    expect(page.get_by_test_id("tracking-notice")).to_have_count(0)
    # Historial: la fila dice que la URL se limpió.
    session.goto("#/history")
    row = page.get_by_test_id("recent-row").filter(has=page.locator(f'a[href="#/scan/{job_id}"]'))
    expect(row.get_by_test_id("url-cleaned")).to_contain_text("gclid")
    page.request.delete(f"{BASE_URL}/api/scans/{job_id}")
    session.assert_clean("URL limpia")


# --- 7b. IDs de cuenta del sitio ---


def test_site_account_ids_are_shown_apart_and_do_not_count_as_identifiers(session, shared, browser):
    job_id = ensure_scan(shared, browser, "accounts", ACCOUNTS)
    page = session.page
    manifest = get_json(page, f"/api/scans/{job_id}/report")
    expected = {"G-FIXTURE1234", "GTM-FIXT123", "45je4a10v9", "AW-987654321", "987654321", "AbC-D_efG1234567890", "123456789012345",
                "2612345678901", "0f8fad5b-d9cb-469f-a165-70867728950e", "C4ABCDEFGHIJ12345678", "1234567"}
    assert {item["value"] for item in manifest["site"]["summary"]["account_ids"]} == expected
    # Solo el identificador del visitante cuenta como sincronización y como identificador persistente.
    sync = [finding for finding in manifest["findings"] if finding["type"] == "id_sync"]
    persistent = [finding for finding in manifest["findings"] if finding["type"] == "persistent_id"]
    assert len(sync) == 1 and sync[0]["details"]["value_length"] == 32
    assert persistent and all("_vid" in finding["details"]["stored_in"] for finding in persistent)
    session.goto(f"#/scan/{job_id}/trackers")
    panel = page.get_by_test_id("account-ids")
    expect(panel.locator("h2")).to_contain_text("ID de cuenta del sitio")
    rows = panel.get_by_test_id("account-id")
    expect(rows).to_have_count(len(expected))
    assert {row.locator("td").nth(2).inner_text() for row in rows.all()} == expected
    for vendor in ("Google Analytics", "Google Tag Manager", "Google Ads", "Meta", "Pinterest", "Snapchat", "TikTok", "LinkedIn"):
        expect(panel).to_contain_text(vendor)
    # Regla 1: nivel y evidencia navegable en cada fila.
    assert panel.locator("[data-level=INFERENCIA]").count() == len(expected)
    rows.first.get_by_test_id("account-id-ref").first.click()
    expect(page.get_by_test_id("request-detail")).to_be_visible()
    session.assert_clean("IDs de cuenta")
    assert_wording(session, "IDs de cuenta")


# --- 2. Panel ---


def test_panel_summarises_the_stored_scans_and_my_exposure(session, shared, browser):
    fp_job = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    # El Panel normal no cuenta los scans de fixtures ni los de tests.
    real = get_json(page, "/api/panel")
    assert not [item for item in real["ranking"] if item["site"].endswith((".test", ".example"))]
    # Datos propios del test (no depende de lo que haya en la base): una captura con dominios de organizaciones
    # conocidas del mapa de entidades. Es un HAR sintético: no se navega a ningún sitio real.
    known_job = import_known_organizations(page)
    # Con ?fixtures=1 (solo en el stack de pruebas) se ven además los sitios de prueba: el de fixtures y el sintético.
    with_tests = get_json(page, "/api/panel?include_tests=true")
    assert with_tests["totals"]["sites"] >= real["totals"]["sites"] + 2
    assert "site.fixtures.test" in {item["site"] for item in with_tests["ranking"]}
    # El HAR importado cuenta para las organizaciones, pero va fuera del ranking por índice.
    assert KNOWN_SITE in {item["site"] for item in with_tests["partial_sites"]} and KNOWN_SITE not in {item["site"] for item in with_tests["ranking"]}
    assert with_tests["totals"]["organizations"] >= 2
    # Las cifras de la página son las de la respuesta que ella misma recibió. (El sitio de fixtures se escanea
    # sin parar durante las suites: su «scan más reciente» cambia entre una consulta y la siguiente.)
    with page.expect_response(lambda response: "/api/panel?include_tests=true" in response.url) as received:
        session.goto("#/?fixtures=1")
    with_fixtures = received.value.json()
    expect(page.get_by_test_id("panel-totals")).to_be_visible()
    expect(page.get_by_test_id("panel-logo")).to_be_visible()
    for card in ("sites", "organizations", "requests"):
        assert page.get_by_test_id(f"total-{card}").locator(".vignette-value").inner_text() == str(with_fixtures["totals"][card]), card
    # Organizaciones: «presente en k de N sitios».
    organizations = page.get_by_test_id("panel-organization")
    expect(organizations.first).to_contain_text(re.compile(rf"presente en \d+ de {with_fixtures['totals']['sites']} sitios?"))
    # Ranking por índice de exposición, de mayor a menor, con enlace al scan.
    ranking = page.get_by_test_id("panel-ranking-item")
    expect(ranking.filter(has_text="site.fixtures.test")).to_have_count(1)
    scores = [int(re.match(r"(\d+)", text).group(1)) for text in page.locator("[data-testid=panel-ranking-item] .badge").all_inner_texts()]
    assert scores == sorted(scores, reverse=True) and len(scores) == len(with_fixtures["ranking"])
    # Atributos más leídos y más enviados, con los nombres de «Mi exposición».
    read = page.get_by_test_id("panel-read-item").all_inner_texts()
    assert read and all(re.search(r"leído en \d+ de \d+", text) for text in read), read
    names = [item["attribute"] for item in with_fixtures["attributes"]["read"]]
    if "canvas" in names:
        assert any(text.startswith("Huella de canvas") for text in read)
    assert page.get_by_test_id("panel-attributes").inner_text().count("no_disponible") == 0
    # Tarjeta de «Mi exposición»: N de M, huella corta, GPU y tipo de IP; «Ver detalle» lleva a #/exposure.
    card = page.get_by_test_id("panel-exposure")
    expect(page.get_by_test_id("panel-exposure-attributes")).to_have_text(re.compile(r"Atributos expuestos\s*\d+ de 26"), timeout=20_000)
    short = page.get_by_test_id("panel-exposure-hash").locator("dd").inner_text()
    assert re.fullmatch(r"[0-9a-f]{12}", short), short
    expect(page.get_by_test_id("panel-exposure-gpu").locator("dd")).not_to_be_empty()
    expect(page.get_by_test_id("panel-exposure-ip").locator("dd")).to_have_text("Red interna del servidor")
    session.assert_clean("panel")
    assert_wording(session, "panel")
    # Ninguna etiqueta repetida en las listas de atributos.
    for test_id in ("panel-read-item", "panel-sent-item"):
        labels = page.locator(f"[data-testid={test_id}] > span:first-child").all_inner_texts()
        assert len(labels) == len(set(labels)), labels
    # Captura del Panel tal como lo ve un usuario (sin los scans de fixtures).
    session.goto("#/")
    expect(page.get_by_test_id("panel-totals")).to_be_visible()
    expect(page.get_by_test_id("panel-ranking")).to_be_visible()
    expect(page.get_by_test_id("panel-exposure-attributes")).to_have_text(re.compile(r"Atributos expuestos\s*\d+ de 26"), timeout=20_000)
    assert "fixtures.test" not in page.get_by_test_id("panel").inner_text()
    page.set_viewport_size({"width": 1366, "height": 900})
    page.screenshot(path=str(SHOTS / "v12-panel.png"), full_page=True)
    card.get_by_test_id("exposure-detail").click()
    expect(page.get_by_test_id("combined-hash")).to_be_visible(timeout=20_000)
    # La huella corta de la tarjeta es el comienzo de la del detalle.
    assert page.get_by_test_id("combined-hash").inner_text().startswith(short)
    assert fp_job


# --- 3. Historial ---


def test_history_lists_scans_and_groups_with_filters(session, shared, browser):
    xss_job = ensure_scan(shared, browser, "xss", XSS_PAGE)
    fp_job = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    session.goto("#/history")
    rows = page.get_by_test_id("recent-row")
    expect(rows.first).to_be_visible()
    link = lambda job: page.locator(f'[data-testid=recent-row] a[href="#/scan/{job}"]')  # noqa: E731
    expect(link(xss_job)).to_have_count(1)
    expect(link(fp_job)).to_have_count(1)
    # Sitio: texto literal dentro de la URL.
    page.get_by_test_id("filter-site").fill("fixtures.test/xss")
    expect(link(fp_job)).to_have_count(0)
    expect(link(xss_job)).to_have_count(1)
    page.get_by_test_id("filter-site").fill("no-existe-este-sitio-%_")
    expect(page.get_by_test_id("recent")).to_contain_text("No hay scans con estos filtros")
    expect(page.get_by_test_id("history-groups")).to_contain_text("No hay grupos con estos filtros")
    page.get_by_test_id("filter-clear").click()
    expect(link(fp_job)).to_have_count(1)
    # Estado.
    page.get_by_test_id("filter-status").select_option("failed")
    expect(link(fp_job)).to_have_count(0)
    page.get_by_test_id("filter-status").select_option("done")
    expect(link(fp_job)).to_have_count(1)
    # Fecha: desde mañana no hay nada; hasta hoy está todo lo de hoy.
    page.get_by_test_id("filter-from").fill("2099-01-01")
    expect(page.get_by_test_id("recent")).to_contain_text("No hay scans con estos filtros")
    page.get_by_test_id("filter-clear").click()
    expect(link(fp_job)).to_have_count(1)
    # Grupos de Opciones avanzadas y botones de borrado existentes.
    expect(page.get_by_test_id("history-groups").locator("h2")).to_have_text("Grupos de Opciones avanzadas")
    groups = get_json(page, "/api/privacy/tests?limit=200")["items"]
    expect(page.get_by_test_id("group-row")).to_have_count(min(len(groups), 50))
    if groups:
        page.get_by_test_id("group-link").first.click()
        expect(page.get_by_test_id("privacy-progress")).to_be_visible()
        session.goto("#/history")
    expect(rows.first.get_by_test_id("delete-scan")).to_be_visible()
    expect(page.get_by_test_id("delete-all-open")).to_be_visible()
    session.assert_clean("historial")
    assert_wording(session, "historial")
    page.screenshot(path=str(SHOTS / "v12-historial.png"), full_page=True)


# --- 5. Fingerprinting: atributos que leyó este sitio ---


def test_fingerprinting_tab_lists_the_browser_attributes_this_site_read(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    data = get_json(page, f"/api/scans/{job_id}/fingerprinting")
    assert data["browser_attributes"], "el fixture de fingerprinting lee atributos"
    session.goto(f"#/scan/{job_id}/fingerprinting")
    table = page.get_by_test_id("browser-attributes")
    expect(table.locator("h3")).to_have_text("Atributos de su navegador que leyó este sitio")
    assert [cell.inner_text() for cell in table.locator("thead th").all()] == ["Atributo", "Leído por (script y organización)", "Enviado a"]
    names = table.get_by_test_id("browser-attribute-name").all_inner_texts()
    assert len(names) == len(set(names)) >= 3
    # Mismos nombres que «Mi exposición» (catálogo de la interfaz).
    canvas = table.get_by_test_id("browser-attribute").filter(has=page.get_by_test_id("browser-attribute-name").get_by_text("Huella de canvas", exact=True))
    expect(canvas).to_have_count(1)
    # Leído por: la URL del script (texto capturado), su organización si se conoce y la llamada de respaldo.
    reader = canvas.get_by_test_id("browser-attribute-reader").filter(has_text="tracker-a.fixtures.test/fp.js")
    expect(reader).to_have_count(1)
    expect(reader.get_by_test_id("browser-attribute-call")).to_have_text(re.compile(r"^llamada #\d+$"))
    assert reader.locator("a[href^=http]").count() == 0, "la URL capturada no es un enlace"
    # Lo enviado lleva nivel, destino y enlace a la request donde se vio el valor.
    sent_rows = table.locator("[data-testid=browser-attribute][data-sent=true]")
    assert any(row["sent_to"] for row in data["browser_attributes"]), "el fixture envía atributos leídos"
    assert sent_rows.count() >= 1
    # Las filas con envío van primero.
    assert table.get_by_test_id("browser-attribute").first.get_attribute("data-sent") == "true"
    sent = sent_rows.first.get_by_test_id("browser-attribute-sent").first
    expect(sent.locator("[data-level=EVIDENCIA]")).to_be_visible()
    sent.get_by_test_id("browser-attribute-request").click()
    expect(page.get_by_test_id("request-detail")).to_be_visible()
    page.go_back()
    # Las cinco pestañas siguen siendo las mismas.
    assert page.locator("[data-testid=tab-menu] [data-testid=tab-title]").all_inner_texts() == ["Resumen", "Hallazgos", "Rastreadores", "Fingerprinting", "Tráfico (requests)"]
    session.assert_clean("tabla de atributos")
    assert_wording(session, "fingerprinting")


def test_exposure_compare_uses_the_real_scan_data(session, shared, browser):
    """Sin simular la API: el sitio de fixtures leyó y envió el canvas; la fila lo marca y enlaza a la evidencia."""
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    session.goto("#/exposure")
    expect(page.get_by_test_id("combined-hash")).to_be_visible(timeout=20_000)
    page.get_by_test_id("compare-select").select_option(job_id)
    mark = page.get_by_test_id("attr-canvas").get_by_test_id("compare-mark")
    expect(mark).to_have_attribute("data-read", "true")
    expect(mark.get_by_test_id("compare-read")).to_contain_text("tracker-a.fixtures.test")
    usage = get_json(page, f"/api/exposure/scan-usage?job_id={job_id}")["attributes"]
    assert (mark.get_attribute("data-sent") == "true") == bool(usage["canvas"]["sent"])
    session.assert_clean("comparar (datos reales)")
    assert_wording(session, "mi exposición")
    page.screenshot(path=str(SHOTS / "v12-mi-exposicion.png"), full_page=True)


# --- 6. Modo compacto ---


def test_views_are_compact_titles_with_one_line_subtitles(session, shared, browser):
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    routes = ["", "#/analyze?advanced=1", "#/history", "#/glossary", f"#/scan/{job_id}", f"#/scan/{job_id}/findings",
              f"#/scan/{job_id}/trackers", f"#/scan/{job_id}/fingerprinting", f"#/scan/{job_id}/requests"]
    checked = 0
    for route in routes:
        session.goto(route)
        expect(page.locator("main h2, main h1").first).to_be_visible()
        page.wait_for_timeout(500)
        # Cada subtítulo ocupa una sola línea a 1366 px.
        for subtitle in page.locator("[data-testid=panel-subtitle]:visible").all():
            lines = subtitle.evaluate("(node) => { const range = document.createRange(); range.selectNodeContents(node); return new Set([...range.getClientRects()].map((rect) => Math.round(rect.top))).size; }")
            assert lines == 1, f"{route}: el subtítulo «{subtitle.inner_text()}» ocupa {lines} líneas"
            checked += 1
        # Ningún párrafo explicativo suelto: fuera de los desplegables y de los avisos, un <p> visible no pasa de 200 caracteres.
        long = page.evaluate("""() => [...document.querySelectorAll('main p')].filter((p) => p.checkVisibility() && !p.closest('details, [role=alert], [role=status], .term-tip, .bubble, [data-testid=tracking-notice]') && p.innerText.trim().length > 200).map((p) => p.innerText.trim().slice(0, 80))""")
        assert long == [], f"{route}: párrafos explicativos en pantalla: {long}"
    assert checked >= 8, checked
    # Las explicaciones siguen disponibles en el ⓘ.
    session.goto(f"#/scan/{job_id}/trackers")
    info = page.get_by_test_id("trackers").get_by_test_id("info").first
    expect(info.locator(".term-tip")).to_be_hidden()
    info.hover()
    expect(info.locator(".term-tip")).to_be_visible()
    expect(info.locator(".term-tip")).to_contain_text("mapa de dominios")
    session.assert_clean("modo compacto")


# --- 9. Texto suelto en todas las páginas ---

# Devuelve todo texto que no esté dentro del contenido de la aplicación: hijos de <body> distintos de #root
# con texto (pintado o no: también cuenta el que entra en el texto de la página), nodos de texto sueltos en
# <body> y texto de .app-root fuera del encabezado y de <main>.
OUTSIDE_TEXT = """() => {
  const stray = [];
  const root = document.getElementById('root');
  for (const node of document.body.childNodes) {
    if (node === root) continue;
    if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) stray.push('texto en body: ' + node.textContent.trim().slice(0, 60));
    if (node.nodeType !== Node.ELEMENT_NODE || ['SCRIPT', 'STYLE', 'LINK'].includes(node.tagName)) continue;
    const rect = node.getBoundingClientRect();
    const painted = node.checkVisibility({checkVisibilityCSS: true}) && rect.width > 0 && rect.height > 0
      && rect.bottom > 0 && rect.right > 0 && rect.top < document.documentElement.scrollHeight;
    if ((node.innerText || '').trim()) stray.push('en el texto de la página: <' + node.tagName.toLowerCase() + '#' + node.id + '> ' + node.innerText.trim().slice(0, 60));
    else if (painted && node.textContent.trim()) stray.push('pintado: <' + node.tagName.toLowerCase() + '#' + node.id + '> ' + node.textContent.trim().slice(0, 60));
  }
  const app = document.querySelector('.app-root');
  const walker = document.createTreeWalker(app, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.textContent.trim() && !node.parentElement.closest('header.app-header, main')) stray.push('fuera de encabezado y main: ' + node.textContent.trim().slice(0, 60));
  }
  const pageText = document.body.innerText.trim(), rootText = root.innerText.trim();
  if (pageText !== rootText) stray.push('el texto de la página no es el de la aplicación: …' + pageText.slice(-60));
  return stray;
}"""


def test_no_text_outside_the_content_on_any_route(session, shared, browser):
    """Antes, tras abrir el Resumen de un scan, al final de TODAS las páginas quedaba un dominio truncado
    (p. ej. «pdscrb.co»): el <span id="recharts_measurement_span"> que la librería de gráficos agrega al
    <body> para medir los rótulos del gráfico «Requests por organización» y nunca quita."""
    job_id = ensure_scan(shared, browser, "main", FIXTURE)
    page = session.page
    request_id = get_json(page, f"/api/scans/{job_id}/requests?page_size=1")["items"][0]["request_id"]
    groups = get_json(page, "/api/privacy/tests?limit=1")["items"]
    routes = ["", "#/analyze", "#/analyze?advanced=1", "#/history", "#/glossary", "#/exposure", f"#/scan/{job_id}",
              f"#/scan/{job_id}/findings", f"#/scan/{job_id}/trackers", f"#/scan/{job_id}/fingerprinting", f"#/scan/{job_id}/requests",
              f"#/scan/{job_id}/request/{request_id}"]
    if groups:
        routes.append(f"#/privacy/{groups[0]['group_id']}")

    # Origen exacto: el gráfico del Resumen crea el span de medición en <body>, con el último rótulo medido dentro.
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    page.wait_for_timeout(800)
    span = page.locator("body > #recharts_measurement_span")
    assert span.count() == 1 and span.evaluate("node => node.textContent.trim().length") > 0, "el gráfico ya no usa el span de medición: revisar este test"
    assert span.evaluate("node => getComputedStyle(node).visibility") == "hidden"
    assert page.evaluate(OUTSIDE_TEXT) == []
    # Al salir del Resumen el span se retira: no viaja a las demás páginas.
    session.goto("#/glossary")
    expect(page.get_by_test_id("glossary")).to_be_visible()
    assert page.locator("#recharts_measurement_span").count() == 0
    # Control positivo: la comprobación detecta un texto como el reportado, pintado o fuera de pantalla.
    page.evaluate("document.body.insertAdjacentHTML('beforeend', '<span id=suelto>pdscrb.co</span>')")
    assert page.evaluate(OUTSIDE_TEXT)[0] == "en el texto de la página: <span#suelto> pdscrb.co"
    page.evaluate("document.getElementById('suelto').remove()")

    checked = 0
    for theme in ("classic", "purple"):
        for presentation in (False, True):
            session.goto("")
            session.set_theme(theme)
            if page.evaluate("document.documentElement.classList.contains('presentation')") != presentation:
                page.get_by_test_id("presentation-toggle").click()
            # Se pasa primero por el Resumen (donde nace el span) y luego por cada ruta, sin recargar.
            for route in [f"#/scan/{job_id}"] + routes:
                page.evaluate("(hash) => { window.location.hash = hash || '#/'; }", route)
                expect(page.locator("main h1, main h2").first).to_be_visible()
                page.wait_for_timeout(350)
                stray = page.evaluate(OUTSIDE_TEXT)
                assert stray == [], f"{theme}{' + presentación' if presentation else ''} · {route or '#/'}: {stray}"
                checked += 1
    if page.evaluate("document.documentElement.classList.contains('presentation')"):
        page.get_by_test_id("presentation-toggle").click()
    session.set_theme("classic")
    print(f"\nTEXTO SUELTO: {checked} combinaciones de ruta × tema × modo revisadas ({len(routes)} rutas), 0 textos fuera del contenido")
    assert checked == 4 * (len(routes) + 1)
    session.assert_clean("texto suelto")


# --- 10. Logo ---


def test_logo_is_local_sized_and_readable_on_dark_backgrounds(session):
    page = session.page
    session.goto("")
    logo = page.get_by_test_id("header-logo")
    expect(logo).to_be_visible()
    state = lambda locator: locator.evaluate("""(img) => ({src: new URL(img.currentSrc || img.src).pathname, natural: img.naturalWidth, height: img.getBoundingClientRect().height,
      left: img.getBoundingClientRect().left, titleLeft: img.nextElementSibling.getBoundingClientRect().left,
      background: getComputedStyle(img).backgroundColor, radius: getComputedStyle(img).borderRadius})""")  # noqa: E731
    normal = state(logo)
    assert normal["src"] == "/logo-256.png" and normal["natural"] == 256, normal
    assert 34 <= normal["height"] <= 38 and normal["left"] < normal["titleLeft"], normal
    # Círculo blanco detrás: legible sobre cualquier fondo oscuro.
    assert normal["background"] == "rgb(255, 255, 255)" and normal["radius"] == "50%", normal
    hero = page.get_by_test_id("panel-logo")
    expect(hero).to_be_visible()
    assert hero.evaluate("img => img.getBoundingClientRect().height") >= 2.5 * normal["height"]
    for theme in ("purple", "classic"):
        session.set_theme(theme)
        expect(logo).to_be_visible()
    # Modo presentación: más grande.
    page.get_by_test_id("presentation-toggle").click()
    assert state(logo)["height"] >= normal["height"] * 1.8
    page.get_by_test_id("presentation-toggle").click()
    # Sobre un fondo oscuro forzado el dibujo sigue dentro de su círculo blanco (píxel central del logo: blanco o tinta, nunca el fondo).
    alpha = page.evaluate("""async () => {
      const img = new Image(); img.src = '/logo-256.png'; await img.decode();
      const canvas = document.createElement('canvas'); canvas.width = canvas.height = 256;
      const context = canvas.getContext('2d'); context.drawImage(img, 0, 0);
      const at = (x, y) => context.getImageData(x, y, 1, 1).data[3];
      return {corner: at(2, 2), centre: at(128, 128), inside: at(128, 40)};
    }""")
    assert alpha == {"corner": 0, "centre": 255, "inside": 255}, alpha
    # Iconos servidos localmente, con su tamaño.
    icons = page.evaluate("[...document.querySelectorAll('link[rel~=icon], link[rel=apple-touch-icon]')].map((link) => [link.rel, link.getAttribute('sizes'), new URL(link.href).pathname])")
    assert ["icon", "32x32", "/favicon-32.png"] in icons and ["icon", "16x16", "/favicon-16.png"] in icons and ["apple-touch-icon", "180x180", "/apple-touch-icon.png"] in icons
    for path, size in (("/favicon-32.png", 32), ("/favicon-16.png", 16), ("/apple-touch-icon.png", 180), ("/logo-256.png", 256), ("/favicon.ico", None)):
        response = page.request.get(f"{BASE_URL}{path}")
        assert response.ok and response.headers["content-type"].startswith("image/"), path
        if size:
            body = response.body()
            assert body[:8] == b"\x89PNG\r\n\x1a\n" and int.from_bytes(body[16:20], "big") == size == int.from_bytes(body[20:24], "big"), path
    # La CSP no cambió: sin orígenes nuevos.
    csp = page.request.get(f"{BASE_URL}/").headers["content-security-policy"]
    assert csp == ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.ipify.org; "
                   "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    session.assert_clean("logo")


# --- XSS y redacción en las vistas nuevas ---


def test_xss_payloads_never_execute_in_the_new_views(session, shared, browser):
    job_id = ensure_scan(shared, browser, "xss", XSS_PAGE)
    page = session.page
    visited = []

    def check(name):
        page.wait_for_timeout(250)  # da tiempo a que un onerror/onload inyectado llegara a dispararse
        session.assert_clean(name)
        assert_wording(session, name)
        visited.append(name)

    # Panel, con los scans de fixtures a la vista (el scan hostil entra en el ranking y en los atributos).
    session.goto("#/?fixtures=1")
    expect(page.get_by_test_id("panel-ranking")).to_be_visible()
    expect(page.get_by_test_id("panel-exposure-hash")).to_be_visible(timeout=20_000)
    check("panel")
    # Historial: título hostil en la lista, y un filtro con un payload como texto.
    session.goto("#/history")
    expect(page.get_by_test_id("recent")).to_contain_text("<img src=x onerror=")
    page.get_by_test_id("filter-site").fill('"><img src=x onerror=window.__XSS=1>')
    expect(page.get_by_test_id("recent")).to_contain_text("No hay scans con estos filtros")
    check("historial con filtro hostil")
    # Analizar: una URL con parámetros de seguimiento y un payload; el aviso la muestra como texto.
    session.goto("#/analyze?advanced=1")
    hostile = FIXTURE + "?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dwindow.__XSS%3D1%3E&utm_source=<img src=x onerror=window.__XSS=1>&<svg/onload=window.__XSS=1>=1&gclid=x"
    page.fill("#url", hostile)
    expect(page.get_by_test_id("tracking-notice")).to_be_visible()
    expect(page.get_by_test_id("tracking-params")).to_have_text("utm_source, gclid")
    expect(page.get_by_test_id("tracking-decision")).to_contain_text("&<svg/onload=window.__XSS=1")
    check("analizar con URL hostil")
    page.get_by_test_id("clean-url").click()
    check("analizar tras limpiar")
    # Scan hostil: tabla de atributos (URLs de script capturadas) e IDs de cuenta.
    session.goto(f"#/scan/{job_id}/fingerprinting")
    expect(page.get_by_test_id("browser-attributes")).to_be_visible()
    check("fingerprinting: atributos del navegador")
    session.goto(f"#/scan/{job_id}/trackers")
    expect(page.get_by_test_id("trackers")).to_be_visible()
    check("rastreadores")
    # Mi exposición comparada con el scan hostil: organizaciones y dominios capturados como texto.
    session.goto("#/exposure")
    expect(page.get_by_test_id("combined-hash")).to_be_visible(timeout=20_000)
    options = page.get_by_test_id("compare-select").locator("option").all_inner_texts()
    assert options[0] == "Sin comparación" and any("site.fixtures.test" in option for option in options)
    page.get_by_test_id("compare-select").select_option(job_id)
    expect(page.get_by_test_id("compare-summary")).to_be_visible()
    check("mi exposición comparada")
    # La API responde con un cuerpo hostil (control de que estas vistas pintan texto, no HTML).
    payload = '<img src=x onerror=window.__XSS=1>'
    panel = {"basis": payload, "level": "EVIDENCIA", "totals": {"sites": 1, "scans": 1, "requests": 1, "organizations": 1},
             "organizations": [{"entity": payload, "sites": 1, "of": 1, "requests": 1}],
             "attributes": {"read": [{"attribute": payload, "sites": 1, "of": 1, "organizations": [payload]}], "sent": []},
             "ranking": [{"site": payload, "job_id": job_id, "url": payload, "site_exposure_score": 50, "band": "Moderado", "trackers": 1, "third_party_domains": 1, "created_at": "2026-10-09T12:00:00+00:00"}]}
    page.route("**/api/panel*", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(panel)))
    session.goto("#/")
    expect(page.get_by_test_id("panel-organization")).to_contain_text("<img src=x onerror=")
    expect(page.get_by_test_id("panel-read-item")).to_contain_text("<img src=x onerror=")
    session.assert_clean("panel con respuesta hostil")
    visited.append("panel con respuesta hostil")
    page.unroute("**/api/panel*")
    print(f"\nXSS v1.2: {len(visited)} vistas nuevas revisadas, 0 ejecuciones, 0 violaciones de CSP, 0 diálogos")
    assert len(visited) >= 8


def test_analyze_with_advanced_options_screenshot(session):
    """Captura de «Analizar un sitio» con las opciones avanzadas abiertas (README)."""
    page = session.page
    session.goto("#/analyze?advanced=1")
    page.fill("#url", "https://ejemplo.cl/ofertas?utm_source=boletin&gclid=EAIaIQobChMI")
    expect(page.get_by_test_id("tracking-notice")).to_be_visible()
    page.get_by_test_id("scenario-rechazar").check()
    page.get_by_test_id("runs").select_option("2")
    expect(page.get_by_test_id("test-size")).to_contain_text("4 scans")
    assert_wording(session, "analizar con opciones avanzadas")
    session.assert_clean("analizar con opciones avanzadas")
    page.screenshot(path=str(SHOTS / "v12-analizar-opciones-avanzadas.png"), full_page=True)
