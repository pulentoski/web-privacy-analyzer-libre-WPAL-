"""Mi exposición: colector en el navegador, vista del servidor, opt-ins y comparación grupal de huellas."""

import json
import os
import re

from playwright.sync_api import expect

from .conftest import BASE_URL, CSP_HOOK, Session, ensure_scan
from .test_flow import FP_PAGE, shot

HOST = BASE_URL.split("://")[1]
PRESENTER_TOKEN = os.environ.get("PRESENTER_TOKEN", "")


def watch_requests(page):
    """Registra toda request que salga del navegador, con su cuerpo."""
    seen = []
    page.on("request", lambda request: seen.append({"url": request.url, "method": request.method, "body": request.post_data}))
    return seen


def external(seen):
    return [entry["url"] for entry in seen if HOST not in entry["url"] and not entry["url"].startswith("data:")]


def open_exposure(session):
    session.goto("#/exposure")
    expect(session.page.get_by_test_id("combined-hash")).to_be_visible(timeout=20_000)
    expect(session.page.get_by_test_id("server-headers")).to_be_visible()


def test_exposure_page_shows_what_the_browser_reveals(session):
    page = session.page
    seen = watch_requests(page)
    # v1.2: «Mi exposición» sale del menú; se llega por la tarjeta del Panel («Ver detalle»).
    session.goto("")
    assert page.get_by_test_id("nav-exposure").count() == 0
    page.get_by_test_id("exposure-detail").click()
    open_exposure(session)

    # Aviso de privacidad: dos líneas y el detalle en «Más información».
    notice = page.get_by_test_id("privacy-notice")
    expect(notice).to_contain_text("no se guardan")
    expect(notice.get_by_text("Qué se recolecta")).to_be_hidden()
    page.get_by_test_id("privacy-more").click()
    for fragment in ("Qué se recolecta", "Qué NO sale del navegador", "Qué sale", "no las guarda"):
        expect(notice).to_contain_text(fragment)
        expect(notice.get_by_text(fragment).first).to_be_visible()

    # Títulos técnicos de las cuatro secciones y subsecciones.
    titles = page.locator("[data-testid=exposure] h2").all_inner_texts()
    assert titles == [
        "Mi exposición", "1. Datos expuestos en la conexión (IP y cabeceras HTTP)", "2. Atributos accesibles mediante APIs del navegador",
        "3. Huella del navegador (hash combinado)", "4. Comparación de huellas en grupo",
    ], titles
    assert page.locator("[data-testid=exposure] h3").all_inner_texts() == ["Navegador y sistema", "Pantalla", "Hardware", "Huellas derivadas", "Permisos", "Red local"]

    # Lo que ve el servidor: IP etiquetada con honestidad y cabeceras.
    # El navegador de prueba llega por la red interna de Docker: acceso local, no "la IP del visitante".
    ip = page.get_by_test_id("observed-ip")
    assert ip.get_attribute("data-access") == "local"
    expect(ip).to_contain_text("Acceso local: el servidor ve la red interna de Docker (172.30.x). Desde otro equipo o desde internet se vería la IP real.")
    assert "IP pública observada" not in ip.inner_text()
    expect(page.get_by_test_id("summary-ip")).to_contain_text("Acceso local")
    assert not re.search(r"\d+\.\d+\.\d+\.\d+", page.get_by_test_id("summary-ip").inner_text())
    expect(page.get_by_test_id("ip-intel")).to_contain_text("no aplica (red privada)")
    expect(page.get_by_test_id("server-view")).to_contain_text("aunque JavaScript esté apagado")
    expect(page.get_by_test_id("header-user-agent").get_by_test_id("level")).to_have_text("Medio")
    headers = page.get_by_test_id("server-headers")
    expect(headers).to_contain_text("User-Agent")
    expect(headers).to_contain_text("es-CL")  # Accept-Language del contexto de prueba
    # Valor largo: truncado con "ver más"; completo al desplegarlo.
    assert page.evaluate("navigator.userAgent") not in headers.inner_text()
    page.get_by_test_id("header-user-agent").get_by_role("button", name=re.compile("ver más")).click()
    assert page.evaluate("navigator.userAgent") in headers.inner_text()

    # Colector: cada atributo con su estado; los no disponibles dicen por qué.
    rows = page.locator("[data-testid^=attr-]")
    assert rows.count() == 26
    statuses = {row.get_attribute("data-testid")[5:]: row.get_attribute("data-status") for row in rows.all()}
    assert set(statuses.values()) == {"DISPONIBLE", "NO_DISPONIBLE"}
    for name in ("user_agent", "platform", "languages", "timezone", "screen", "hardware_concurrency", "canvas", "audio", "fonts", "storage"):
        assert statuses[name] == "DISPONIBLE", name
    expect(page.get_by_test_id("attr-canvas")).to_contain_text(re.compile(r"[0-9a-f]{64}"))
    expect(page.get_by_test_id("attr-audio")).to_contain_text(re.compile(r"[0-9a-f]{64}"))
    # http://frontend:8080 no es contexto seguro: se explica qué queda fuera.
    assert page.evaluate("isSecureContext") is False
    expect(page.get_by_test_id("insecure-context")).to_contain_text("contexto seguro")
    for name in ("device_memory", "webgpu", "ua_client_hints", "crypto_subtle"):
        assert statuses[name] == "NO_DISPONIBLE", name
        expect(page.get_by_test_id(f"attr-{name}")).to_contain_text("contexto seguro")
    expect(page.get_by_test_id("lan-ip")).to_contain_text("No se intenta obtener")
    expect(page.get_by_test_id("lan-ip")).to_contain_text(".local")

    combined = page.get_by_test_id("combined-hash").inner_text()
    assert re.fullmatch(r"[0-9a-f]{64}", combined)

    # Tarjetas de resumen.
    summary = page.get_by_test_id("summary")
    for label in ("Atributos expuestos", "Huella combinada", "GPU detectada", "IP observada", "Contexto seguro", "Hora de lectura"):
        expect(summary).to_contain_text(label)
    available = sum(1 for status in statuses.values() if status == "DISPONIBLE")
    expect(page.get_by_test_id("summary-attributes")).to_contain_text(f"{available} de 26")
    expect(page.get_by_test_id("combined-short")).to_have_text(combined[:12])
    expect(page.get_by_test_id("summary-secure")).to_contain_text("No")
    assert re.search(r"\d{1,2}:\d{2}:\d{2}", page.get_by_test_id("summary-read-at").inner_text())

    # Nivel de identificabilidad por atributo: badge + justificación en el tooltip, rotulado como estimación.
    expect(page.get_by_test_id("level-legend")).to_contain_text("Estimación cualitativa")
    for name, level in (("canvas", "alto"), ("audio", "alto"), ("webgl", "alto"), ("fonts", "alto"), ("screen", "medio"), ("timezone", "medio"),
                        ("languages", "medio"), ("hardware_concurrency", "medio"), ("color_depth", "bajo"), ("cookies_enabled", "bajo")):
        badge = page.get_by_test_id(f"attr-{name}").get_by_test_id("level")
        assert badge.get_attribute("data-level") == level, name
        expect(badge).to_have_text(level.capitalize())
    assert page.locator("[data-testid^=attr-] [data-testid=level][data-level=no_disponible]").count() == 0
    assert "entropía" not in page.get_by_test_id("exposure").inner_text().replace("No equivale a bits de entropía", "")
    # La explicación vive en el tooltip ⓘ: oculta hasta enfocar o pasar el cursor.
    info = page.get_by_test_id("attr-canvas").get_by_test_id("info")
    tip = info.get_by_role("tooltip")
    expect(tip).to_be_hidden()
    info.hover()
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("estimación cualitativa")
    page.mouse.move(0, 0)
    # Valores largos truncados con "ver más".
    agent = page.get_by_test_id("attr-user_agent")
    assert len(page.evaluate("navigator.userAgent")) > 72
    expect(agent.get_by_role("button", name=re.compile("ver más"))).to_be_visible()
    agent.get_by_role("button", name=re.compile("ver más")).click()
    expect(agent).to_contain_text(page.evaluate("navigator.userAgent"))

    # «Actualizar» vuelve a leer todo: nueva request al servidor (sin caché) y nueva hora de lectura.
    before = len([entry for entry in seen if entry["url"].endswith("/api/exposure/server")])
    with page.expect_response(lambda response: response.url.endswith("/api/exposure/server")) as fresh:
        page.get_by_test_id("refresh").click()
    assert fresh.value.headers["cache-control"] == "no-store"
    expect(page.get_by_test_id("refresh")).to_have_text("Actualizar")
    assert len([entry for entry in seen if entry["url"].endswith("/api/exposure/server")]) == before + 1
    expect(page.get_by_test_id("read-at")).to_contain_text("Lectura:")
    assert page.get_by_test_id("combined-hash").inner_text() == combined
    expect(page.locator("text=No se puede afirmar que sea única")).to_be_visible()
    shot(page, "mi-exposicion")
    # Misma vista en modo presentación.
    page.get_by_test_id("presentation-toggle").click()
    assert page.evaluate("document.documentElement.classList.contains('presentation')")
    expect(page.get_by_test_id("summary")).to_be_visible()
    shot(page, "mi-exposicion-presentacion")
    page.get_by_test_id("presentation-toggle").click()

    # Privacidad por defecto: nada sale salvo la visita. Ni terceros, ni valores, ni hashes.
    page.wait_for_timeout(1500)
    assert external(seen) == [], external(seen)
    posts = [entry for entry in seen if entry["method"] != "GET"]
    assert posts == [], posts
    assert not [entry for entry in seen if "/api/exposure/compare" in entry["url"] or "ip-lookup" in entry["url"]]
    assert all("?" not in entry["url"] for entry in seen if "/api/exposure/" in entry["url"])  # nada en query
    assert page.evaluate("typeof RTCPeerConnection") == "function"  # existe, pero la página no la usó:
    session.assert_clean("mi exposición")


def test_page_never_asks_for_permissions_or_uses_webrtc(browser):
    context = browser.new_context(locale="es-CL")
    # Trampas instaladas antes que la página: cualquier solicitud de permiso o uso de WebRTC queda registrada.
    context.add_init_script("""
      window.__asked = [];
      const trap = (name) => function () { window.__asked.push(name); throw new Error('no permitido en el test'); };
      if (navigator.geolocation) { navigator.geolocation.getCurrentPosition = trap('geolocation'); navigator.geolocation.watchPosition = trap('geolocation'); }
      if (window.Notification) Notification.requestPermission = trap('notifications');
      if (navigator.mediaDevices) { navigator.mediaDevices.getUserMedia = trap('getUserMedia'); navigator.mediaDevices.enumerateDevices = trap('enumerateDevices'); }
      window.RTCPeerConnection = trap('RTCPeerConnection'); window.webkitRTCPeerConnection = trap('RTCPeerConnection');
    """)
    session = Session(context.new_page())
    try:
        open_exposure(session)
        session.page.wait_for_timeout(1000)
        assert session.page.evaluate("window.__asked") == []
        assert session.dialogs == []
    finally:
        context.close()


def test_public_ip_is_strictly_opt_in(session):
    page = session.page
    seen = watch_requests(page)
    # El tercero se simula: la prueba no debe depender de internet ni revelar la IP real.
    page.route("https://api.ipify.org/**", lambda route: route.fulfill(status=200, content_type="application/json", headers={"access-control-allow-origin": "*"}, body='{"ip":"8.8.8.8"}'))
    open_exposure(session)
    page.wait_for_timeout(1000)
    assert external(seen) == []  # sin consulta automática
    box = page.get_by_test_id("public-ip")
    expect(box).to_contain_text("ese tercero (api.ipify.org) verá su IP pública")
    expect(box).to_contain_text("No se consulta de forma automática")
    box.locator("summary").click()
    page.get_by_test_id("public-ip-button").click()
    result = page.get_by_test_id("public-ip-result")
    expect(result).to_contain_text("8.8.8.8")
    expect(result).to_contain_text("AS15169")
    expect(result).to_contain_text("aproximado")
    expect(result.get_by_role("link", name="IP Geolocation by DB-IP")).to_have_attribute("href", "https://db-ip.com")
    assert external(seen) == ["https://api.ipify.org/?format=json"]
    lookups = [entry for entry in seen if "ip-lookup" in entry["url"]]
    assert len(lookups) == 1 and lookups[0]["method"] == "POST" and "8.8.8.8" not in lookups[0]["url"]
    session.assert_clean("ip pública opt-in")


def test_room_comparison_sends_only_hashes(browser):
    """Tres asistentes: dos con el mismo navegador y uno distinto."""
    assert PRESENTER_TOKEN, "falta EXPOSURE_PRESENTER_TOKEN en .env (ver .env.example)"

    def attendee(**options):
        context = browser.new_context(locale="es-CL", **options)
        context.add_init_script(CSP_HOOK)
        session = Session(context.new_page())
        seen = watch_requests(session.page)
        open_exposure(session)
        return context, session, seen

    def join(session):
        page = session.page
        button = page.get_by_test_id("room-compare")
        expect(button).to_be_disabled()  # sin consentimiento no se puede enviar
        page.get_by_test_id("room-consent").check()
        button.click()
        expect(page.get_by_test_id("room-result")).to_be_visible()
        return int(page.get_by_test_id("room-participants").inner_text()), page.get_by_test_id("room-verdict").inner_text()

    # El administrador deja el grupo vacío.
    context, presenter, _ = attendee()
    presenter.goto("#/exposure?admin=1")
    expect(presenter.page.get_by_test_id("presenter")).to_contain_text("Administrador:")
    presenter.page.get_by_test_id("presenter-token").fill("token-incorrecto")
    presenter.page.get_by_test_id("presenter-purge").click()
    expect(presenter.page.get_by_test_id("presenter-status")).to_contain_text("incorrecto")
    presenter.page.get_by_test_id("presenter-token").fill(PRESENTER_TOKEN)
    presenter.page.get_by_test_id("presenter-purge").click()
    expect(presenter.page.get_by_test_id("presenter-status")).to_contain_text("Grupo purgado")
    context.close()

    contexts = []
    try:
        ctx_a, a, seen_a = attendee(viewport={"width": 1280, "height": 720})
        contexts.append(ctx_a)
        assert not [e for e in seen_a if "compare" in e["url"]]  # antes de aceptar no se envió nada
        assert join(a) == (1, "Su huella combinada es única en este grupo.")

        ctx_b, b, _ = attendee(viewport={"width": 1280, "height": 720})
        contexts.append(ctx_b)
        participants, verdict = join(b)
        assert participants == 2 and "la comparten 2 participantes" in verdict

        ctx_c, c, _ = attendee(viewport={"width": 1280, "height": 720}, timezone_id="America/Santiago", color_scheme="dark")
        contexts.append(ctx_c)
        participants, verdict = join(c)
        assert participants == 3 and "única en este grupo" in verdict
        expect(c.page.get_by_test_id("room-attr-timezone")).to_have_text("1 de 3")
        expect(c.page.get_by_test_id("room-attr-color_scheme")).to_have_text("1 de 3")
        expect(c.page.get_by_test_id("room-attr-user_agent")).to_have_text("3 de 3")
        shot(c.page, "comparacion-grupal")

        # Lo que salió del navegador de A: solo hashes. Ningún valor en claro.
        sent = [e for e in seen_a if "/api/exposure/compare" in e["url"]]
        assert len(sent) == 1 and sent[0]["method"] == "POST"
        body = json.loads(sent[0]["body"])
        assert set(body) == {"consent", "combined", "attributes"} and body["consent"] is True
        hashes = [body["combined"], *body["attributes"].values()]
        assert len(hashes) >= 20 and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
        clear_values = a.page.evaluate("[navigator.userAgent, navigator.platform, Intl.DateTimeFormat().resolvedOptions().timeZone, screen.width + 'x' + screen.height]")
        for value in clear_values:
            assert value not in sent[0]["body"], f"valor en claro enviado: {value}"

        # Reenviar no suma un participante.
        a.page.get_by_test_id("room-compare").click()
        expect(a.page.get_by_test_id("room-participants")).to_have_text("3")
        for session in (a, b, c):
            session.assert_clean("comparación grupal de huellas")
    finally:
        for context in contexts:
            context.close()


def usage_payload(job_id):
    """Cruce simulado de UN scan, con las etiquetas que antes quedaban como texto suelto bajo la última fila."""
    example = {"job_id": job_id, "site": "https://sitio-real.cl/", "call_ref": 1, "request_ref": None}
    item = lambda label, scans, when: {"label": label, "is_entity": False, "scans": scans, "last_scan_at": when, "example": example}  # noqa: E731
    read = [item("Google", 3, "2026-10-07T12:00:00+00:00"), item("on.aws", 1, "2026-10-06T12:00:00+00:00"), item("tracker-a.fixtures.test", 2, "2026-10-05T12:00:00+00:00")]
    sent = [item("on.aws", 1, "2026-10-06T12:00:00+00:00"), item("tracker-a", 1, "2026-10-05T12:00:00+00:00")]
    return {"attributes": {name: {"read": read, "sent": sent} for name in ("webgl_renderer", "canvas", "permissions", "fonts")}, "note": ""}


# Todo texto visible de la vista debe estar dentro de una sección del panel (o en las tarjetas / la leyenda)
# y dentro de su caja. Devuelve los textos que no lo cumplen.
STRAY_TEXT = """() => {
  const stray = [];
  const walker = document.createTreeWalker(document.querySelector('main'), NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode, text = node.textContent.trim(), parent = node.parentElement;
    if (!text || parent.closest('.sr-only')) continue;
    if (!parent.checkVisibility({checkVisibilityCSS: true, contentVisibilityAuto: true})) continue;
    const range = document.createRange(); range.selectNodeContents(node);
    const rects = [...range.getClientRects()].filter((rect) => rect.width > 0 && rect.height > 0);
    if (!rects.length) continue;
    const box = parent.closest('section.panel, [data-testid=summary], [data-testid=level-legend]');
    if (!box || !box.closest('[data-testid=exposure]')) { stray.push('fuera de sección: ' + text.slice(0, 60)); continue; }
    const limit = box.getBoundingClientRect();
    if (rects.some((rect) => rect.bottom > limit.bottom + 1 || rect.top < limit.top - 1 || rect.right > limit.right + 1 || rect.left < limit.left - 1))
      stray.push('desborda su sección: ' + text.slice(0, 60));
  }
  return stray;
}"""


def choose_compare(page, job_id):
    """Elige un scan en «Comparar con un scan» y espera a que la página marque los atributos."""
    select = page.get_by_test_id("compare-select")
    expect(select).to_be_visible()
    select.select_option(job_id)
    expect(page.get_by_test_id("compare-summary")).to_be_visible()


def test_compare_with_a_scan_marks_what_that_site_read_and_sent(session, shared, browser):
    """v1.2: la página muestra solo el navegador del visitante; el cruce con un scan es opcional y explícito."""
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    asked = []
    page.on("request", lambda request: "/api/exposure/scan-usage" in request.url and asked.append(request.url))
    open_exposure(session)
    # Sin scan elegido: ni líneas «Scans guardados…», ni marcas, ni consulta alguna al cruce.
    visible = page.get_by_test_id("exposure").inner_text()
    assert "Scans guardados" not in visible and "Suma de todos los scans" not in visible
    assert page.locator("[data-testid=usage], [data-testid=usage-note], [data-testid=compare-mark]").count() == 0
    assert asked == []
    assert page.evaluate(STRAY_TEXT) == []

    page.route("**/api/exposure/scan-usage?job_id=*", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(usage_payload(job_id))))
    choose_compare(page, job_id)
    assert asked and all(url.endswith(f"?job_id={job_id}") for url in asked), asked
    expect(page.get_by_test_id("compare-summary")).to_have_text("Ese sitio leyó 4 de 26 atributos y envió 4.")
    mark = page.get_by_test_id("attr-webgl").get_by_test_id("compare-mark")
    expect(mark.get_by_test_id("compare-read")).to_have_text(re.compile(r"^Leído por Google, on\.aws, tracker-a\.fixtures\.test$"))
    expect(mark.get_by_test_id("compare-sent")).to_have_text(re.compile(r"^Enviado a on\.aws, tracker-a$"))
    expect(page.get_by_test_id("attr-canvas").get_by_test_id("compare-mark")).to_be_visible()
    # Atributos que el sitio de ese scan no tocó no llevan marca.
    assert page.get_by_test_id("attr-cookies_enabled").get_by_test_id("compare-mark").count() == 0
    # Las marcas viven solo dentro de la fila de su atributo.
    assert page.locator("[data-testid=compare-mark]").evaluate_all("nodes => nodes.length === 4 && nodes.every(node => node.closest('[data-testid^=attr-]'))")
    assert page.evaluate(STRAY_TEXT) == []
    # Quitar la comparación devuelve la página a «solo el navegador del visitante».
    page.get_by_test_id("compare-select").select_option("")
    expect(page.locator("[data-testid=compare-mark]")).to_have_count(0)
    assert page.get_by_test_id("compare-summary").count() == 0
    # Cada nombre enlaza a su evidencia.
    choose_compare(page, job_id)
    mark.get_by_test_id("compare-link").first.click()
    expect(page.get_by_test_id("fingerprinting").or_(page.get_by_test_id("request-detail"))).to_be_visible()
    assert "/scan/" in page.url
    session.assert_clean("comparar con un scan")


def test_no_text_outside_the_panel_sections(session, shared, browser):
    """Ningún texto visible queda fuera de las secciones del panel, tampoco con todo desplegado ni en modo presentación."""
    job_id = ensure_scan(shared, browser, "fp", FP_PAGE)
    page = session.page
    page.route("**/api/exposure/scan-usage?job_id=*", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(usage_payload(job_id))))
    open_exposure(session)
    choose_compare(page, job_id)
    expect(page.get_by_test_id("attr-permissions").get_by_test_id("compare-mark")).to_be_visible()
    # La comprobación detecta de verdad un texto suelto (control positivo).
    page.evaluate("document.querySelector('[data-testid=exposure]').insertAdjacentHTML('beforeend', '<span id=suelto>on.aws</span>')")
    assert page.evaluate(STRAY_TEXT) == ["fuera de sección: on.aws"]
    page.evaluate("document.getElementById('suelto').remove()")
    for presentation in (False, True):
        if page.evaluate("document.documentElement.classList.contains('presentation')") != presentation:
            page.get_by_test_id("presentation-toggle").click()
        page.evaluate("document.querySelectorAll('[data-testid=exposure] details').forEach((node) => { node.open = false; })")
        assert page.evaluate(STRAY_TEXT) == [], f"presentación={presentation}, cerrado"
        # Con todos los desplegables abiertos y la comparación activa, todo sigue dentro de su fila y de su sección.
        page.evaluate("document.querySelectorAll('[data-testid=exposure] details').forEach((node) => { node.open = true; })")
        expect(page.get_by_test_id("attr-permissions").get_by_test_id("compare-sent")).to_contain_text("tracker-a")
        assert page.evaluate(STRAY_TEXT) == [], f"presentación={presentation}, desplegado"
    page.get_by_test_id("presentation-toggle").click()
    # Lo último de la página es la sección 4: después no hay nada.
    assert page.evaluate("document.querySelector('[data-testid=exposure]').lastElementChild.querySelector('h2').textContent") == "4. Comparación de huellas en grupo"
    assert page.evaluate("[...document.querySelector('main').childNodes].filter((n) => n.nodeType === 3 && n.textContent.trim()).length") == 0
    session.assert_clean("texto fuera de las secciones")


REMOVE_APIS = """
  // Simula un navegador endurecido o antiguo: estas APIs no existen o están bloqueadas.
  delete Navigator.prototype.hardwareConcurrency;
  delete Navigator.prototype.plugins;
  delete Navigator.prototype.permissions;
  delete window.OfflineAudioContext; delete window.webkitOfflineAudioContext;
  HTMLCanvasElement.prototype.getContext = function () { return null; };
  Object.defineProperty(Document.prototype, 'fonts', {get() { return undefined; }, configurable: true});
  Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('bloqueado', 'SecurityError'); }, configurable: true});
  Object.defineProperty(Navigator.prototype, 'languages', {get() { throw new DOMException('bloqueado', 'SecurityError'); }, configurable: true});
"""


def test_missing_or_blocked_apis_are_reported_as_unavailable_with_a_reason(browser):
    context = browser.new_context(locale="es-CL")
    context.add_init_script(CSP_HOOK)
    context.add_init_script(REMOVE_APIS)
    session = Session(context.new_page())
    page = session.page
    try:
        open_exposure(session)
        for name in ("hardware_concurrency", "plugins", "permissions", "audio", "canvas", "webgl", "fonts", "languages"):
            row = page.get_by_test_id(f"attr-{name}")
            assert row.get_attribute("data-status") == "NO_DISPONIBLE", name
            expect(row).to_contain_text("No disponible")
            text = row.get_by_test_id("value-cell").inner_text()
            # Hay un motivo, y no hay ningún valor: ni un hash, ni un número, ni una lista inventada.
            assert len(text) > 15 and not re.search(r"[0-9a-f]{64}", text), (name, text)
        expect(page.get_by_test_id("attr-languages")).to_contain_text("SecurityError")
        expect(page.get_by_test_id("attr-webgl")).to_contain_text("WebGL no está disponible")
        # El almacenamiento bloqueado se muestra como false, no se omite ni rompe la página.
        expect(page.get_by_test_id("attr-storage")).to_contain_text("localStorage: false")
        expect(page.get_by_test_id("attr-storage")).to_contain_text("sessionStorage: true")
        # Lo que sí existe se sigue leyendo, y la huella combinada se calcula igual.
        assert page.get_by_test_id("attr-user_agent").get_attribute("data-status") == "DISPONIBLE"
        assert re.fullmatch(r"[0-9a-f]{64}", page.get_by_test_id("combined-hash").inner_text())
        assert session.page_errors == [] and session.dialogs == []
    finally:
        context.close()
