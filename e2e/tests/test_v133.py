"""v1.3.3 — ilustración que gira mientras el scan está en curso y títulos de panel con franja de
advertencia en «Unidad Púrpura» (Clásico sin cambios)."""

from playwright.sync_api import expect

from .conftest import BASE_URL
from .test_v13 import CSP, FIXTURE, SHOTS

SPINNER = """(img) => { const s = getComputedStyle(img), r = img.getBoundingClientRect(); const url = new URL(img.currentSrc || img.src);
  return {path: url.pathname, local: url.origin === location.origin, radius: s.borderTopLeftRadius, animation: s.animationName, iterations: s.animationIterationCount,
          border: s.borderTopColor, shadow: s.boxShadow, width: r.width, height: r.height, alt: img.alt, natural: img.naturalWidth}; }"""
HEAD = """(node) => { const s = getComputedStyle(node), h = getComputedStyle(node.querySelector('h2'));
  return {image: s.backgroundImage, size: s.backgroundSize, border: s.borderBottomColor, borderWidth: s.borderBottomWidth, background: s.backgroundColor,
          marginLeft: s.marginLeft, title: h.color, paddingTop: parseFloat(s.paddingTop)}; }"""
ORANGE, RED, PURPLE = "rgb(255, 122, 26)", "rgb(255, 90, 110)", "rgb(107, 47, 179)"


def test_spinner_turns_while_the_scan_runs_and_disappears_when_it_ends(session):
    page = session.page
    session.goto("#/analyze")
    session.set_theme("purple")
    session.start_scan(FIXTURE)
    spinner = page.locator("[data-testid=progress] [data-testid=scan-spinner] img")
    expect(spinner).to_be_visible()
    page.wait_for_function("document.querySelector('[data-testid=scan-spinner] img').naturalWidth > 0")
    purple = spinner.evaluate(SPINNER)
    # Local, con texto alternativo, circular (no cuadrada) y girando sin fin; borde verde neón con brillo.
    assert purple["path"] in ("/scanning-320.webp", "/scanning-320.jpg") and purple["local"] and purple["natural"] == 320, purple
    assert "Scan en curso" in purple["alt"]
    assert purple["radius"] == "50%" and abs(purple["width"] - purple["height"]) < 1 and purple["width"] >= 60, purple
    assert purple["animation"] == "scan-spin" and purple["iterations"] == "infinite", purple
    assert purple["border"] == "rgb(124, 255, 79)" and purple["shadow"] != "none", purple
    SHOTS.mkdir(parents=True, exist_ok=True)
    page.get_by_test_id("progress").screenshot(path=str(SHOTS / "progreso-girando-unidad-purpura.png"))
    # Clásico: mismo giro, borde neutro y sin brillo.
    session.set_theme("classic")
    if spinner.count():
        classic = spinner.evaluate(SPINNER)
        assert classic["animation"] == "scan-spin" and classic["radius"] == "50%" and classic["border"] == "rgb(100, 116, 139)" and classic["shadow"] == "none", classic
        page.get_by_test_id("progress").screenshot(path=str(SHOTS / "progreso-girando-clasico.png"))
    # prefers-reduced-motion: sin giro (pulso suave).
    page.emulate_media(reduced_motion="reduce")
    if spinner.count():
        assert spinner.evaluate("img => getComputedStyle(img).animationName") == "scan-pulse"
    page.emulate_media(reduced_motion="no-preference")
    # Al terminar, la ilustración desaparece.
    assert session.wait_finished() == "done"
    expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
    expect(page.get_by_test_id("scan-spinner")).to_have_count(0)
    for path, magic, limit in (("/scanning-320.webp", b"RIFF", 30_000), ("/scanning-320.jpg", b"\xff\xd8", 40_000)):
        response = page.request.get(f"{BASE_URL}{path}")
        assert response.ok and response.body()[: len(magic)] == magic and len(response.body()) < limit, path
    assert page.request.get(f"{BASE_URL}/").headers["content-security-policy"] == CSP
    session.assert_clean("ilustración giratoria")


def test_panel_titles_carry_the_warning_stripe_only_in_purple_unit(session):
    page = session.page
    views = [("panel", "", "panel-exposure"), ("analizar", "#/analyze", "har-import"), ("historial", "#/history", "history-view"),
             ("glosario", "#/glossary", "glossary"), ("mi exposición", "#/exposure", "combined-hash")]
    session.goto("")
    session.set_theme("purple")
    for name, route, test_id in views:
        session.goto(route)
        expect(page.get_by_test_id(test_id).first).to_be_visible()
        heads = page.locator(".panel-head")
        assert heads.count() >= 1, name
        head = heads.first.evaluate(HEAD)
        # Franja diagonal arriba (el texto queda debajo de ella), fondo oscuro y línea del tono naranja.
        assert "repeating-linear-gradient" in head["image"] and head["size"].startswith("100%"), (name, head)
        assert head["border"] == ORANGE and head["borderWidth"] == "1px" and head["background"] == "rgb(43, 21, 3)", (name, head)
        assert head["paddingTop"] >= 12 and head["title"] == "rgb(236, 230, 247)", (name, head)
        tones = page.evaluate("[...new Set([...document.querySelectorAll('.panel-head')].map((node) => node.dataset.tone))]")
        assert set(tones) <= {"alert", "danger", "neutral"}, (name, tones)
    page.screenshot(path=str(SHOTS / "encabezados-unidad-purpura.png"))
    # Variantes: rojo para avisos de bloqueo, morado con verde para paneles neutros.
    variants = page.locator(".panel-head").first.evaluate("""(node) => { const out = {};
      for (const tone of ['danger', 'neutral']) { node.dataset.tone = tone; const s = getComputedStyle(node); out[tone] = [s.borderBottomColor, s.backgroundColor, s.backgroundImage]; }
      node.dataset.tone = 'alert'; return out; }""")
    assert variants["danger"][0] == RED and variants["danger"][1] == "rgb(58, 10, 18)", variants
    assert variants["neutral"][0] == PURPLE and "rgb(124, 255, 79)" in variants["neutral"][2], variants
    # Clásico sin cambios: el título no lleva franja, fondo ni márgenes propios.
    session.set_theme("classic")
    for name, route, test_id in views[:2]:
        session.goto(route)
        expect(page.get_by_test_id(test_id).first).to_be_visible()
        head = page.locator(".panel-head").first.evaluate(HEAD)
        assert head["image"] == "none" and head["borderWidth"] == "0px" and head["marginLeft"] == "0px" and head["background"] == "rgba(0, 0, 0, 0)", (name, head)
    session.assert_clean("encabezados")
