"""Control negativo del detector de XSS.

El 0 de test_xss.py solo vale si el detector falla cuando hay algo que detectar. Aquí se
abre una vista vulnerable a propósito (existe solo en el build `frontend-vulnerable`) con
el mismo scan de payloads, y se exige que `assert_clean` la marque como fallida.
"""

import os
import re
import urllib.request

import pytest
from playwright.sync_api import expect

from .conftest import BASE_URL, CSP_HOOK, Session, ensure_scan
from .test_xss import XSS_PAGE

CONTROL = os.environ.get("CONTROL_URL", "http://frontend-vulnerable:8080")
CONTROL_NO_CSP = os.environ.get("CONTROL_URL_NO_CSP", "http://frontend-vulnerable:8081")


def open_control(browser, base, job_id):
    context = browser.new_context()
    context.add_init_script(CSP_HOOK)
    session = Session(context.new_page())
    session.page.goto(f"{base}/#/__xss-control/{job_id}")
    expect(session.page.get_by_test_id("xss-control-sink")).to_be_attached(timeout=15_000)
    session.page.wait_for_timeout(800)  # tiempo para que el onerror inyectado se dispare (o lo bloquee la CSP)
    return context, session


def test_detector_flags_the_vulnerable_view_without_csp(shared, browser):
    """Sin CSP el payload SE EJECUTA: el detector debe verlo."""
    job_id = ensure_scan(shared, browser, "xss", XSS_PAGE)
    context, session = open_control(browser, CONTROL_NO_CSP, job_id)
    try:
        assert session.page.evaluate("window.__XSS") >= 1, "el control no ejecutó el payload: no sirve como control"
        with pytest.raises(AssertionError, match="se ejecutó un payload"):
            session.assert_clean("control sin CSP")
    finally:
        context.close()


def test_csp_blocks_the_vulnerable_view_and_the_detector_still_flags_it(shared, browser):
    """Con la CSP de producción el payload NO se ejecuta, pero queda inyectado y la CSP lo reporta."""
    job_id = ensure_scan(shared, browser, "xss", XSS_PAGE)
    context, session = open_control(browser, CONTROL, job_id)
    try:
        state = session.page.evaluate("() => ({xss: window.__XSS ?? null, csp: window.__cspViolations, injected: document.querySelectorAll('img[src=\"x\"]').length})")
        assert state["xss"] is None, "la CSP no bloqueó la ejecución"
        assert state["injected"] >= 1 and any("script-src" in violation for violation in state["csp"]), state
        with pytest.raises(AssertionError, match="violaciones de CSP"):
            session.assert_clean("control con CSP")
    finally:
        context.close()


def test_production_bundle_does_not_contain_the_vulnerable_view(session):
    html = urllib.request.urlopen(f"{BASE_URL}/", timeout=10).read().decode()
    assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', html)
    assert any(asset.endswith(".js") for asset in assets)
    for asset in assets:
        body = urllib.request.urlopen(f"{BASE_URL}{asset}", timeout=10).read().decode("utf-8", "replace")
        # (La cadena "dangerouslySetInnerHTML" sí aparece: es parte de React. Lo que no debe estar es la vista.)
        for marker in ("CONTROL NEGATIVO", "xss-control-sink", "XssControl", "__xss-control"):
            assert marker not in body, f"{asset} contiene {marker}"
    for name in re.findall(r"XssControl[-\w]*\.js", html):
        raise AssertionError(f"el index referencia {name}")
    # El build de control sí la tiene (si no, la comprobación anterior no probaría nada).
    control_html = urllib.request.urlopen(f"{CONTROL}/", timeout=10).read().decode()
    control_js = "".join(
        urllib.request.urlopen(f"{CONTROL}{asset}", timeout=10).read().decode("utf-8", "replace")
        for asset in re.findall(r'(?:src|href)="(/assets/[^"]+\.js)"', control_html)
    )
    assert "XssControl" in control_js
    # Y en producción la ruta no existe: cae en la página de inicio, sin ejecutar nada.
    session.goto("#/__xss-control/00000000-0000-0000-0000-000000000000")
    expect(session.page.get_by_test_id("panel")).to_be_visible()  # v1.2: el inicio es el Panel
    assert session.page.get_by_test_id("xss-control").count() == 0
    session.assert_clean("ruta de control en producción")
