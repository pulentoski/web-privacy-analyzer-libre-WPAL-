"""E2E de la interfaz con un navegador real contra el frontend (nginx + API + worker reales)."""

import os
import re
import time

import pytest
from playwright.sync_api import expect, sync_playwright

BASE_URL = os.environ.get("BASE_URL", "http://frontend:8080")
SCAN_TIMEOUT_MS = 120_000

# Se instala antes que el código de la app: registra cualquier violación de CSP.
CSP_HOOK = """
window.__cspViolations = [];
document.addEventListener('securitypolicyviolation', (event) => {
  window.__cspViolations.push(event.violatedDirective + ' | ' + event.blockedURI + ' | ' + (event.sample || ''));
});
"""


class Session:
    """Una página con los detectores de ejecución no deseada conectados."""

    def __init__(self, page):
        self.page = page
        self.dialogs = []
        self.page_errors = []
        page.on("dialog", lambda dialog: (self.dialogs.append(dialog.message), dialog.dismiss()))
        page.on("pageerror", lambda error: self.page_errors.append(str(error)))

    def goto(self, hash_path=""):
        self.page.goto(f"{BASE_URL}/{hash_path}")

    def start_scan(self, url):
        self.goto("#/analyze")
        self.page.fill("#url", url)
        self.page.click("button[type=submit]")
        expect(self.page.get_by_test_id("scan-url")).to_be_visible(timeout=15_000)
        return re.search(r"#/scan/([0-9a-f-]{36})", self.page.url).group(1)

    def wait_finished(self):
        """Etapa final del scan: "done" o "failed" (el texto visible es su nombre en español)."""
        stage = self.page.get_by_test_id("scan-stage")
        expect(stage).to_have_attribute("data-stage", re.compile("done|failed"), timeout=SCAN_TIMEOUT_MS)
        return stage.get_attribute("data-stage")

    def scan(self, url):
        job_id = self.start_scan(url)
        assert self.wait_finished() == "done"
        expect(self.page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
        return job_id

    def open_tech(self, test_id="request-tech"):
        """Abre el «detalle técnico» si está cerrado (F10: va debajo de la frase técnica)."""
        block = self.page.get_by_test_id(test_id).first
        expect(block).to_be_visible()
        if block.get_attribute("data-open") != "true":
            self.page.get_by_test_id(f"{test_id}-toggle").first.click()
        expect(self.page.get_by_test_id(f"{test_id}-content").first).to_be_visible()

    def open_all(self, test_id):
        """Abre todos los bloques «detalle técnico» de ese tipo que haya en la vista."""
        for _ in range(400):
            # Solo los que están a la vista (los de un grupo plegado no se pueden pulsar).
            closed = self.page.locator(f"[data-testid={test_id}][data-open=false] [data-testid={test_id}-toggle]:visible")
            if closed.count() == 0:
                return
            closed.first.click()
        raise AssertionError(f"demasiados bloques {test_id} sin abrir")

    def set_theme(self, theme):
        self.page.get_by_test_id(f"theme-{theme}").click()
        expect(self.page.locator("html")).to_have_attribute("data-theme", theme)

    def assert_clean(self, where=""):
        """Nada capturado se ejecutó: sin marca de XSS, sin diálogos, sin violaciones de CSP, sin errores."""
        state = self.page.evaluate("() => ({xss: window.__XSS, csp: window.__cspViolations || null, injected: document.querySelectorAll('img[src=\"x\"], svg[onload], script:not([src])').length})")
        assert state["xss"] is None, f"{where}: se ejecutó un payload (window.__XSS={state['xss']})"
        assert state["csp"] == [], f"{where}: violaciones de CSP: {state['csp']}"
        assert state["injected"] == 0, f"{where}: hay elementos inyectados en el DOM"
        assert self.dialogs == [], f"{where}: se abrió un diálogo: {self.dialogs}"
        assert self.page_errors == [], f"{where}: errores de JavaScript: {self.page_errors}"


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture(scope="session", autouse=True)
def leave_no_test_scans(browser):
    """Las pruebas no dejan scans en el historial (v1.4.2): al terminar se borran, por la API, los de hosts de prueba
    (sitio de fixtures, .example, HAR sintéticos). Los scans de sitios reales no se tocan."""
    yield
    context = browser.new_context()
    try:
        for _ in range(20):
            items = context.request.get(f"{BASE_URL}/api/scans?limit=200").json().get("items", [])
            leftovers = [item for item in items if item.get("is_test")]
            if not leftovers:
                break
            for item in leftovers:
                if item.get("stage") in ("done", "failed"):
                    context.request.delete(f"{BASE_URL}/api/scans/{item['job_id']}")
            if any(item.get("stage") not in ("done", "failed") for item in leftovers):
                time.sleep(3)  # un scan aún en curso: se borra en la vuelta siguiente
    finally:
        context.close()


@pytest.fixture
def session(browser):
    context = browser.new_context(viewport={"width": 1366, "height": 900}, accept_downloads=True, locale="es-CL")
    context.add_init_script(CSP_HOOK)
    page = context.new_page()
    page.set_default_timeout(20_000)
    yield Session(page)
    context.close()


@pytest.fixture(scope="session")
def shared(browser):
    """Scans compartidos entre tests (cada scan cuenta para el rate limit)."""
    return {}


def ensure_scan(shared, browser, key, url):
    if key not in shared:
        context = browser.new_context(viewport={"width": 1366, "height": 900})
        context.add_init_script(CSP_HOOK)
        session = Session(context.new_page())
        session.page.set_default_timeout(20_000)
        shared[key] = session.scan(url)
        context.close()
    return shared[key]
