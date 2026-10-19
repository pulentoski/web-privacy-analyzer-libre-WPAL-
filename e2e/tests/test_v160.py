"""v1.6.0 (docs/adr/042): el Resumen en bento carga en los dos temas (y en modo presentación) sin errores de consola, con
sus secciones en orden, sin scroll horizontal en móvil y con contraste AA. Deja las capturas del Resumen de cada tema."""

from playwright.sync_api import expect

from .conftest import ensure_scan
from .test_f10 import CONTRAST_JS, SHOTS
from .test_flow import FIXTURE

ORDER = ["summary-header", "summary-bento", "summary-stats", "relations", "chart-category", "chart-org", "recipients", "data-categories",
         "fold-cookies", "fold-services", "fold-levels", "limits-notice"]
NAMES = {"classic": "clasico", "purple": "unidad-purpura"}
# Aviso de Chromium por servir la interfaz en http://frontend:8080 dentro de la red de test (origen no «trustworthy»):
# es del entorno, no de la página. Cualquier otro error de consola hace fallar el test.
ENVIRONMENT_NOTICES = ("The Cross-Origin-Opener-Policy header has been ignored",)


def test_summary_loads_in_both_themes_without_console_errors(session, shared, browser):
    job_id = ensure_scan(shared, browser, "main", FIXTURE)
    page = session.page
    console = []
    page.on("console", lambda message: console.append(message.text)
            if message.type == "error" and not message.text.startswith(ENVIRONMENT_NOTICES) else None)
    for theme in ("classic", "purple"):
        for presentation in (False, True):
            session.goto("")
            session.set_theme(theme)
            if page.evaluate("document.documentElement.classList.contains('presentation')") != presentation:
                page.get_by_test_id("presentation-toggle").click()
            session.goto(f"#/scan/{job_id}")
            expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
            expect(page.get_by_test_id("recipient-row").first).to_be_visible()
            # Secciones en orden de arriba abajo.
            tops = [page.get_by_test_id(test_id).first.bounding_box()["y"] for test_id in ORDER]
            assert tops == sorted(tops), (theme, presentation, list(zip(ORDER, tops)))
            expect(page.get_by_test_id("summary-validity")).to_be_visible()
            expect(page.get_by_test_id("summary-stats").locator(".vignette")).to_have_count(8)
            # Contraste con todo abierto (plegados, «Cómo se calculó», protocolo).
            for summary in page.locator("[data-testid=dashboard] details > summary").all():
                summary.click()
            page.wait_for_timeout(300)
            outcome = page.evaluate(CONTRAST_JS)
            assert outcome["checked"] > 40 and outcome["failures"] == [], (theme, presentation, outcome["failures"][:8])
            if not presentation:
                page.evaluate("document.querySelectorAll('[data-testid=dashboard] details[open]').forEach((node) => { node.open = false; })")
                SHOTS.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(SHOTS / f"v160-resumen-{NAMES[theme]}.png"), full_page=True)
                # Móvil: el bento se apila y no hay scroll horizontal (el mapa se desplaza dentro de su caja).
                page.set_viewport_size({"width": 390, "height": 844})
                page.wait_for_timeout(300)
                assert page.evaluate("document.scrollingElement.scrollWidth <= document.scrollingElement.clientWidth + 1"), "scroll horizontal en móvil"
                boxes = [page.get_by_test_id(test_id).bounding_box() for test_id in ("card-exposure", "highlights", "measurement")]
                assert boxes[0]["y"] < boxes[1]["y"] < boxes[2]["y"], "en móvil el bento se apila"
                page.set_viewport_size({"width": 1366, "height": 900})
    if page.evaluate("document.documentElement.classList.contains('presentation')"):
        page.get_by_test_id("presentation-toggle").click()
    session.set_theme("classic")
    assert console == [], console
    session.assert_clean("Resumen v1.6.0")
