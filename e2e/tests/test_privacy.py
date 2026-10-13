"""Opciones avanzadas (ex Privacy Test) de extremo a extremo: formulario → progreso → comparación (criterios 2, 3, 6, 7 y 8 de F7)."""

import re

from playwright.sync_api import expect

from .conftest import BASE_URL
from .test_flow import shot

CMP = "http://site.fixtures.test/cmp/"
UNKNOWN = "http://site.fixtures.test/cmp/unknown"
COOKIELESS = "http://site.fixtures.test/cookieless/"
FIXTURE = "http://site.fixtures.test/"
FORBIDDEN_WORDS = re.compile(r"\ban[oó]nim[oa]s?\b|ocult[oa]s?\b|ocultar|invisible|indetectable", re.IGNORECASE)
TIMEOUT = 240_000


def start_test(session, url, scenarios=("sin_interaccion",), profiles=("real",), runs=1):
    page = session.page
    # v1.2: el formulario es la sección «Opciones avanzadas» de «Analizar un sitio».
    session.goto("")
    page.get_by_test_id("nav-scans").click()
    open_advanced(page)
    page.fill("#url", url)
    for scenario in ("sin_interaccion", "aceptar", "rechazar"):
        page.get_by_test_id(f"scenario-{scenario}").set_checked(scenario in scenarios)
    for profile in ("real", "windows-chrome-es-cl", "macos-chrome-es-cl", "android-chrome-es-cl", "incoherente-demo"):
        page.get_by_test_id(f"profile-{profile}").set_checked(profile in profiles)
    page.get_by_test_id("runs").select_option(str(runs))
    total = len(scenarios) * len(profiles) * runs
    expect(page.get_by_test_id("test-size")).to_contain_text(f"{total} scans")
    page.get_by_test_id("analyze-submit").click()
    progress = page.get_by_test_id("privacy-progress")
    expect(progress).to_be_visible()
    expect(progress).to_contain_text(f"de {total} scans")
    return total


def open_advanced(page):
    advanced = page.get_by_test_id("advanced")
    expect(advanced).to_be_visible()
    if advanced.get_attribute("open") is None:
        page.get_by_test_id("advanced-toggle").click()
    expect(page.get_by_test_id("runs")).to_be_visible()


def wait_result(session):
    expect(session.page.get_by_test_id("privacy-progress")).to_have_attribute("data-status", "completed", timeout=TIMEOUT)
    expect(session.page.get_by_test_id("privacy-result")).to_be_visible()


def assert_wording(session, where):
    text = session.page.locator("body").inner_text()
    found = FORBIDDEN_WORDS.findall(text)
    assert found == [], f"{where}: la interfaz usa {found}"
    session.assert_clean(where)


def test_form_explains_limits_and_validates(session):
    page = session.page
    # #/privacy redirige a «Analizar un sitio» con las opciones avanzadas abiertas.
    session.goto("#/privacy")
    expect(page).to_have_url(re.compile(r"#/analyze\?advanced=1$"))
    expect(page.get_by_test_id("advanced")).to_have_attribute("open", "")
    expect(page.get_by_test_id("ip-note")).to_contain_text("No cambia la dirección IP")
    # Sin tocar nada, la selección por defecto es un scan simple.
    expect(page.get_by_test_id("test-size")).to_have_attribute("data-simple", "true")
    expect(page.get_by_test_id("analyze-submit")).to_have_text("Analizar")
    # Tamaño del grupo en vivo y tope por grupo.
    page.fill("#url", FIXTURE)
    for scenario in ("aceptar", "rechazar"):
        page.get_by_test_id(f"scenario-{scenario}").check()
    page.get_by_test_id("profile-windows-chrome-es-cl").check()
    page.get_by_test_id("runs").select_option("3")
    expect(page.get_by_test_id("test-size")).to_contain_text("18 scans")
    expect(page.get_by_test_id("analyze-submit")).to_be_disabled()
    page.get_by_test_id("runs").select_option("1")
    expect(page.get_by_test_id("analyze-submit")).to_be_enabled()
    expect(page.get_by_test_id("analyze-submit")).to_have_text("Analizar (6 scans)")
    page.fill("#url", "ejemplo")
    page.get_by_test_id("analyze-submit").click()
    expect(page.get_by_test_id("field-error")).to_contain_text("http://")
    assert_wording(session, "formulario")


def test_runs_and_stability(session):
    """runs=3 sobre el fixture: cada tracker aparece en 3 de 3 corridas y los conteos tienen mediana y rango."""
    start_test(session, FIXTURE, runs=3)
    page = session.page
    wait_result(session)
    assert page.locator("[data-testid=group-job][data-done=true]").count() == 3
    cell = page.get_by_test_id("cell")
    expect(cell).to_have_count(1)
    expect(cell).to_contain_text("3 de 3")
    expect(cell).to_contain_text("21")  # requests: mediana 21 en las tres corridas
    page.get_by_test_id("stability").locator("summary").click()
    items = page.get_by_test_id("stability-item").all_inner_texts()
    assert len(items) == 2
    assert any("tracker-a.fixtures.test" in item and "apareció en 3 de 3 corridas" in item for item in items)
    assert any("cdn-b.fixtures.test" in item and "apareció en 3 de 3 corridas" in item for item in items)
    # Sin escenarios de consentimiento ni perfiles, no hay diferencias que mostrar.
    assert page.get_by_test_id("differences").count() == 0
    # Identificador del fixture (uid fijo en el script): mismo valor en corridas limpias.
    ids = page.get_by_test_id("persistent-id")
    assert ids.count() >= 1
    expect(ids.first).to_contain_text("3 de 3 corridas con contextos nuevos")
    assert_wording(session, "estabilidad")


def test_consent_scenarios(session):
    start_test(session, CMP, scenarios=("sin_interaccion", "aceptar", "rechazar"))
    page = session.page
    wait_result(session)
    consent = page.get_by_test_id("consent")
    expect(consent).to_contain_text("OneTrust")
    statuses = sorted(row.get_attribute("data-status") for row in page.get_by_test_id("consent-run").all())
    assert statuses == ["aceptado", "rechazado", "sin_interaccion"]
    expect(consent).to_contain_text("API TCF del sitio")
    # La captura del banner se sirve desde nuestra API y carga bajo la CSP.
    banner = page.get_by_test_id("consent-banner")
    expect(banner).to_be_visible()
    assert page.evaluate("document.querySelector('[data-testid=consent-banner]').naturalWidth") > 100
    # Antes de interactuar: en las 3 corridas. Tras rechazar: el que ignora el rechazo. Solo tras aceptar: uno.
    pre = page.get_by_test_id("pre-consent-item").all_inner_texts()
    assert len(pre) == 1 and "/cmp/pre.gif" in pre[0] and "en 3 de 3 corridas" in pre[0]
    post = page.get_by_test_id("post-reject-item").all_inner_texts()
    assert len(post) == 1 and "/cmp/ignores-reject.gif" in post[0] and "en 1 de 1 corridas" in post[0]
    only = page.get_by_test_id("only-accept-item").all_inner_texts()
    assert len(only) == 1 and "/cmp/accept-only.gif" in only[0]
    for section in ("pre-consent", "post-reject", "only-accept"):
        expect(page.get_by_test_id(section).locator("[data-level=EVIDENCIA]")).to_be_visible()
    expect(consent).to_contain_text("No es un juicio")
    # v1.2: conclusión de una línea al inicio, por plantilla y con su nivel (cifras = las de la tabla).
    conclusion = page.get_by_test_id("conclusion")
    expect(conclusion).to_have_attribute("data-kind", "rechazo")
    expect(conclusion.locator("[data-level=EVIDENCIA]").first).to_be_visible()
    text = conclusion.locator(".bubble-text").inner_text()
    match = re.fullmatch(r"Al rechazar: (\d+) → (\d+) requests de rastreo; (ninguna organización siguió|1 organización siguió|\d+ organizaciones siguieron) recibiendo datos\.", text)
    assert match, text
    assert page.evaluate("document.querySelector('[data-testid=privacy-result]').firstElementChild.dataset.testid") == "conclusion"
    assert int(match.group(2)) >= 1, "el fixture sigue enviando /cmp/ignores-reject.gif después de rechazar"
    print(f"\nCONCLUSIÓN: «{text}»")
    shot(page, "privacy-test-consentimiento")
    # La evidencia es navegable hasta la request.
    page.get_by_test_id("post-reject-item").get_by_test_id("privacy-evidence").first.click()
    session.open_tech()
    expect(page.get_by_test_id("request-detail")).to_contain_text("ignores-reject.gif")
    assert_wording(session, "consentimiento")


def test_unrecognized_banner_is_not_applicable(session):
    start_test(session, UNKNOWN, scenarios=("rechazar",))
    page = session.page
    wait_result(session)
    expect(page.get_by_test_id("consent-not-applicable")).to_contain_text("no se pulsó ningún botón")
    expect(page.get_by_test_id("conclusion").locator(".bubble-text")).to_have_text("Banner no reconocido: los escenarios fueron equivalentes.")
    expect(page.get_by_test_id("conclusion")).to_have_attribute("data-kind", "banner_no_reconocido")
    expect(page.get_by_test_id("cell-failures")).to_have_text("ninguno")
    assert page.get_by_test_id("consent-run").get_attribute("data-status") == "no_aplicable"
    expect(page.get_by_test_id("consent-run")).to_contain_text("No se reconoció")
    assert page.get_by_test_id("post-reject").count() == 0 and page.get_by_test_id("consent-banner").count() == 0
    assert_wording(session, "banner no reconocido")


def test_profiles_inconsistency_and_persistent_id(session):
    """Real vs Windows vs incoherente, 2 corridas: tabla de atributos, alerta e identificador sin cookies."""
    start_test(session, COOKIELESS, profiles=("real", "windows-chrome-es-cl", "incoherente-demo"), runs=2)
    page = session.page
    wait_result(session)
    expect(page.get_by_test_id("ip-unchanged")).to_contain_text("ningún perfil la cambia")

    # Alerta solo para el perfil incoherente.
    alerts = page.get_by_test_id("inconsistent")
    expect(alerts).to_have_count(1)
    assert alerts.get_attribute("data-profile") == "incoherente-demo"
    expect(alerts).to_contain_text("⚠ FINGERPRINT INCONSISTENTE")
    rules = {item.get_attribute("data-rule") for item in page.get_by_test_id("inconsistency").all()}
    assert {"os_mismatch", "timezone_vs_locale"} <= rules
    expect(alerts.locator("[data-level=EVIDENCIA]").first).to_be_visible()
    expect(alerts.locator("[data-level=INFERENCIA]").first).to_be_visible()
    consistent = page.get_by_test_id("consistent-profiles").inner_text()
    assert "Windows 11" in consistent and "Navegador real" in consistent and "INCOHERENTE" not in consistent

    # Tabla REAL vs PERFIL.
    table = page.get_by_test_id("attribute-table")
    expect(page.get_by_test_id("attr-row-platform")).to_contain_text("Linux x86_64")
    expect(page.get_by_test_id("attr-row-platform")).to_contain_text("Win32")
    assert page.get_by_test_id("attr-row-platform").locator("td[data-status=CAMBIO]").count() == 2
    canvas = page.get_by_test_id("attr-row-canvas_hash")
    assert canvas.locator("td[data-status=PERMANECIO]").count() == 2
    expect(canvas).to_contain_text("sigue observable")
    expect(page.get_by_test_id("attr-row-ip")).to_contain_text("la misma en todas las corridas")
    summary = page.locator("[data-testid=profile-summary][data-profile=windows-chrome-es-cl]").inner_text()
    for heading in ("Cambiaron", "Permanecieron", "Nuevos", "Potencialmente identificadores que siguen observables"):
        assert heading in summary
    assert "Huella de canvas" in summary.split("Potencialmente identificadores")[1] and "Dirección IP" in summary.split("Potencialmente identificadores")[1]
    expect(table).to_be_visible()

    # Identificador sin cookies: igual en 2 corridas limpias; cambia con el perfil salvo la parte de la IP.
    fpid = page.locator("[data-testid=persistent-id][data-parameter=fpid]")
    assert fpid.count() == 3  # uno por perfil
    real = fpid.filter(has_text="Perfil: real")
    expect(real).to_contain_text("2 de 2 corridas con contextos nuevos")
    expect(real.locator("[data-level=EVIDENCIA]")).to_be_visible()
    expect(real.locator("[data-level=INFERENCIA]")).to_be_visible()
    assert real.get_attribute("data-changes") == "true"
    results = [item.get_attribute("data-result") for item in real.get_by_test_id("persistent-id-profile").all()]
    assert results == ["CAMBIA_EN_PARTE", "CAMBIA_EN_PARTE"]
    expect(real).to_contain_text("se mantiene la parte")
    expect(real).to_contain_text("la IP, que ningún perfil cambia")
    shot(page, "privacy-test-perfiles")
    assert_wording(session, "perfiles")
