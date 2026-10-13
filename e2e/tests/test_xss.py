"""XSS: scan de un sitio que siembra payloads en todo lo capturado; ninguna vista debe ejecutarlos."""

import re

from playwright.sync_api import expect

from .conftest import ensure_scan

XSS_PAGE = "http://site.fixtures.test/xss/"


def test_xss_payloads_never_execute_in_any_view(session, shared, browser):
    job_id = ensure_scan(shared, browser, "xss", XSS_PAGE)
    page = session.page
    visited = []

    def check(name):
        page.wait_for_timeout(250)  # da tiempo a que un onerror/onload inyectado llegara a dispararse
        session.assert_clean(name)
        visited.append(name)

    # Historial: el título capturado aparece en la lista de scans.
    session.goto("#/history")
    recent = page.get_by_test_id("recent")
    expect(recent).to_contain_text("<img src=x onerror=")
    check("inicio")
    # F10: confirmación de borrado junto a un título hostil (se cancela: no se borra nada).
    row = page.get_by_test_id("recent-row").filter(has_text="<img src=x onerror=").first
    row.get_by_test_id("delete-scan").click()
    expect(row.get_by_test_id("delete-scan-confirm")).to_be_visible()
    check("inicio con confirmación de borrado")
    row.get_by_test_id("delete-scan-no").click()
    page.get_by_test_id("delete-all-open").click()
    page.get_by_test_id("delete-all-input").fill('<img src=x onerror="window.__XSS=1">')
    expect(page.get_by_test_id("delete-all-confirm")).to_be_disabled()
    check("inicio con formulario de borrar todo")
    page.get_by_test_id("delete-all-cancel").click()

    # Resumen: título en la cabecera, grafo, gráficos, categorías de datos.
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("dashboard")).to_be_visible()
    expect(page.get_by_test_id("scan-title")).to_contain_text("<script>window.__XSS=1</script>")
    check("resumen")
    page.get_by_test_id("presentation-toggle").click()
    check("resumen (modo presentación)")
    page.get_by_test_id("presentation-toggle").click()
    # F10: frase de resumen, tarjetas, panel «¿Qué es esto?» y menú, en los dos temas.
    expect(page.get_by_test_id("summary-plain")).to_be_visible()
    expect(page.get_by_test_id("onomatopoeia-trackers")).to_have_count(0)
    page.get_by_test_id("what-is-this").locator("summary").click()
    expect(page.get_by_test_id("what-definition")).to_be_visible()
    page.get_by_test_id("what-is-this").get_by_test_id("term").first.hover()
    check("resumen (tema clásico, panel y tooltip abiertos)")
    session.set_theme("purple")
    check("resumen (tema Unidad Púrpura)")
    session.set_theme("classic")

    # Tabla: URLs con payloads, con y sin filtros.
    session.goto(f"#/scan/{job_id}/requests?page_size=200")
    expect(page.get_by_test_id("requests-table")).to_be_visible()
    expect(page.get_by_test_id("requests-table")).to_contain_text("%3Cimg%20src%3Dx")
    # F10: cada fila lleva su frase técnica (plantilla + datos capturados) antes de la URL.
    assert page.get_by_test_id("request-plain").count() == page.get_by_test_id("request-row").count() >= 7
    check("tabla")
    session.goto(f"#/scan/{job_id}/requests?domain=%3Cscript%3Ewindow.__XSS%3D1%3C%2Fscript%3E&band=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
    expect(page.get_by_test_id("requests")).to_be_visible()
    check("tabla con filtros hostiles en la URL")

    # Detalle de CADA request: parámetros, decodificaciones, cookies, headers, initiator.
    session.goto(f"#/scan/{job_id}/requests?page_size=200")
    expect(page.get_by_test_id("request-row").first).to_be_visible()
    hrefs = [link.get_attribute("href") for link in page.get_by_test_id("request-link").all()]
    assert len(hrefs) >= 7
    text, plain_text = "", ""
    for href in hrefs:
        session.goto(href)
        expect(page.get_by_test_id("request-detail")).to_be_visible()
        # F10: la frase técnica va primero; el detalle técnico se abre para revisarlo entero.
        expect(page.get_by_test_id("request-summary").get_by_test_id("request-plain")).to_be_visible()
        plain_text += page.get_by_test_id("request-summary").inner_text()
        session.open_tech()
        more = page.get_by_role("button", name=re.compile("ver más"))
        for _ in range(200):  # también el texto completo, sin truncar
            if more.count() == 0:
                break
            more.first.click()
        text += page.get_by_test_id("request-detail").inner_text()
        check(f"detalle {href}")
    # Los payloads están ahí, visibles como texto: nombres y valores de parámetros, cookie, decodificados.
    for visible in ('<img src=x onerror="window.__XSS=(window.__XSS||0)+1">', "<script>window.__XSS=1</script>",
                    "<svg/onload=window.__XSS=1>", "javascript:window.__XSS=1", "{{constructor.constructor("):
        assert visible in text, f"el payload no se mostró (¿se perdió en el camino?): {visible}"
    assert "base64 → json" in text, "no se mostró la decodificación del POST"
    assert "Cookie enviada" in text, "no se mostró la cookie con payload"
    # Un payload capturado llega a una frase técnica (el nombre de un parámetro) y se ve como texto.
    assert "<script>window.__XSS=1</script>" in plain_text or "<svg/onload=window.__XSS=1>" in plain_text or "<img src=x" in plain_text, \
        f"ninguna frase técnica llevó texto capturado hostil: {plain_text[:600]}"

    # Trackers, con todos los grupos abiertos.
    session.goto(f"#/scan/{job_id}/trackers")
    expect(page.get_by_test_id("trackers")).to_be_visible()
    for summary in page.locator("[data-testid=tracker-group] > summary").all():
        summary.click()
    for summary in page.locator("[data-testid=tracker-bundle] > summary").all():  # v1.4.2
        summary.click()
    assert page.get_by_test_id("tracker-plain").count() >= 3
    session.open_all("tracker-detail")
    page.get_by_test_id("what-is-this").locator("summary").click()
    check("trackers")

    # Fingerprinting: el NOMBRE del script es un payload.
    session.goto(f"#/scan/{job_id}/fingerprinting")
    expect(page.get_by_test_id("fingerprinting")).to_contain_text("%3Cimg%20src%3Dx%20onerror%3Dwindow.__XSS%3D1%3E.js")
    for summary in page.locator("[data-testid=fp-script] summary").all():
        summary.click()
    assert page.get_by_test_id("fp-plain").count() >= 1
    page.get_by_test_id("what-is-this").locator("summary").click()
    check("fingerprinting")

    # Hallazgos: el texto de un claim cita un parámetro cuyo nombre es un payload.
    session.goto(f"#/scan/{job_id}/findings")
    expect(page.get_by_test_id("findings")).to_contain_text("<script>window.__XSS=1</script>")
    check("hallazgos")
    # F10: «Hallazgos por grupo». Los siete grupos, con todos sus detalles abiertos: las frases
    # técnicas llevan nombres de parámetro y de script que son payloads.
    story = page.get_by_test_id("story")
    expect(story.get_by_test_id("story-step")).to_have_count(8)
    session.open_all("story-detail")
    story_text = story.inner_text()
    assert "<script>window.__XSS=1</script>" in story_text or "<img src=x onerror=" in story_text or "%3Cimg%20src%3Dx" in story_text, \
        f"los grupos no mostraron ningún dato capturado hostil: {story_text[:800]}"
    assert page.get_by_test_id("finding-plain").count() == page.get_by_test_id("finding").count() >= 5
    page.get_by_test_id("what-is-this").locator("summary").click()
    check("hallazgos por grupo (pasos abiertos)")
    session.set_theme("purple")
    check("hallazgos por grupo (tema Unidad Púrpura)")
    page.get_by_test_id("presentation-toggle").click()
    check("hallazgos por grupo (Unidad Púrpura + presentación)")
    page.get_by_test_id("presentation-toggle").click()
    session.set_theme("classic")
    session.goto(f"#/scan/{job_id}/findings?level=%3Csvg%2Fonload%3Dalert(1)%3E&f=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
    expect(page.get_by_test_id("findings")).to_be_visible()
    check("hallazgos con parámetros hostiles en la URL")

    # Rutas hostiles: no deben romper ni inyectar nada.
    # F10: glosario (texto fijo) y rutas nuevas.
    session.goto("#/glossary")
    expect(page.get_by_test_id("glossary-term").first).to_be_visible()
    check("glosario")
    for route in ("#/scan/%3Cscript%3Ealert(1)%3C%2Fscript%3E", f"#/scan/{job_id}/request/1%20onerror%3Dalert(1)", "#/javascript:alert(1)",
                  "#/glossary/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", f"#/scan/{job_id}/%3Csvg%2Fonload%3Dalert(1)%3E"):
        session.goto(route)
        check(f"ruta {route}")

    print(f"\nXSS: {len(visited)} vistas revisadas, 0 ejecuciones, 0 violaciones de CSP, 0 diálogos")
    assert len(visited) >= 26


def test_captured_urls_are_never_links(session, shared, browser):
    job_id = ensure_scan(shared, browser, "xss", XSS_PAGE)
    page = session.page
    for view in ("requests?page_size=200", "trackers", "fingerprinting", "findings"):
        session.goto(f"#/scan/{job_id}/{view}")
        page.wait_for_timeout(500)
        # Con todo el detalle técnico abierto: ahí están las URLs capturadas.
        page.evaluate("document.querySelectorAll('[data-testid=tracker-group], [data-testid=tracker-bundle]').forEach((group) => { group.open = true; })")
        for block in ("tracker-detail", "story-detail"):
            session.open_all(block)
        hrefs = page.evaluate("[...document.querySelectorAll('a[href]')].map((a) => a.getAttribute('href'))")
        # Todos los enlaces son navegación interna (#/...) o la descarga del reporte de la propia API.
        external = [href for href in hrefs if not (href.startswith("#/") or href.startswith("/api/scans/"))]
        assert external == [], f"{view}: enlaces a destinos capturados: {external}"
    session.assert_clean("enlaces")
