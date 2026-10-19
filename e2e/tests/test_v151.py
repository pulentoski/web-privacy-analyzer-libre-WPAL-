"""v1.5.1: con «Mostrar identificadores completos» desactivado, el detalle de request enmascara los valores con forma de
identificador (URL, parámetros, cookies, cabeceras y cadena de redirección); el HTML y el PDF exportados tampoco los
llevan. El fixture /v151/ envía el mismo ID por todas esas vías (fixtures/server.py, V151_ID)."""

from playwright.sync_api import expect

from .conftest import BASE_URL, ensure_scan
from .test_reports import download, pdf_text
from .test_v12 import get_json

PAGE = "http://site.fixtures.test/v151/"
ID = "5f0c3e9a7b1d4c2e8f6a0b9c3d7e1f42"
MASKED = "5f0c…[32 caracteres]"


def _request_id(page, job_id, host, path):
    items = get_json(page, f"/api/scans/{job_id}/requests?domain={host}&page_size=200")["items"]
    return next(item["request_id"] for item in items if item["host"] == host and path in item["url"])


def _open_tech_detail(page):
    expect(page.get_by_test_id("request-detail")).to_be_visible(timeout=30_000)
    if page.get_by_test_id("request-tech").get_attribute("data-open") != "true":
        page.get_by_test_id("request-tech-toggle").click()
    expect(page.get_by_test_id("request-tech-content")).to_be_visible()
    return page.get_by_test_id("request-tech-content")


def test_request_detail_masks_identifiers_until_revealed(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v151", PAGE)
    page = session.page
    pixel = _request_id(page, job_id, "tracker-a.fixtures.test", "/v151/px")
    # La captura sí tiene el valor completo (la api lo entrega solo con reveal=true).
    assert ID in str(get_json(page, f"/api/scans/{job_id}/requests/{pixel}?reveal=true"))

    for request_id, blocks in ((pixel, ("parameters", "cookies", "redirect-chain")),
                               (_request_id(page, job_id, "site.fixtures.test", "/v151/ping"), ("cookies",))):
        session.goto(f"#/scan/{job_id}/request/{request_id}")
        content = _open_tech_detail(page)
        expect(page.get_by_test_id("request-reveal")).not_to_be_checked()
        expect(page.get_by_test_id("request-masking-note")).to_contain_text("enmascarados")
        for block in blocks:
            expect(page.get_by_test_id(block)).to_contain_text(MASKED)
        assert ID not in page.get_by_test_id("request-detail").inner_text(), "ningún valor completo con el interruptor desactivado"
        assert MASKED in content.inner_text()

        page.get_by_test_id("request-reveal").check()
        content = _open_tech_detail(page)
        expect(page.get_by_test_id("request-masking-note")).to_contain_text("valores completos")
        expect(content).to_contain_text(ID)
    # Cabeceras: Cookie enviada (ping propio) y Set-Cookie y Location del pixel, también enmascaradas por defecto.
    masked = get_json(page, f"/api/scans/{job_id}/requests/{pixel}")
    headers = {header["name"].lower(): header["value"] for header in masked["response_headers"]}
    assert headers["location"].endswith(f"/v151/sync/{MASKED}?partner_uid={MASKED}") and MASKED in headers["set-cookie"]
    assert masked["redirect_chain"] and ID not in str(masked)
    session.assert_clean("detalle de request enmascarado")


def test_exported_html_and_pdf_do_not_carry_the_identifier(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v151", PAGE)
    page = session.page
    # El pixel con el ID es un rastreador (lista de fixtures): su URL va en el reporte.
    report = get_json(page, f"/api/scans/{job_id}/report")
    assert ID in str(report["trackers"]), "el reporte sin enmascarar sí lo lleva: la comprobación no es vacía"
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("download-reveal")).not_to_be_checked(timeout=30_000)
    _, html = download(page, "download-html")
    assert ID not in html.decode("utf-8") and MASKED in html.decode("utf-8")
    _, pdf = download(page, "download-pdf")
    text = pdf_text(pdf).replace(" ", "")
    assert ID not in text and "5f0c" in text
    # Con la opción explícita el export sí lo lleva.
    assert page.request.post(f"{BASE_URL}/api/scans/{job_id}/export", data={"reveal": True}).ok
    revealed = page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/html?reveal=true")
    assert revealed.ok and ID in revealed.text()
    session.assert_clean("export enmascarado")
