"""v1.5.3: en el sitio de fixtures (http) el navegador manda Proxy-Authorization y Proxy-Connection al egress-proxy. Ni
la vista del detalle de request (con «Mostrar identificadores completos») ni el HTML y el PDF exportados las muestran.

El e2e no tiene PROXY_SCAN_SECRET: busca la cabecera, el usuario del proxy («scan-<id>:») y el prefijo en base64 de ese
usuario, que no depende del secreto. La búsqueda del secreto en todas las salidas está en worker/tests/v153.
"""

import base64

from playwright.sync_api import expect

from .conftest import BASE_URL, ensure_scan
from .test_reports import pdf_text
from .test_v151 import _open_tech_detail
from .test_v12 import get_json

PAGE = "http://site.fixtures.test/v151/"


def needles(job_id: str) -> list[str]:
    user = f"scan-{job_id}:"
    return ["proxy-authorization", "proxy-connection", user, base64.b64encode(user.encode()).decode()[:56].lower()]


def assert_clean_text(where: str, value: str, job_id: str) -> None:
    lowered = value.lower()
    found = [needle for needle in needles(job_id) if needle.lower() in lowered]
    assert not found, (where, found)


def test_request_detail_and_exports_never_show_proxy_headers(session, shared, browser):
    job_id = ensure_scan(shared, browser, "v151", PAGE)
    page = session.page
    items = get_json(page, f"/api/scans/{job_id}/requests?page_size=200")["items"]
    assert any(item["url"].startswith("http://") for item in items), "el fixture es http: el navegador habló con el proxy en claro"

    # Vista del detalle con los valores completos, en una request propia y en una de tercero.
    for item in (items[0], next(item for item in items if item["host"] != "site.fixtures.test")):
        session.goto(f"#/scan/{job_id}/request/{item['request_id']}")
        _open_tech_detail(page)
        page.get_by_test_id("request-reveal").check()
        content = _open_tech_detail(page)
        expect(content).to_contain_text("accept", ignore_case=True)  # las cabeceras sí se muestran
        assert_clean_text(f"detalle {item['request_id']}", page.get_by_test_id("request-detail").inner_text(), job_id)

    # Reportes con los valores completos: HTML, JSON y el texto del PDF.
    assert page.request.post(f"{BASE_URL}/api/scans/{job_id}/export", data={"reveal": True}).ok
    for kind in ("json", "html"):
        response = page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/{kind}?reveal=true")
        assert response.ok
        assert_clean_text(kind, response.text(), job_id)
    pdf = None
    for _ in range(90):
        pdf = page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/pdf?reveal=true")
        if pdf.status != 409:
            break
        page.wait_for_timeout(2000)
    assert pdf is not None and pdf.ok, pdf.status
    assert_clean_text("pdf", pdf_text(pdf.body()).replace(" ", ""), job_id)
    session.assert_clean("cabeceras del proxy")
