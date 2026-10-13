"""Reportes exportables de extremo a extremo (F8): botones, HTML, PDF renderizado por el worker y sha256."""

import hashlib
import io
import json
import pathlib
import re

from playwright.sync_api import expect
from pypdf import PdfReader

from .conftest import BASE_URL, ensure_scan
from .test_privacy import CMP, start_test, wait_result

F8_PAGE = "http://site.fixtures.test/f8/?gdpr=0&gcs=G110"
# Identificador que el fixture envía a su tracker en una URL (parámetro cid de fixtures/static/f8/f8.js).
FULL_ID = "1234567890.1790000000"
PDF_TIMEOUT = 150_000


STORY_STEPS = ["1. Identificadores persistentes", "2. Fingerprinting", "3. Fugas de URL y Referer", "4. Exfiltración de atributos",
               "5. Sincronización de identificadores", "6. Consentimiento (TCF / Consent Mode)", "7. Registro de interacción", "8. Fuera del alcance observable"]


def pdf_fonts(data: bytes) -> set[str]:
    """Nombres de las tipografías incrustadas en el PDF."""
    fonts = set()
    for page in PdfReader(io.BytesIO(data)).pages:
        resources = page.get("/Resources") or {}
        for font in (resources.get("/Font") or {}).values():
            fonts.add(str(font.get_object().get("/BaseFont", "")))
    return fonts


def pdf_text(data: bytes) -> str:
    reader = PdfReader(io.BytesIO(data))
    assert len(reader.pages) >= 2, "el anexo empieza en una página nueva"
    return re.sub(r"\s+", " ", " ".join(page.extract_text() for page in reader.pages))


def api_json(page, path):
    response = page.request.get(f"{BASE_URL}{path}")
    assert response.ok, f"{path}: {response.status}"
    return response.json()


def download(page, test_id, timeout=PDF_TIMEOUT):
    with page.expect_download(timeout=timeout) as download:
        page.get_by_test_id(test_id).click()
    return download.value, pathlib.Path(download.value.path()).read_bytes()


def test_download_html_and_pdf_of_a_scan(session, shared, browser):
    job_id = ensure_scan(shared, browser, "f8", F8_PAGE)
    page = session.page
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("dashboard")).to_be_visible(timeout=30_000)
    expect(page.get_by_test_id("download-pdf")).to_have_text("Descargar PDF")
    expect(page.get_by_test_id("download-html")).to_have_text("Descargar HTML")
    expect(page.get_by_test_id("download-reveal")).not_to_be_checked()
    expect(page.get_by_test_id("download-masking")).to_contain_text("enmascarados")

    # --- HTML ---
    html_file, html_bytes = download(page, "download-html")
    assert html_file.suggested_filename == f"reporte-{job_id}.html"
    html = html_bytes.decode("utf-8")
    sha256 = page.get_by_test_id("download-sha256").inner_text()
    exported = page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/json")
    assert hashlib.sha256(exported.body()).hexdigest() == sha256, "el sha256 mostrado es el del JSON exportado"
    assert f'data-sha256="{sha256}"' in html
    assert "<script" not in html and not re.search(r'(?:src|href)="(?!data:)', html), "HTML autocontenido y sin scripts"
    assert FULL_ID not in html and FULL_ID not in exported.text(), "identificadores enmascarados por defecto"
    assert "cid=1234…[21 caracteres]" in html
    # F10: «Hallazgos por grupo» en el resumen ejecutivo, con los siete pasos en orden...
    summary = html[html.index("Resumen ejecutivo"):html.index("Anexo técnico")]
    positions = [summary.index(step) for step in STORY_STEPS]
    assert positions == sorted(positions), "los siete pasos van en orden dentro del resumen ejecutivo"
    assert "Hallazgos por grupo" in summary and "Hallazgos por grupo: detalle y evidencia" in html
    assert 'class="lvl lvl-EVIDENCIA"' in summary
    # ...y sobrio: sin el tema de la interfaz (Unidad Púrpura).
    for themed in ("Barlow", "JetBrains", "Bangers", "Comic Neue", "box-shadow", "radial-gradient", "conic-gradient", "clip-path", "#0b0614", "#7cff4f", "@font-face"):
        assert themed not in html, f"el reporte para clientes no lleva el tema de la interfaz: {themed}"

    # --- PDF (lo renderiza el worker a partir de un export nuevo) ---
    pdf_file, pdf = download(page, "download-pdf")
    assert pdf_file.suggested_filename == f"reporte-{job_id}.pdf" and pdf[:5] == b"%PDF-"
    status = api_json(page, f"/api/scans/{job_id}/export")
    info = status["files"]["pdf"]["render_info"]
    assert status["files"]["pdf"]["status"] == "ready" and info["network_requests_attempted"] == 0 and info["attempted"] == []
    report = json.loads(page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/json").body())
    text = pdf_text(pdf)
    compact = text.replace(" ", "")
    # Resumen ejecutivo y anexo técnico.
    for needle in ("Resumen ejecutivo", "Resultados", "Relevancia", "Recomendaciones", "Anexo técnico", "Metodología",
                   "Hallazgos", "Fingerprinting", "Consentimiento: TCF y Consent Mode", "Limitaciones", "Leyenda de niveles de evidencia",
                   "EVIDENCIA", "INFERENCIA", "CNAME cloaking", "Destinos por país"):
        assert needle in text, needle
    # F10: la nueva estructura llega al PDF, en orden y sin las tipografías del tema de la interfaz.
    story_positions = [compact.index(step.replace(" ", "")) for step in STORY_STEPS]
    assert story_positions == sorted(story_positions), "los siete pasos van en orden en el PDF"
    assert "Noseobservóenestavisita" in compact or all(step.replace(" ", "") in compact for step in STORY_STEPS)
    assert "sininiciodesesión,búsquedasniclics" in compact, "el grupo fijo «Fuera del alcance observable» está en el PDF"
    fonts = pdf_fonts(pdf)
    assert fonts and not any(name in font.lower() for font in fonts for name in ("bangers", "comic", "barlow", "jetbrains")), fonts
    assert "¡ZAS!" not in text and "¡LISTO!" not in text
    print(f"\nPDF: {len(PdfReader(io.BytesIO(pdf)).pages)} páginas, tipografías {sorted(fonts)}, 7 pasos en orden")
    # Fecha, URL y versiones.
    assert "site.fixtures.test/f8/" in compact
    assert report["scan"]["finished_at"][:10] in text
    for version in (report["versions"]["analyzer"], report["versions"]["lists"], report["versions"]["ip_database"]):
        assert version.replace(" ", "") in compact, version
    # Atribuciones y aviso legal.
    assert "IP Geolocation by DB-IP" in text and "CC-BY-4.0" in text
    assert "No constituye asesoría legal" in text
    # sha256 del JSON impreso en el documento, e identificadores enmascarados.
    assert status["sha256"] in compact
    assert hashlib.sha256(page.request.get(f"{BASE_URL}/api/scans/{job_id}/export/json").body()).hexdigest() == status["sha256"]
    assert FULL_ID not in compact
    # Lo propio de F8 llega al documento: TCF, Consent Mode y el alias DNS.
    assert "OneTrust LLC" in text and "G110" in text and "metrics.site.fixtures.test" in compact
    session.assert_clean("descarga de reportes")


def test_reveal_is_an_explicit_choice(session, shared, browser):
    job_id = ensure_scan(shared, browser, "f8", F8_PAGE)
    page = session.page
    session.goto(f"#/scan/{job_id}")
    expect(page.get_by_test_id("download-html")).to_be_visible(timeout=30_000)
    page.get_by_test_id("download-reveal").check()
    expect(page.get_by_test_id("download-masking")).to_contain_text("valores completos")
    html_file, html_bytes = download(page, "download-html")
    assert html_file.suggested_filename == f"reporte-{job_id}-completo.html"
    html = html_bytes.decode("utf-8")
    assert FULL_ID in html and "muestra los valores completos" in html
    session.assert_clean("reporte completo")


def test_privacy_test_group_report(session):
    start_test(session, CMP, scenarios=("sin_interaccion", "rechazar"))
    wait_result(session)
    page = session.page
    group_id = re.search(r"([0-9a-f-]{36})", page.url).group(1)
    expect(page.get_by_test_id("privacy-report")).to_be_visible()
    pdf_file, pdf = download(page, "download-pdf")
    assert pdf_file.suggested_filename == f"reporte-grupo-{group_id}.pdf" and pdf[:5] == b"%PDF-"
    status = api_json(page, f"/api/privacy/test/{group_id}/export")
    assert status["files"]["pdf"]["render_info"]["network_requests_attempted"] == 0
    text = pdf_text(pdf)
    for needle in ("Reporte de análisis con opciones avanzadas", "Resumen ejecutivo", "Anexo técnico", "mediana", "rechazar", "IP Geolocation by DB-IP", "No constituye asesoría legal"):
        assert needle in text, needle
    assert status["sha256"] in text.replace(" ", "")
    session.assert_clean("reporte de grupo")
