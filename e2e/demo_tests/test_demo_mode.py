"""Modo demo de exposición, probado desde la IP LAN del host (http y https autofirmado).

No forman parte de la suite por defecto porque necesitan el modo demo levantado:

    DEMO_MODE=exposure ./scripts/demo.sh
    docker compose exec e2e pytest demo_tests -q
"""

import ipaddress
import json
import os
import pathlib
import re
import ssl
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import expect, sync_playwright

HTTP = os.environ["DEMO_HTTP_URL"]
HTTPS = os.environ["DEMO_HTTPS_URL"]
SHOTS = pathlib.Path("/tmp/screenshots")
UNVERIFIED = ssl._create_unverified_context()  # el certificado es autofirmado a propósito


def fetch(url, method="GET", body=None):
    request = urllib.request.Request(url, method=method, data=body, headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(request, timeout=10, context=UNVERIFIED if url.startswith("https") else None) as response:
            return response.status, response.read().decode(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(), dict(error.headers)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


def open_page(browser, base, **options):
    context = browser.new_context(locale="es-CL", **options)
    page = context.new_page()
    page.set_default_timeout(20_000)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(base + "/")
    expect(page.get_by_test_id("combined-hash")).to_be_visible()
    expect(page.get_by_test_id("server-headers")).to_be_visible()
    return context, page, errors


@pytest.mark.parametrize("base", [HTTP, HTTPS])
def test_only_the_exposure_page_is_reachable_from_the_lan(base):
    status, body, headers = fetch(base + "/")
    assert status == 200 and '<div id="root">' in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert json.loads(fetch(base + "/mode.json")[1]) == {"mode": "exposure"}
    status, body, _ = fetch(base + "/api/exposure/server")
    assert status == 200 and json.loads(body)["stored"] is False
    # La API de scans no existe desde la LAN, con ningún método.
    for method, path, payload in (
        ("POST", "/api/scans", b'{"url": "https://example.com"}'), ("GET", "/api/scans", None),
        ("GET", "/api/scans/00000000-0000-0000-0000-000000000000", None),
        ("GET", "/api/scans/00000000-0000-0000-0000-000000000000/report", None),
        ("POST", "/api/scans/00000000-0000-0000-0000-000000000000/reanalyze", b"{}"), ("GET", "/api/exposurex", None),
        ("GET", "/api/../api/scans", None), ("GET", "/api//scans", None),
    ):
        status, body, _ = fetch(base + path, method, payload)
        assert status in (400, 403), (method, path, status)
        if status == 403:
            assert json.loads(body)["error_code"] == "NOT_AVAILABLE_IN_EXPOSURE_MODE"
    assert fetch(base + "/health")[0] == 404


def test_server_view_from_the_lan_labels_the_private_ip(browser):
    status, body, _ = fetch(HTTP + "/api/exposure/server")
    data = json.loads(body)
    assert data["ip"]["kind"] == "private" and data["ip"]["is_public"] is False
    assert "IP pública observada" not in data["ip"]["label"]
    # Desde un equipo de la LAN la IP es privada ("lan"). Esta suite corre en un contenedor del mismo
    # host: su visita llega por la red interna de Docker y debe rotularse como acceso local, no como LAN.
    if ipaddress.ip_address(data["ip"]["observed"]) in ipaddress.ip_network("172.30.0.0/16"):
        assert data["ip"]["access"] == "local" and data["ip"]["label"].startswith("Acceso local: el servidor ve la red interna de Docker (172.30.x).")
    else:
        assert data["ip"]["access"] == "lan" and "IP privada (misma red local)" in data["ip"]["label"]
    assert data["ip_intel"] == {"kind": "private", "applies": False, "note": "no aplica (red privada)"}
    print(f"\nIP observada desde la LAN: {data['ip']['observed']} ({data['ip']['label']})")


def test_http_on_the_lan_is_an_insecure_context_and_the_page_explains_it(browser):
    context, page, errors = open_page(browser, HTTP)
    try:
        assert page.evaluate("isSecureContext") is False
        expect(page.get_by_test_id("insecure-context")).to_contain_text("no se abrió en un contexto seguro")
        for name in ("crypto_subtle", "ua_client_hints", "device_memory", "webgpu"):
            row = page.get_by_test_id(f"attr-{name}")
            assert row.get_attribute("data-status") == "NO_DISPONIBLE", name
            expect(row).to_contain_text("contexto seguro")
        # La huella se calcula igual (SHA-256 propio, sin crypto.subtle).
        assert re.fullmatch(r"[0-9a-f]{64}", page.get_by_test_id("combined-hash").inner_text())
        # Solo existe "Mi exposición": sin formulario de scans ni navegación hacia él.
        assert page.locator("#url").count() == 0 and page.get_by_test_id("nav-scans").count() == 0
        page.goto(HTTP + "/#/")
        expect(page.get_by_test_id("exposure")).to_be_visible()
        assert page.locator("#url").count() == 0
        assert errors == []
    finally:
        context.close()


def test_https_with_the_self_signed_certificate_is_a_secure_context(browser):
    # Sin aceptar el certificado, el navegador se niega: es autofirmado.
    strict = browser.new_context()
    with pytest.raises(Exception, match="ERR_CERT"):
        strict.new_page().goto(HTTPS + "/")
    strict.close()

    context, page, errors = open_page(browser, HTTPS, ignore_https_errors=True)  # equivale a "continuar de todos modos"
    try:
        assert page.evaluate("isSecureContext") is True
        assert page.get_by_test_id("insecure-context").count() == 0
        has = page.evaluate("({subtle: !!(crypto && crypto.subtle), hints: !!navigator.userAgentData, memory: navigator.deviceMemory !== undefined, gpu: !!navigator.gpu})")
        status = {name: page.get_by_test_id(f"attr-{name}").get_attribute("data-status") for name in ("crypto_subtle", "ua_client_hints", "device_memory", "webgpu")}
        print(f"\nHTTPS: APIs presentes en este navegador: {has} | estado en la página: {status}")
        assert has["subtle"] and status["crypto_subtle"] == "DISPONIBLE"
        assert has["hints"] and status["ua_client_hints"] == "DISPONIBLE"
        # Valor largo: truncado; completo con "ver más".
        page.get_by_test_id("attr-ua_client_hints").get_by_role("button", name=re.compile("ver más")).click()
        expect(page.get_by_test_id("attr-ua_client_hints")).to_contain_text("architecture")
        assert has["memory"] and status["device_memory"] == "DISPONIBLE"
        # WebGPU: si el navegador la tiene, ya no se culpa al contexto; que haya adaptador depende del equipo.
        if has["gpu"]:
            assert "contexto seguro" not in page.get_by_test_id("attr-webgpu").inner_text()
        else:
            expect(page.get_by_test_id("attr-webgpu")).to_contain_text("no implementa WebGPU")
        assert page.locator("#url").count() == 0
        assert errors == []
        SHOTS.mkdir(exist_ok=True)
        page.screenshot(path=str(SHOTS / "mi-exposicion-https.png"), full_page=True)
    finally:
        context.close()


def test_certificate_matches_the_lan_address():
    host = HTTPS.split("://")[1].split(":")[0]
    port = int(HTTPS.rsplit(":", 1)[1])
    pem = ssl.get_server_certificate((host, port))
    decoded = ssl._ssl._test_decode_cert  # noqa: SLF001  (solo para leer SAN y fechas del PEM)
    path = pathlib.Path("/tmp/demo-cert.pem")
    path.write_text(pem)
    info = decoded(str(path))
    assert ("IP Address", host) in info["subjectAltName"]
    assert info["issuer"] == info["subject"]  # autofirmado


# --- F10: en modo demo no se puede borrar el historial ---

INTERNAL = os.environ.get("BASE_URL", "http://frontend:8080")
SOME_SCAN = "00000000-0000-4000-8000-000000000000"


@pytest.mark.parametrize("base", [HTTP, HTTPS])
def test_history_cannot_be_deleted_from_the_lan(base):
    """Desde la red local, la API entera (también DELETE) responde 403 en nginx."""
    for method, path, body in (("DELETE", f"/api/scans/{SOME_SCAN}", None), ("DELETE", "/api/scans", b'{"confirm":"BORRAR"}'), ("GET", "/api/history", None)):
        status, text, _ = fetch(base + path, method=method, body=body)
        assert status == 403 and json.loads(text)["error_code"] == "NOT_AVAILABLE_IN_EXPOSURE_MODE", (method, path, status, text)


def test_history_cannot_be_deleted_even_from_the_full_interface_while_in_demo_mode():
    """La api arranca con DEMO_MODE: tampoco por la interfaz completa (loopback) se puede borrar."""
    status, text, _ = fetch(INTERNAL + "/api/history")
    before = json.loads(text)
    assert status == 200 and before["delete_enabled"] is False
    for path, body in ((f"/api/scans/{SOME_SCAN}", None), ("/api/scans", b'{"confirm":"BORRAR"}')):
        status, text, _ = fetch(INTERNAL + path, method="DELETE", body=body)
        assert status == 403 and json.loads(text)["error_code"] == "HISTORY_DELETE_DISABLED", (path, status, text)
    after = json.loads(fetch(INTERNAL + "/api/history")[1])
    assert after["scans"] == before["scans"] and after["reports"] == before["reports"]
