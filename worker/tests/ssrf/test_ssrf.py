import urllib.request

import pytest

from .conftest import CANARY_BODY, PROXY_ERROR_HEADER, required_env, visit

BLOCKED_URLS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://db:5432",
    "http://api:8000/health",
    "http://egress-proxy:3128",
    "http://localtest.me",
    "http://10.0.0.1.nip.io",
    "https://example.com:22",
]
BLOCKED_FROM_ENV = ["LAN_GATEWAY", "HOST_LAN_IP", "INTERNAL_GATEWAY"]

FETCH_JS = """async (url) => {
    try {
        const response = await fetch(url);
        return {ok: true, status: response.status, body: (await response.text()).slice(0, 200)};
    } catch (error) {
        return {ok: false, error: String(error)};
    }
}"""

WEBSOCKET_JS = """(url) => new Promise((resolve) => {
    let socket;
    try { socket = new WebSocket(url); } catch (error) { resolve('exception: ' + error); return; }
    socket.onopen = () => resolve('open');
    socket.onerror = () => resolve('error');
    socket.onclose = () => resolve('close');
    setTimeout(() => resolve('timeout'), 20000);
})"""


def assert_blocked(outcome, url):
    assert CANARY_BODY not in outcome.body, f"{url}: se alcanzó el canario interno"
    assert outcome.blocked, f"{url}: NO fue bloqueada (status={outcome.status})"


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_blocked(page, url):
    assert_blocked(visit(page, url), url)


@pytest.mark.parametrize("variable", BLOCKED_FROM_ENV)
def test_blocked_addresses_from_preflight(page, variable):
    url = f"http://{required_env(variable)}"
    assert_blocked(visit(page, url), url)


def test_public_site_loads(page):
    outcome = visit(page, "https://example.com")
    assert outcome.error is None, outcome.error
    assert outcome.proxy_error is None
    assert outcome.status == 200
    assert page.title() == "Example Domain"


# --- Controles: prueban que los destinos existen y que el arnés detectaría una fuga ---


def test_control_canary_reachable_without_proxy(direct_page):
    outcome = visit(direct_page, "http://127.0.0.1")
    assert outcome.status == 200 and CANARY_BODY in outcome.body


def test_control_canary_websocket_opens_without_proxy(direct_page):
    visit(direct_page, "http://127.0.0.1")
    assert direct_page.evaluate(WEBSOCKET_JS, "ws://127.0.0.1/") == "open"


def test_control_api_reachable_from_worker_python():
    # El código del worker (confiable) sí ve la red internal; Chromium no debe verla.
    with urllib.request.urlopen("http://api:8000/health", timeout=5) as response:
        assert response.status == 200


# --- Peticiones lanzadas desde la página ---

FORBIDDEN_FETCH_TARGETS = [
    "http://127.0.0.1/",
    "http://api:8000/health",
    "http://169.254.169.254/latest/meta-data/",
    "https://10.0.0.1/",
]


@pytest.mark.parametrize("target", FORBIDDEN_FETCH_TARGETS)
def test_fetch_from_page_to_forbidden_destination_fails(page, target):
    responses = []
    page.on("response", lambda response: responses.append(response))
    assert visit(page, "http://example.com").status == 200

    result = page.evaluate(FETCH_JS, target)

    assert result["ok"] is False, f"fetch a {target} tuvo éxito: {result}"
    # Además del fallo visto por la página: ninguna respuesta vino del destino real.
    for response in responses:
        if response.url == target:
            assert response.headers.get(PROXY_ERROR_HEADER), f"{target} respondió sin pasar por la denegación del proxy"


@pytest.mark.parametrize("target", ["ws://127.0.0.1/", "ws://api:8000/", "wss://10.0.0.1/"])
def test_websocket_from_page_to_forbidden_destination_fails(page, target):
    assert visit(page, "http://example.com").status == 200
    result = page.evaluate(WEBSOCKET_JS, target)
    assert result in {"error", "close"} or result.startswith("exception"), f"{target}: {result}"


@pytest.mark.parametrize("target", ["metadata", "loopback", "private", "api", "db"])
def test_redirect_from_an_allowed_site_to_a_forbidden_destination_is_blocked(page, fixtures_site, target):
    """La URL inicial es válida; el destino prohibido llega después, por un 302.

    Validar solo la URL de entrada no basta: el proxy decide en cada conexión.
    """
    url = f"http://site.fixtures.test/ssrf/redirect/{target}"
    outcome = visit(page, url)
    assert_blocked(outcome, url)


def test_redirect_control_reaches_an_allowed_destination(page, fixtures_site):
    """Control del arnés: una redirección entre hosts permitidos sí funciona."""
    outcome = visit(page, "http://site.fixtures.test/redirect/start")
    assert not outcome.blocked and outcome.status == 200
