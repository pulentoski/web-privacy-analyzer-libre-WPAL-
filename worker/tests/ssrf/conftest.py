"""Tests SSRF con Chromium real, lanzado con el launcher de producción.

Un "canario" escucha en 0.0.0.0:80 dentro del propio worker. Si Chromium se
saltara el proxy para loopback, la navegación llegaría al canario y el test
fallaría: así un "connection refused" no puede pasar por bloqueo.
"""

import base64
import hashlib
import http.server
import os
import threading
import time
from dataclasses import dataclass

import pytest
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from app.browser.launcher import context_kwargs, launch_kwargs
from app.config import settings

CANARY_BODY = "SSRF-CANARY-REACHED"
PROXY_ERROR_HEADER = "x-squid-error"
NAV_TIMEOUT_MS = 30_000
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if key:
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            time.sleep(5)  # mantener abierto para que el navegador dispare "open"
            self.close_connection = True
            return
        body = f"<title>{CANARY_BODY}</title>{CANARY_BODY}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session", autouse=True)
def canary():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 80), CanaryHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture(scope="session")
def playwright_instance():
    with sync_playwright() as playwright:
        yield playwright


@pytest.fixture(scope="session")
def browser(playwright_instance):
    browser = playwright_instance.chromium.launch(**launch_kwargs())
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def direct_browser(playwright_instance):
    """Chromium SIN proxy, solo para los controles que validan el propio arnés."""
    browser = playwright_instance.chromium.launch(
        headless=settings.headless, channel="chromium", chromium_sandbox=settings.chromium_sandbox
    )
    yield browser
    browser.close()


@pytest.fixture
def page(browser):
    context = browser.new_context(**context_kwargs())
    yield context.new_page()
    context.close()


@pytest.fixture
def direct_page(direct_browser):
    context = direct_browser.new_context(**context_kwargs())
    yield context.new_page()
    context.close()


@dataclass
class Outcome:
    error: str | None = None
    status: int | None = None
    proxy_error: str | None = None
    body: str = ""

    @property
    def blocked(self) -> bool:
        """Bloqueado = Chromium no pudo navegar, o respondió el propio proxy con un error."""
        return self.error is not None or self.proxy_error is not None


def visit(page, url: str) -> Outcome:
    try:
        response = page.goto(url, timeout=NAV_TIMEOUT_MS)
    except PlaywrightError as exc:
        return Outcome(error=exc.message.splitlines()[0])
    return Outcome(
        status=response.status,
        proxy_error=response.headers.get(PROXY_ERROR_HEADER),
        body=page.content(),
    )


def required_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"Falta la variable de entorno {name} (ver .env.example)"
    return value
