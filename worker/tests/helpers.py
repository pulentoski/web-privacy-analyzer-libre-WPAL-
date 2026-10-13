"""Utilidades compartidas por los tests que usan el sitio de fixtures."""

import asyncio
import concurrent.futures
import json
import urllib.error
import urllib.request

from app.config import settings

SITE = "http://site.fixtures.test"
FIXTURE_HOSTS = {"site.fixtures.test", "tracker-a.fixtures.test", "cdn-b.fixtures.test"}

# El código del worker tampoco tiene ruta al sitio de fixtures: va por el proxy.
_proxy = settings.egress_proxy_url.replace("://", f"://scan-00000000-0000-0000-0000-000000000000:{settings.proxy_scan_secret.get_secret_value()}@")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": _proxy}))


def run_async(coroutine):
    """Ejecuta una corrutina en un hilo propio.

    Los tests SSRF usan la API síncrona de Playwright, que deja un event loop
    activo en el hilo principal durante toda la sesión.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coroutine).result()


def fixtures_call(path: str, method: str = "GET") -> dict:
    request = urllib.request.Request(SITE + path, method=method, data=b"" if method == "POST" else None)
    with _opener.open(request, timeout=10) as response:
        return json.loads(response.read())


def find(capture: dict, host: str, path: str, method: str = "GET") -> dict:
    matches = [
        r for r in capture["requests"] if r["host"] == host and r["path"] == path and r["method"] == method
    ]
    assert len(matches) == 1, f"{method} {host}{path}: se esperaba 1 request capturada, hay {len(matches)}"
    return matches[0]
