"""HAR sintético para los tests (v1.3). No procede de ningún sitio real.

Trae lo que el importador debe resolver: dos páginas y entradas sin página, cabeceras Cookie,
Set-Cookie y Authorization con «secretos», requests bloqueadas por una extensión, un término de
búsqueda enviado a otro dominio, una ola de sincronización y payloads XSS en todos los campos de
texto. La copia de e2e/tests/har_fixture.py es idéntica (cada imagen de tests se construye aparte).
"""

import json

SECRET_COOKIE = "sid=SECRETO-COOKIE-123"
SECRET_SET_COOKIE = "uid=SECRETO-SETCOOKIE-456; Path=/; Max-Age=31536000"
SECRET_AUTH = "Bearer SECRETO-TOKEN-789"
SECRETS = ("SECRETO-COOKIE-123", "SECRETO-SETCOOKIE-456", "SECRETO-TOKEN-789", "SECRETO-OBJETO-000")
XSS = "<img src=x onerror=alert('har-xss')>"
XSS_SCRIPT = "<script>alert('har-xss-2')</script>"
SEARCH_TERM = "zapatillas rojas"
PAGE_URL = "https://www.tienda-sintetica.example/buscar?q=zapatillas+rojas"
SYNC_URLS = [
    "https://frame.syncer-uno.example/syncframe?origin=tienda",
    "https://sync.socio-a.example/sync?partner=1",
    "https://rtb.socio-b.example/csync/abc",
    "https://cm.socio-c.example/cookiematching?id=1",
    "https://px.socio-d.example/usersync/x",
]


def _entry(url, started, *, pageref=None, method="GET", status=200, resource_type="image", request_headers=None, response_headers=None,
           error=None, post=None, mime="image/gif", ip="203.0.113.10", cookies=None):
    entry = {
        "startedDateTime": started, "time": 12.5, "_resourceType": resource_type, "serverIPAddress": ip,
        "request": {"method": method, "url": url, "httpVersion": "HTTP/2", "headers": request_headers or [], "queryString": [],
                    "cookies": cookies or [], "headersSize": 120, "bodySize": 0},
        "response": {"status": status, "statusText": "", "httpVersion": "HTTP/2", "headers": response_headers or [], "cookies": [],
                     "content": {"size": 10, "mimeType": mime, "text": "CUERPO-DE-RESPUESTA-NO-SE-GUARDA"}, "redirectURL": "",
                     "headersSize": 80, "bodySize": 10},
        "cache": {}, "timings": {"send": 0, "wait": 10, "receive": 2},
        "_initiator": {"type": "script", "stack": {"callFrames": [{"functionName": XSS, "url": "https://www.tienda-sintetica.example/app.js"}]}},
    }
    if pageref:
        entry["pageref"] = pageref
    if error:
        entry["response"]["_error"] = error
    if post is not None:
        entry["request"]["postData"] = {"mimeType": "application/json", "text": post}
    return entry


def build() -> dict:
    referer = {"name": "Referer", "value": PAGE_URL}
    entries = [
        # Sin página, una hora antes: otra carga (agrupada por tiempo).
        _entry("https://www.tienda-sintetica.example/antigua.gif", "2026-01-15T09:00:00.000Z"),
        _entry("https://www.tienda-sintetica.example/antigua2.gif", "2026-01-15T09:00:01.000Z"),
        # --- página 1: la que se analiza ---
        _entry(PAGE_URL, "2026-01-15T10:00:00.000Z", pageref="page_1", resource_type="document", mime="text/html",
               request_headers=[{"name": "Cookie", "value": SECRET_COOKIE}, {"name": "User-Agent", "value": XSS_SCRIPT}],
               response_headers=[{"name": "Set-Cookie", "value": SECRET_SET_COOKIE}, {"name": "X-Demo", "value": XSS}],
               cookies=[{"name": "sid", "value": "SECRETO-OBJETO-000"}]),
        _entry("https://static.tienda-sintetica.example/app.js", "2026-01-15T10:00:00.200Z", pageref="page_1", resource_type="script",
               mime="application/javascript", request_headers=[referer]),
        # Término de búsqueda hacia otro dominio, con credenciales en cabeceras.
        _entry("https://stats.medidor-uno.example/collect?q=zapatillas%20rojas&v=1", "2026-01-15T10:00:00.400Z", pageref="page_1",
               resource_type="ping", request_headers=[referer, {"name": "Authorization", "value": SECRET_AUTH}, {"name": "cookie", "value": SECRET_COOKIE}]),
        # Payload XSS en la URL y en el cuerpo.
        _entry("https://px.medidor-dos.example/p?x=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "2026-01-15T10:00:00.500Z", pageref="page_1",
               method="POST", resource_type="xhr", post=json.dumps({"nota": XSS_SCRIPT}), request_headers=[referer]),
        # Bloqueadas por una extensión del navegador.
        _entry("https://ads.bloqueado-uno.example/ad.js", "2026-01-15T10:00:00.600Z", pageref="page_1", status=0, resource_type="script",
               error="net::ERR_BLOCKED_BY_CLIENT", ip=""),
        _entry("https://ads.bloqueado-dos.example/pixel.gif", "2026-01-15T10:00:00.700Z", pageref="page_1", status=0,
               error="net::ERR_BLOCKED_BY_CLIENT", ip=""),
        # Ola de sincronización: cinco requests en menos de un segundo.
        *[_entry(url, f"2026-01-15T10:00:01.{index}00Z", pageref="page_1") for index, url in enumerate(SYNC_URLS)],
        # Entrada sin pageref dentro de la ventana de la página 1: se suma a ella.
        _entry("https://www.tienda-sintetica.example/tardia.gif", "2026-01-15T10:00:02.000Z"),
        # No son requests de red: se ignoran.
        _entry("data:image/gif;base64,AAAA", "2026-01-15T10:00:02.100Z", pageref="page_1"),
        # --- página 2 ---
        _entry("https://www.tienda-sintetica.example/otra", "2026-01-15T10:05:00.000Z", pageref="page_2", resource_type="document", mime="text/html"),
        _entry("https://static.tienda-sintetica.example/otra.css", "2026-01-15T10:05:00.100Z", pageref="page_2", resource_type="stylesheet", mime="text/css"),
    ]
    return {"log": {
        "version": "1.2",
        "creator": {"name": f"Sintético {XSS}", "version": "1"},
        "pages": [
            {"id": "page_1", "startedDateTime": "2026-01-15T10:00:00.000Z", "title": PAGE_URL, "pageTimings": {}},
            {"id": "page_2", "startedDateTime": "2026-01-15T10:05:00.000Z", "title": XSS, "pageTimings": {}},
        ],
        "entries": entries,
    }}


def as_bytes() -> bytes:
    return json.dumps(build()).encode("utf-8")
