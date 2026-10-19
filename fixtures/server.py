"""Sitio de fixtures: ground truth para los tests de captura (F2).

Un solo servidor responde por varios nombres (alias de red en compose) que
simulan dominios distintos. Registra cada request recibida y la expone en
/__received para compararla con lo que capturó el worker.
"""

import asyncio
import base64
import hashlib
import json
import pathlib
import uuid

from aiohttp import WSMsgType, web

SITE = "site.fixtures.test"
TRACKER = "tracker-a.fixtures.test"
CDN = "cdn-b.fixtures.test"

STATIC = pathlib.Path(__file__).parent / "static"
GIF_1X1 = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)
FLOOD_REQUESTS = 2000

received: list[dict] = []
abuse_reports: list[dict] = []


@web.middleware
async def record(request: web.Request, handler):
    if not request.path.startswith("/__"):
        body = await request.read()
        received.append(
            {
                "seq": len(received),
                "method": request.method,
                "host": request.host,
                "path": request.path,
                "query": request.query_string and request.rel_url.raw_query_string,
                "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
                "body_size": len(body),
                "websocket": request.headers.get("Upgrade", "").lower() == "websocket",
                # Cómo se presenta el navegador (perfil base, ADR 008).
                "user_agent": request.headers.get("User-Agent"),
                "sec_ch_ua": request.headers.get("Sec-CH-UA"),
                "sec_ch_ua_platform": request.headers.get("Sec-CH-UA-Platform"),
                "sec_ch_ua_mobile": request.headers.get("Sec-CH-UA-Mobile"),
                "accept_language": request.headers.get("Accept-Language"),
            }
        )
    response = await handler(request)
    # Sin caché: cada request de la página debe llegar al servidor.
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    return response


def static(name: str, content_type: str):
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=(STATIC / name).read_bytes(), content_type=content_type)

    return handler


def binary(body: bytes, content_type: str):
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=body, content_type=content_type)

    return handler


async def index(request: web.Request) -> web.Response:
    response = web.Response(body=(STATIC / "index.html").read_bytes(), content_type="text/html")
    response.set_cookie("fx_session", "abc123", path="/", httponly=True)
    return response


async def api_data(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


async def collect(request: web.Request) -> web.Response:
    return web.Response(status=204)


async def redirect_start(request: web.Request) -> web.Response:
    raise web.HTTPFound(f"http://{TRACKER}/redirect/hop")


# Redirecciones hacia destinos que el proxy debe bloquear (tests SSRF). Mapa fijo: no es un
# redirector abierto.
SSRF_REDIRECTS = {
    "metadata": "http://169.254.169.254/latest/meta-data/",
    "loopback": "http://127.0.0.1/",
    "private": "http://10.0.0.1/",
    "api": "http://api:8000/health",
    "db": "http://db:5432/",
}


async def ssrf_redirect(request: web.Request) -> web.Response:
    target = SSRF_REDIRECTS.get(request.match_info["target"])
    if target is None:
        raise web.HTTPNotFound()
    raise web.HTTPFound(target)


# v1.4.8 (docs/adr/035): documento que nunca responde a tiempo, directo o tras una redirección ya respondida.
HANG_S = 90


async def hang(request: web.Request) -> web.Response:
    await asyncio.sleep(HANG_S)
    return web.Response(text="tarde", content_type="text/html")


async def redirect_to_hang(request: web.Request) -> web.Response:
    raise web.HTTPFound("/v148/hang")


# v1.5.1: identificador fijo que el fixture envía en URL, parámetros, cookies, cabeceras y redirección.
V151_ID = "5f0c3e9a7b1d4c2e8f6a0b9c3d7e1f42"


async def v151_page(request: web.Request) -> web.Response:
    response = web.Response(body=(STATIC / "v151/index.html").read_bytes(), content_type="text/html")
    response.set_cookie("v151_uid", V151_ID, path="/")
    return response


async def v151_pixel(request: web.Request) -> web.Response:
    response = web.HTTPFound(f"http://{CDN}/v151/sync/{V151_ID}?partner_uid={V151_ID}")
    response.set_cookie("v151_tp", V151_ID, path="/")
    raise response


# v1.5.2: comparación de visitas. El servidor da un identificador nuevo a cada perfil sin cookie y reutiliza el que trae
# la cookie. La «campaña» cambia desde la segunda carga de la página (estado del servidor, como una rotación A/B):
# aparece en las visitas 2 y 3, no en la 1. /__reset vuelve a empezar la cuenta.
v152_loads = 0


async def v152_page(request: web.Request) -> web.Response:
    global v152_loads
    v152_loads += 1
    response = web.Response(body=(STATIC / "v152/index.html").read_bytes(), content_type="text/html")
    uid = request.cookies.get("v152_uid") or uuid.uuid4().hex
    response.set_cookie("v152_uid", uid, path="/", max_age=365 * 24 * 3600)
    response.set_cookie("v152_sess", uuid.uuid4().hex, path="/")  # de sesión: sin Max-Age ni Expires
    response.set_cookie("v152_campaign", "inicio" if v152_loads == 1 else "rotada", path="/")
    return response


async def v152_cached(request: web.Request) -> web.Response:
    response = web.Response(body=(STATIC / "v152/cached.js").read_bytes(), content_type="application/javascript")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


async def redirect_hop(request: web.Request) -> web.Response:
    raise web.HTTPMovedPermanently(f"http://{CDN}/redirect/final")


async def websocket(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for message in ws:
        if message.type == WSMsgType.TEXT:
            await ws.send_str(f"echo:{message.data}")
    return ws


async def flood(request: web.Request) -> web.Response:
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Flood</title>
<link rel="icon" href="data:,"></head><body><script>
(async () => {{
  const total = {FLOOD_REQUESTS}, batch = 100;
  for (let start = 0; start < total; start += batch) {{
    const pending = [];
    for (let i = start; i < Math.min(start + batch, total); i++) pending.push(fetch('/flood/item?i=' + i));
    await Promise.allSettled(pending);
  }}
}})();
</script></body></html>"""
    return web.Response(text=html, content_type="text/html")


async def flood_item(request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def xss_script(request: web.Request) -> web.Response:
    """Script cuyo NOMBRE es un payload; lee el renderer para aparecer en la vista de fingerprinting."""
    body = """(function () {
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var info = gl.getExtension('WEBGL_debug_renderer_info');
    gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
  } catch (error) {}
  navigator.sendBeacon('http://tracker-a.fixtures.test/xss/post', 'hecho');
})();"""
    return web.Response(text=body, content_type="application/javascript")


async def cookieless_script(request: web.Request) -> web.Response:
    """Tracker "sin cookies": el servidor aporta un hash de la IP y el script uno de UA + pantalla + zona.

    El identificador final es <hash del dispositivo>-<hash de la IP>: no hay cookie ni storage, y aun
    así es el mismo en cada visita. Cambiar el perfil del navegador cambia la primera mitad, no la segunda.
    """
    ip_hash = hashlib.sha256(("ip:" + (request.remote or "")).encode()).hexdigest()[:16]
    body = """(async function () {
  var device = [navigator.userAgent, screen.width + 'x' + screen.height, Intl.DateTimeFormat().resolvedOptions().timeZone].join('|');
  var digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(device));
  var deviceHash = Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('').slice(0, 16);
  new Image().src = 'http://tracker-a.fixtures.test/cl.gif?fpid=' + deviceHash + '-%s&v=3';
})();""" % ip_hash
    return web.Response(text=body, content_type="application/javascript")


async def abuse_report(request: web.Request) -> web.Response:
    """Lo que el script hostil del fixture dice haber encontrado (lo lee el test)."""
    abuse_reports.append(await request.json())
    return web.Response(status=204)


async def get_abuse(request: web.Request) -> web.Response:
    return web.json_response({"reports": abuse_reports})


async def get_received(request: web.Request) -> web.Response:
    return web.json_response({"requests": received})


async def reset(request: web.Request) -> web.Response:
    global v152_loads
    v152_loads = 0
    received.clear()
    abuse_reports.clear()
    return web.json_response({"reset": True})


# v1.5.0: IP «pública» que devuelve el servicio de IP de salida de prueba (EGRESS_IP_SERVICE_URL en scripts/test.sh).
# Ruta de control (/__...): no se registra en /__received, no es tráfico del sitio.
EGRESS_TEST_IP = "8.8.8.8"


async def egress_ip(request: web.Request) -> web.Response:
    return web.Response(text=EGRESS_TEST_IP + "\n", content_type="text/plain")


async def egress_ip_invalid(request: web.Request) -> web.Response:
    return web.Response(text="no-es-una-ip", content_type="text/plain")


async def empty(request: web.Request) -> web.Response:
    return web.Response(status=204)


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def build_app() -> web.Application:
    app = web.Application(middlewares=[record], client_max_size=1024 * 1024)
    app.add_routes(
        [
            # first-party
            web.get("/", index),
            web.get("/static/style.css", static("style.css", "text/css")),
            web.get("/static/app.js", static("app.js", "application/javascript")),
            web.get("/img/first.png", binary(PNG_1X1, "image/png")),
            web.get("/api/data", api_data),
            web.post("/metrics", collect),
            web.get("/redirect/start", redirect_start),
            web.get("/v148/hang", hang),
            web.get("/v148/redirect-to-hang", redirect_to_hang),
            web.get("/ssrf/redirect/{target}", ssrf_redirect),
            web.get("/ws", websocket),
            web.get("/sw.js", static("sw.js", "application/javascript")),
            web.get("/manifest.json", static("manifest.json", "application/json")),
            web.get("/flood", flood),
            web.get("/flood/item", flood_item),
            # página de fingerprinting (F4)
            web.get("/fp/article", static("fp/index.html", "text/html")),
            web.get("/fp/probe", static("fp/probe.html", "text/html")),
            web.get("/static/fp/abuse.js", static("fp/abuse.js", "application/javascript")),
            web.get("/static/fp/benign.js", static("fp/benign.js", "application/javascript")),
            web.get("/static/fp/fonts.js", static("fp/fonts.js", "application/javascript")),
            web.get("/static/fp/webrtc.js", static("fp/webrtc.js", "application/javascript")),
            web.get("/static/fp/probe.js", static("fp/probe.js", "application/javascript")),
            web.get("/fp/animation-done", api_data),
            web.get("/fp/animation-tick", api_data),
            web.post("/fp/abuse-report", abuse_report),
            web.get("/__abuse", get_abuse),
            # consentimiento e identificador sin cookies (F7)
            web.get("/cmp/", static("cmp/index.html", "text/html")),
            web.get("/cmp/unknown", static("cmp/unknown.html", "text/html")),
            web.get("/static/cmp/cmp.js", static("cmp/cmp.js", "application/javascript")),
            web.get("/cmp/pre.gif", binary(GIF_1X1, "image/gif")),
            web.get("/cmp/accept-only.gif", binary(GIF_1X1, "image/gif")),
            web.get("/cmp/ignores-reject.gif", binary(GIF_1X1, "image/gif")),
            web.get("/cmp/clicked-unknown.gif", binary(GIF_1X1, "image/gif")),
            web.get("/cookieless/", static("cookieless/index.html", "text/html")),
            web.get("/cookieless.js", cookieless_script),
            web.get("/cl.gif", binary(GIF_1X1, "image/gif")),
            # TCF, Consent Mode y CNAME (F8)
            web.get("/f8/", static("f8/index.html", "text/html")),
            web.get("/static/f8/f8.js", static("f8/f8.js", "application/javascript")),
            web.get("/g/collect", binary(GIF_1X1, "image/gif")),
            web.get("/pagead/conversion", binary(GIF_1X1, "image/gif")),
            web.get("/b/ss/collect", binary(GIF_1X1, "image/gif")),
            # Registro de interacción, librería benigna de canvas y script inline (v1.4.2)
            web.get("/interact/", static("interact/index.html", "text/html")),
            web.get("/static/interact/interact.js", static("interact/interact.js", "application/javascript")),
            web.get("/static/interact/qrcode.min.js", static("interact/qrcode.min.js", "application/javascript")),
            web.get("/interact/event", binary(GIF_1X1, "image/gif")),
            # Conversions API de Meta en un host de nube genérico (v1.4.2): el fixture no tiene un host on.aws; lo prueba el analizador con una captura sintética.
            # Login para el enmascarado de credenciales de la captura interactiva (v1.4.1)
            web.get("/login/", static("login/index.html", "text/html")),
            web.get("/static/login/login.js", static("login/login.js", "application/javascript")),
            web.post("/login/submit", index),
            web.post("/login/api", collect),
            web.post("/login/upload", collect),
            # IDs de cuenta del sitio (v1.2)
            web.get("/accounts/", static("accounts/index.html", "text/html")),
            web.get("/static/accounts/accounts.js", static("accounts/accounts.js", "application/javascript")),
            web.get("/gtm.js", binary(GIF_1X1, "image/gif")),
            web.get("/pagead/conversion/{account}/", binary(GIF_1X1, "image/gif")),
            web.get("/tr", binary(GIF_1X1, "image/gif")),
            web.get("/v3/", binary(GIF_1X1, "image/gif")),
            web.get("/p", binary(GIF_1X1, "image/gif")),
            web.get("/api/v2/pixel", binary(GIF_1X1, "image/gif")),
            web.get("/li/collect", binary(GIF_1X1, "image/gif")),
            # v1.4.5: servicios de terceros sin señales de rastreo, varias cuentas de analítica, recuadro que no carga
            web.get("/v145/", static("v145/index.html", "text/html")),
            web.get("/static/v145/v145.js", static("v145/v145.js", "application/javascript")),
            # Protocolo de visita, cobertura de contextos e IP de salida (v1.5.0)
            web.get("/v150/coverage/", static("v150/coverage.html", "text/html")),
            web.get("/v150/coverage/frame", static("v150/frame.html", "text/html")),
            web.get("/static/v150/coverage.js", static("v150/coverage.js", "application/javascript")),
            web.get("/static/v150/frame.js", static("v150/frame.js", "application/javascript")),
            web.get("/static/v150/worker.js", static("v150/worker.js", "application/javascript")),
            web.get("/static/v150/sw.js", static("v150/sw.js", "application/javascript")),
            web.get("/v150/mark", empty),
            web.get("/v150/mark-failed", empty),
            web.get("/v150/sw-registration", empty),
            web.get("/v150/scroll/", static("v150/scroll.html", "text/html")),
            web.get("/static/v150/scroll.js", static("v150/scroll.js", "application/javascript")),
            web.get("/v150/scroll-bottom", empty),
            web.get("/v150/scroll-more", empty),
            web.get("/v150/close/", static("v150/close.html", "text/html")),
            web.get("/static/v150/close.js", static("v150/close.js", "application/javascript")),
            web.post("/v150/bye", empty),
            web.get("/__egress-ip", egress_ip),
            # Enmascarado del detalle de request (v1.5.1)
            web.get("/v151/", v151_page),
            web.get("/static/v151/v151.js", static("v151/v151.js", "application/javascript")),
            web.get("/v151/px", v151_pixel),
            web.get("/v151/sync/{uid}", binary(GIF_1X1, "image/gif")),
            web.get("/v151/ping", empty),
            web.get("/__egress-ip-invalid", egress_ip_invalid),
            # Comparación de visitas (v1.5.2)
            web.get("/v152/", v152_page),
            web.get("/static/v152/v152.js", static("v152/v152.js", "application/javascript")),
            web.post("/v152/collect", collect),
            web.get("/v152/welcome-back.gif", binary(GIF_1X1, "image/gif")),
            web.get("/v152/px", binary(GIF_1X1, "image/gif")),
            web.get("/v152/cached.js", v152_cached),
            # fixture XSS (F5)
            web.get("/xss/", static("xss/index.html", "text/html")),
            web.get("/static/xss/payloads.js", static("xss/payloads.js", "application/javascript")),
            web.get("/xss/collect.gif", binary(GIF_1X1, "image/gif")),
            web.get("/xss/sync.gif", binary(GIF_1X1, "image/gif")),
            web.post("/xss/post", collect),
            web.get("/xss/{name}.js", xss_script),
            # tracker-a
            web.get("/fp.js", static("fp/fp.js", "application/javascript")),
            web.get("/fp-collect.gif", binary(GIF_1X1, "image/gif")),
            web.post("/fp-beacon", collect),
            web.get("/ref-full.gif", binary(GIF_1X1, "image/gif")),
            web.get("/ref-origin.gif", binary(GIF_1X1, "image/gif")),
            web.get("/ref-none.gif", binary(GIF_1X1, "image/gif")),
            web.get("/tracker.js", static("tracker.js", "application/javascript")),
            web.get("/pixel.gif", binary(GIF_1X1, "image/gif")),
            web.get("/leak.gif", binary(GIF_1X1, "image/gif")),
            web.get("/jwt.gif", binary(GIF_1X1, "image/gif")),
            web.post("/beacon", collect),
            web.post("/collect", collect),
            web.get("/frame.html", static("frame.html", "text/html")),
            web.get("/frame-pixel.gif", binary(GIF_1X1, "image/gif")),
            web.get("/redirect/hop", redirect_hop),
            # cdn-b
            web.get("/logo.png", binary(PNG_1X1, "image/png")),
            web.get("/lib.css", static("lib.css", "text/css")),
            web.get("/sync.gif", binary(GIF_1X1, "image/gif")),
            web.get("/font.woff2", binary(b"wOF2-not-a-real-font", "font/woff2")),
            web.get("/redirect/final", binary(GIF_1X1, "image/gif")),
            # control
            web.get("/__received", get_received),
            web.post("/__reset", reset),
            web.get("/__health", health),
        ]
    )
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=80, access_log=None)
