"""Captura de tráfico de un scan (F2). Registra; no clasifica ni interpreta.

Todo lo que viene del sitio (URLs, headers, bodies, frames, storage, stacks) es
NO confiable: se acota en tamaño y se guarda como dato.

Fuentes:
- Eventos de Playwright (request/response/requestfinished/requestfailed/websocket).
- CDP Network.requestWillBeSent, solo para el initiator y como respaldo del
  post_data. Playwright no expone el requestId de CDP, así que se empareja por
  (método, URL) en orden de llegada.
"""

import asyncio
import base64
import hashlib
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError

from app.browser.parties import is_third_party, registrable_domain

logger = logging.getLogger(__name__)

MAX_URL_CHARS = 8192
MAX_HEADERS = 200
MAX_HEADER_NAME_CHARS = 256
MAX_HEADER_VALUE_CHARS = 8192
MAX_QUERY_PARAMS = 500
MAX_STACK_FRAMES = 30
ASYNC_STACK_DEPTH = 8
MAX_FUNCTION_NAME_CHARS = 256
MAX_FAILURE_CHARS = 512
MAX_WEBSOCKETS = 50
# Cabeceras del navegador con el egress-proxy, no del sitio (v1.5.3, docs/adr/041): Proxy-Authorization lleva el usuario
# del scan y PROXY_SCAN_SECRET en base64. Nunca se guardan.
PROXY_HEADERS = frozenset({"proxy-authorization", "proxy-connection"})
MAX_WS_FRAMES = 50
MAX_WS_FRAME_BYTES = 4096
MAX_COOKIES = 500
MAX_COOKIE_VALUE_CHARS = 4096
MAX_STORAGE_ORIGINS = 20
MAX_STORAGE_ITEMS = 200
MAX_STORAGE_KEY_CHARS = 512
MAX_STORAGE_VALUE_CHARS = 4096
# Llamadas al navegador durante el volcado: ninguna puede colgar la captura.
EXTRA_CALL_TIMEOUT_S = 2.0
FINALIZE_BUDGET_S = 12.0
FINALIZE_CONCURRENCY = 50
MAX_MASKED_FIELDS = 200

PROXY_ERROR_HEADER = "x-squid-error"
PROXY_TUNNEL_ERROR = "ERR_TUNNEL_CONNECTION_FAILED"
SW_BLOCKED_MARKER = "Service Worker registration blocked by Playwright"

# Devuelve como mucho `maxItems` pares por storage; el valor ya viene cortado.
STORAGE_JS = """([maxItems, maxKey, maxValue]) => {
    const dump = (name) => {
        const out = {items: [], total: 0, error: null};
        try {
            const storage = window[name];
            out.total = storage.length;
            for (let i = 0; i < storage.length && out.items.length < maxItems; i++) {
                const key = String(storage.key(i));
                const value = String(storage.getItem(key));
                out.items.push([key.slice(0, maxKey), value.slice(0, maxValue), value.length > maxValue]);
            }
        } catch (error) {
            out.error = String(error).slice(0, 200);
        }
        return out;
    };
    return {origin: String(location.origin), local: dump('localStorage'), session: dump('sessionStorage')};
}"""

SW_REGISTRATIONS_JS = """async () => {
    if (!navigator.serviceWorker) return null;
    try { return (await navigator.serviceWorker.getRegistrations()).length; } catch (error) { return null; }
}"""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def text(value: object, limit: int) -> str | None:
    """Cadena acotada y almacenable en Postgres (sin NUL ni surrogates sueltos)."""
    if not isinstance(value, str):
        return None
    value = value[:limit]
    return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


def encode_body(data: bytes, limit: int) -> dict:
    """Cuerpo truncado a `limit` bytes. sha256 y size son del cuerpo completo."""
    truncated = len(data) > limit
    head = data[:limit]
    encoding, payload = "base64", None
    # Al truncar se puede partir un carácter multibyte: se prueba recortando hasta 3 bytes.
    for cut in range(4 if truncated else 1):
        candidate = head[: len(head) - cut] if cut else head
        try:
            decoded = candidate.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "\x00" not in decoded:
            encoding, payload = "utf8", decoded
        break
    if payload is None:
        payload = base64.b64encode(head).decode("ascii")
    return {
        "data": payload,
        "encoding": encoding,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": truncated,
    }


def split_url(url: str) -> dict:
    """Partes de la URL sin decodificar nada. La query se conserva cruda, en orden y con duplicados."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return {"scheme": None, "host": None, "path": None, "query_params": []}
    params = []
    if parts.query:
        for pair in parts.query.split("&")[:MAX_QUERY_PARAMS]:
            name, separator, value = pair.partition("=")
            # None = el parámetro venía sin "=" (distinto de valor vacío).
            params.append([text(name, MAX_URL_CHARS), text(value, MAX_URL_CHARS) if separator else None])
    return {
        "scheme": text(parts.scheme.lower(), 32),
        "host": text(host, 255),
        "path": text(parts.path, MAX_URL_CHARS),
        "query_params": params,
    }


def clean_headers(headers: object) -> list[dict]:
    out = []
    if not isinstance(headers, list):
        return out
    for header in headers[:MAX_HEADERS]:
        if not isinstance(header, dict):
            continue
        name = text(header.get("name"), MAX_HEADER_NAME_CHARS)
        value = text(header.get("value"), MAX_HEADER_VALUE_CHARS)
        if name is not None and value is not None and name.lower() not in PROXY_HEADERS:
            out.append({"name": name, "value": value})
    return out


def header_value(headers: list[dict], name: str) -> str | None:
    for header in headers:
        if header["name"].lower() == name:
            return header["value"]
    return None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def normalize_initiator(initiator: object) -> dict | None:
    """Initiator de CDP reducido a tipo, URL y stack acotado.

    `script_url` es el primer frame del stack con URL: el script que lanzó la request.
    """
    if not isinstance(initiator, dict):
        return None
    frames = []
    stack = initiator.get("stack")
    depth = 0
    # El stack puede venir encadenado por `parent` (llamadas asíncronas).
    while isinstance(stack, dict) and len(frames) < MAX_STACK_FRAMES and depth < 10:
        call_frames = stack.get("callFrames")
        for frame in call_frames if isinstance(call_frames, list) else []:
            if not isinstance(frame, dict) or len(frames) >= MAX_STACK_FRAMES:
                continue
            frames.append(
                {
                    "function": text(frame.get("functionName"), MAX_FUNCTION_NAME_CHARS) or "",
                    "url": text(frame.get("url"), MAX_URL_CHARS) or "",
                    "line": _int(frame.get("lineNumber")),
                    "column": _int(frame.get("columnNumber")),
                    "async": depth > 0,
                }
            )
        stack = stack.get("parent")
        depth += 1
    url = text(initiator.get("url"), MAX_URL_CHARS)
    script_url = next((frame["url"] for frame in frames if frame["url"]), None)
    return {
        "type": text(initiator.get("type"), 32),
        "url": url,
        "line": _int(initiator.get("lineNumber")),
        "script_url": script_url or url,
        "stack": frames,
    }


class NetworkMonitor:
    def __init__(self, context, page, *, start_url: str, max_requests: int, max_body_bytes: int) -> None:
        self._context = context
        self._page = page
        # Páginas vigiladas: una en un scan; varias pestañas en una captura interactiva (v1.4).
        self._pages: list = []
        self._start_url = start_url
        self._max_requests = max_requests
        self._max_body_bytes = max_body_bytes
        self._loop = asyncio.get_running_loop()
        self._records: list[dict] = []
        self._by_request: dict = {}
        self._websockets: list[dict] = []
        self._cdp: dict[tuple[str, str], deque] = defaultdict(deque)
        self._cdp_count = 0
        # [(método CDP, parámetros)] que se envían a cada sesión (página u OOPIF) al adjuntarla.
        self.session_setup: list[tuple[str, dict]] = []
        self._cdp_frames: set = set()
        self._tasks: set[asyncio.Task] = set()
        self._sw_blocked: list[str] = []
        # Filtro opcional de cuerpos (bytes, content-type) -> (bytes, [{name, length}]); lo usa la captura interactiva.
        self.body_filter = None
        self.masked_fields: list[dict] = []
        self.truncated = False
        self.last_activity = self._loop.time()
        # Volcado previo al cierre de la pestaña (v1.5.0): con la pestaña cerrada Chromium ya no entrega cabeceras.
        self._matched = 0
        self._pre: dict | None = None

    @property
    def count(self) -> int:
        """Requests registradas hasta ahora (sirve de frontera "antes / después" de una acción)."""
        return len(self._records)

    @property
    def responses(self) -> int:
        """Requests que ya recibieron respuesta (decide si un goto agotado deja un scan parcial)."""
        return sum(1 for record in self._records if record["response"] is not None)

    def _main_documents(self):
        for record in self._records:
            request = record["request"]
            try:
                if request.resource_type == "document" and request.frame.parent_frame is None:
                    yield record
            except PlaywrightError:  # request sin frame (p. ej. de un worker)
                continue

    def document_status(self) -> int | None:
        """Estado HTTP de la última navegación de la página principal que recibió respuesta. None = ninguna."""
        status = None
        for record in self._main_documents():
            if record["response"] is not None:
                status = record["response"].status
        return status

    def navigation_failure(self) -> str | None:
        """Texto de error de red (net::ERR_*) del primer documento principal que falló. None = ninguno."""
        for record in self._main_documents():
            if record["failed"]:
                return text(record["request"].failure, 200)
        return None

    # --- arranque ---

    async def start(self) -> None:
        await self.attach_page(self._page)

    def set_primary(self, page) -> None:
        """Página de referencia para el snapshot final (la última en la que navegó el usuario)."""
        self._page = page

    async def attach_page(self, page) -> None:
        """Vigila una página más del mismo contexto (pestañas nuevas de una captura interactiva)."""
        if page in self._pages:
            return
        self._pages.append(page)
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("requestfinished", self._on_finished)
        page.on("requestfailed", self._on_failed)
        page.on("websocket", self._on_websocket)
        page.on("console", self._on_console)
        page.on("framenavigated", self._on_frame_navigated)
        await self._attach_cdp(page)

    async def _attach_cdp(self, target) -> None:
        try:
            session = await self._context.new_cdp_session(target)
            session.on("Network.requestWillBeSent", lambda params: self._on_cdp_request(session, params))
            await session.send("Network.enable")
            # Sin stacks asíncronos, lo que Chromium carga en diferido (p. ej. `new Image().src`)
            # llega como initiator "parser" y no se puede atribuir a su script.
            await session.send("Runtime.enable")
            await session.send("Runtime.setAsyncCallStackDepth", {"maxDepth": ASYNC_STACK_DEPTH})
            # Ajustes del perfil del navegador que van por sesión CDP (v1.4.5: idiomas del perfil base).
            for method, params in self.session_setup:
                await session.send(method, params)
        except PlaywrightError:
            # Un frame del mismo proceso que su padre no tiene sesión propia: ya lo cubre la del padre.
            self._cdp_frames.discard(target)

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- eventos de Playwright ---

    def _on_request(self, request) -> None:
        self.last_activity = self._loop.time()
        if len(self._records) >= self._max_requests:
            self.truncated = True
            return
        record = {
            "seq": len(self._records),
            "ts": now_utc(),
            "request": request,
            "response": None,
            "finished": False,
            "failed": False,
        }
        self._records.append(record)
        self._by_request[request] = record

    def _on_response(self, response) -> None:
        record = self._by_request.get(response.request)
        if record is not None:
            record["response"] = response

    def _on_finished(self, request) -> None:
        record = self._by_request.get(request)
        if record is not None:
            record["finished"] = True

    def _on_failed(self, request) -> None:
        record = self._by_request.get(request)
        if record is not None:
            record["failed"] = True

    def _on_console(self, message) -> None:
        try:
            content = message.text
        except PlaywrightError:
            return
        if SW_BLOCKED_MARKER in content and len(self._sw_blocked) < 20:
            page_url = text(self._page.url, MAX_URL_CHARS)
            self._sw_blocked.append(page_url)
            logger.warning("service_worker_registration_blocked", extra={"page_url": page_url})

    def _on_frame_navigated(self, frame) -> None:
        # Los iframes cross-site viven en otro proceso (OOPIF) con su propia sesión CDP.
        if frame.parent_frame is None or frame in self._cdp_frames:
            return
        self._cdp_frames.add(frame)
        self._spawn(self._attach_cdp(frame))

    def _on_websocket(self, websocket) -> None:
        self.last_activity = self._loop.time()
        if len(self._websockets) >= MAX_WEBSOCKETS:
            return
        record = {
            "seq": len(self._websockets),
            "ts": now_utc(),
            "url": websocket.url,
            "frames": [],
            "frames_sent": 0,
            "frames_received": 0,
            "closed": False,
            "error": None,
        }
        self._websockets.append(record)

        def on_frame(direction: str, payload) -> None:
            record[f"frames_{direction}"] += 1
            if len(record["frames"]) >= MAX_WS_FRAMES:
                return
            binary = isinstance(payload, (bytes, bytearray))
            data = bytes(payload) if binary else str(payload).encode("utf-8", "replace")
            body = encode_body(data, MAX_WS_FRAME_BYTES)
            if binary:
                # Un frame binario se guarda siempre en base64, aunque sea UTF-8 válido.
                body["data"] = base64.b64encode(data[:MAX_WS_FRAME_BYTES]).decode("ascii")
                body["encoding"] = "base64"
            record["frames"].append(
                {"seq": len(record["frames"]), "ts": now_utc(), "direction": direction, "opcode": "binary" if binary else "text", **body}
            )

        websocket.on("framesent", lambda payload: on_frame("sent", payload))
        websocket.on("framereceived", lambda payload: on_frame("received", payload))
        websocket.on("close", lambda _: record.__setitem__("closed", True))
        websocket.on("socketerror", lambda error: record.__setitem__("error", text(str(error), MAX_FAILURE_CHARS)))

    # --- eventos de CDP ---

    def _on_cdp_request(self, session, params) -> None:
        if not isinstance(params, dict) or self._cdp_count >= self._max_requests * 2:
            return
        request = params.get("request")
        if not isinstance(request, dict):
            return
        method, url = request.get("method"), request.get("url")
        if not isinstance(method, str) or not isinstance(url, str):
            return
        fragment = request.get("urlFragment")
        if isinstance(fragment, str):
            url += fragment
        entry = {"initiator": params.get("initiator"), "post_data": None}
        self._cdp[(method, url)].append(entry)
        self._cdp_count += 1
        if request.get("hasPostData"):
            entries = request.get("postDataEntries")
            try:
                if not isinstance(entries, list) or not entries:
                    raise ValueError
                entry["post_data"] = b"".join(base64.b64decode(item["bytes"]) for item in entries)
            except (KeyError, TypeError, ValueError):
                # Cuerpos que CDP no adjunta al evento (p. ej. Blob): se piden aparte.
                request_id = params.get("requestId")
                if isinstance(request_id, str):
                    self._spawn(self._fetch_post_data(session, request_id, entry))

    async def _fetch_post_data(self, session, request_id: str, entry: dict) -> None:
        try:
            result = await asyncio.wait_for(
                session.send("Network.getRequestPostData", {"requestId": request_id}), EXTRA_CALL_TIMEOUT_S
            )
        except (PlaywrightError, asyncio.TimeoutError):
            return
        data = result.get("postData") if isinstance(result, dict) else None
        if isinstance(data, str):
            entry["post_data"] = data.encode("utf-8", "replace")

    # --- volcado ---

    async def _call(self, factory, deadline: float):
        """Llamada al navegador con timeout. Devuelve None si falla o se agotó el presupuesto."""
        if self._loop.time() >= deadline:
            return None
        try:
            return await asyncio.wait_for(factory(), EXTRA_CALL_TIMEOUT_S)
        except (PlaywrightError, asyncio.TimeoutError):
            return None

    async def _build(self, record: dict, cdp_entry: dict | None, first_party: set[str], deadline: float) -> dict:
        request = record["request"]
        response = record["response"]
        raw_url = request.url
        parts = split_url(raw_url)

        request_headers = await self._call(request.headers_array, deadline)
        if request_headers is None:
            request_headers = [{"name": name, "value": value} for name, value in request.headers.items()]
        request_headers = clean_headers(request_headers)

        status, response_headers, mime = None, None, None
        if response is not None:
            status = response.status
            response_headers = await self._call(response.headers_array, deadline)
            if response_headers is None:
                response_headers = [{"name": name, "value": value} for name, value in response.headers.items()]
            response_headers = clean_headers(response_headers)
            content_type = header_value(response_headers, "content-type")
            mime = text(content_type.split(";")[0].strip().lower(), 255) if content_type else None

        sizes = await self._call(request.sizes, deadline) if record["finished"] else None

        post_data = request.post_data_buffer
        post_data_source = "playwright"
        if post_data is None and cdp_entry is not None and cdp_entry["post_data"] is not None:
            post_data, post_data_source = cdp_entry["post_data"], "cdp"
        if post_data is not None and self.body_filter is not None:
            # Captura interactiva: credenciales enmascaradas ANTES de codificar y guardar (hash incluido).
            post_data, masked = self.body_filter(post_data, header_value(request_headers, "content-type"))
            for item in masked:
                if len(self.masked_fields) < MAX_MASKED_FIELDS:
                    self.masked_fields.append({**item, "seq": record["seq"]})
        if isinstance(post_data, str):
            post_data = post_data.encode("utf-8")
        body = encode_body(post_data, self._max_body_bytes) if post_data is not None else None

        failure = text(request.failure, MAX_FAILURE_CHARS) if record["failed"] else None
        blocked = bool(response_headers and header_value(response_headers, PROXY_ERROR_HEADER)) or bool(
            failure and PROXY_TUNNEL_ERROR in failure
        )
        try:
            frame_url = text(request.frame.url, MAX_URL_CHARS)
        except PlaywrightError:
            frame_url = None  # request sin frame (p. ej. de un worker)
        redirected_from = self._by_request.get(request.redirected_from) if request.redirected_from else None
        timing = request.timing
        return {
            "seq": record["seq"],
            "ts": record["ts"],
            "method": text(request.method, 32),
            "url": text(raw_url, MAX_URL_CHARS),
            "url_truncated": len(raw_url) > MAX_URL_CHARS,
            **parts,
            "resource_type": text(request.resource_type, 32),
            "frame_url": frame_url,
            "is_navigation": request.is_navigation_request(),
            "initiator": normalize_initiator(cdp_entry["initiator"]) if cdp_entry else None,
            "request_headers": request_headers,
            "post_data": body,
            "post_data_source": post_data_source if body else None,
            "response_status": status,
            "response_headers": response_headers,
            "mime_type": mime,
            "sizes": {key: value for key, value in sizes.items() if _int(value) is not None} if sizes else None,
            "timing": {key: value for key, value in timing.items() if isinstance(value, (int, float))},
            "failure_text": failure,
            "blocked_by_proxy": blocked,
            "third_party": is_third_party(parts["host"], first_party),
            "registrable_domain": registrable_domain(parts["host"]),
            "redirected_from_seq": redirected_from["seq"] if redirected_from else None,
        }

    def _redirect_chains(self, built: list[dict]) -> list[list[dict]]:
        by_seq = {item["seq"]: item for item in built}
        next_hop = {item["redirected_from_seq"]: item["seq"] for item in built if item["redirected_from_seq"] is not None}
        chains = []
        for item in built:
            if item["redirected_from_seq"] is not None or item["seq"] not in next_hop:
                continue
            chain, seq = [], item["seq"]
            while seq is not None and len(chain) < 50:
                hop = by_seq[seq]
                chain.append({"request_seq": seq, "url": hop["url"], "status": hop["response_status"]})
                seq = next_hop.get(seq)
            chains.append(chain)
        return chains

    def _build_websockets(self, first_party: set[str]) -> list[dict]:
        out = []
        for record in self._websockets:
            host = split_url(record["url"])["host"]
            out.append(
                {
                    "seq": record["seq"],
                    "ts": record["ts"],
                    "url": text(record["url"], MAX_URL_CHARS),
                    "host": host,
                    "third_party": is_third_party(host, first_party),
                    "frames_sent": record["frames_sent"],
                    "frames_received": record["frames_received"],
                    "frames_truncated": record["frames_sent"] + record["frames_received"] > len(record["frames"]),
                    "closed": record["closed"],
                    "error": record["error"],
                    "frames": list(record["frames"]),
                }
            )
        return out

    async def _snapshot_cookies(self, first_party: set[str]) -> list[dict]:
        try:
            cookies = await asyncio.wait_for(self._context.cookies(), EXTRA_CALL_TIMEOUT_S)
        except (PlaywrightError, asyncio.TimeoutError):
            return []
        out = []
        for cookie in cookies[:MAX_COOKIES]:
            domain = text(cookie.get("domain"), 255) or ""
            expires = cookie.get("expires")
            out.append(
                {
                    "name": text(cookie.get("name"), MAX_HEADER_NAME_CHARS) or "",
                    "value": text(cookie.get("value"), MAX_COOKIE_VALUE_CHARS) or "",
                    "domain": domain,
                    "path": text(cookie.get("path"), MAX_URL_CHARS) or "",
                    # -1 = cookie de sesión.
                    "expires": float(expires) if isinstance(expires, (int, float)) else None,
                    "http_only": bool(cookie.get("httpOnly")),
                    "secure": bool(cookie.get("secure")),
                    "same_site": text(cookie.get("sameSite"), 16),
                    "third_party": is_third_party(domain.lstrip("."), first_party),
                }
            )
        return out

    async def _snapshot_storage(self) -> list[dict]:
        """localStorage y sessionStorage por origen, leídos en cada frame http(s)."""
        out, seen = [], set()
        frames = []
        for page in self._pages or [self._page]:
            try:
                frames.extend([] if page.is_closed() else page.frames)
            except PlaywrightError:
                continue
        for frame in frames:
            if not frame.url.startswith(("http://", "https://")) or len(seen) >= MAX_STORAGE_ORIGINS:
                continue
            try:
                dump = await asyncio.wait_for(
                    frame.evaluate(STORAGE_JS, [MAX_STORAGE_ITEMS, MAX_STORAGE_KEY_CHARS, MAX_STORAGE_VALUE_CHARS]),
                    EXTRA_CALL_TIMEOUT_S,
                )
            except (PlaywrightError, asyncio.TimeoutError):
                continue
            # El resultado viene del mundo de la página: se valida tipo y tamaño otra vez.
            if not isinstance(dump, dict):
                continue
            origin = text(dump.get("origin"), MAX_URL_CHARS)
            if not origin or origin in seen:
                continue
            seen.add(origin)
            for storage_type in ("local", "session"):
                section = dump.get(storage_type)
                items = section.get("items") if isinstance(section, dict) else None
                for item in (items if isinstance(items, list) else [])[:MAX_STORAGE_ITEMS]:
                    if not isinstance(item, list) or len(item) != 3:
                        continue
                    key = text(item[0], MAX_STORAGE_KEY_CHARS)
                    value = text(item[1], MAX_STORAGE_VALUE_CHARS)
                    if key is None or value is None:
                        continue
                    out.append(
                        {
                            "origin": origin,
                            "storage_type": storage_type,
                            "key": key,
                            "value": value,
                            "value_truncated": item[2] is True,
                        }
                    )
        return out

    async def _service_workers(self) -> dict:
        try:
            registrations = await asyncio.wait_for(self._page.evaluate(SW_REGISTRATIONS_JS), EXTRA_CALL_TIMEOUT_S)
        except (PlaywrightError, asyncio.TimeoutError):
            registrations = None
        return {
            "blocked_attempts": len(self._sw_blocked),
            # None = no se pudo consultar (p. ej. contexto no seguro: la API no existe).
            "registrations": _int(registrations),
            "active_workers": len(self._context.service_workers),
        }

    def _first_party(self) -> set[str]:
        first_party = set()
        for url in (self._start_url, self._page.url):
            domain = registrable_domain(split_url(url)["host"])
            if domain:
                first_party.add(domain)
        return first_party

    def _match_cdp(self, records: list[dict]) -> None:
        """Empareja con CDP, en orden de llegada, las requests de `records` que aún no lo estaban."""
        for record in records[self._matched:]:
            request = record["request"]
            queue = self._cdp.get((request.method, request.url))
            record["cdp"] = queue.popleft() if queue else None
        self._matched = max(self._matched, len(records))

    @staticmethod
    def _state(record: dict) -> tuple:
        return (record["response"] is not None, record["finished"], record["failed"])

    async def _build_pending(self, first_party: set[str], deadline: float) -> list[dict]:
        """Construye las requests sin construir o que cambiaron (respuesta, fin o fallo) desde la última vez.

        Trabaja sobre una copia fija de las requests y la devuelve: mientras se construyen, la pestaña puede seguir
        generando tráfico (captura interactiva) y lo que llegue después queda fuera de este volcado.
        """
        if self._tasks:
            await asyncio.wait(set(self._tasks), timeout=EXTRA_CALL_TIMEOUT_S)
        records = list(self._records)
        self._match_cdp(records)
        pending = [record for record in records if record.get("built_state") != self._state(record)]
        semaphore = asyncio.Semaphore(FINALIZE_CONCURRENCY)

        async def build(record):
            async with semaphore:
                state = self._state(record)
                record["built"] = await self._build(record, record["cdp"], first_party, deadline)
                record["built_state"] = state

        await asyncio.gather(*(build(record) for record in pending))
        return records

    async def prepare_close(self, budget_s: float = FINALIZE_BUDGET_S) -> None:
        """Vuelca lo que depende de la pestaña antes de cerrarla (v1.5.0): cabeceras, storage y Service Workers.

        Tras el cierre, finalize() solo construye las requests nuevas o que cambiaron, con lo que aún se pueda leer.
        """
        deadline = self._loop.time() + budget_s
        first_party = self._first_party()
        await self._build_pending(first_party, deadline)
        self._pre = {
            "first_party": first_party,
            "storage": await self._snapshot_storage(),
            "service_workers": await self._service_workers(),
        }

    async def finalize(self, budget_s: float = FINALIZE_BUDGET_S) -> dict:
        """Vuelca lo capturado. Debe llamarse con la página aún abierta, o tras prepare_close()."""
        deadline = self._loop.time() + budget_s
        pre = self._pre
        first_party = pre["first_party"] if pre is not None else self._first_party()
        built = [record["built"] for record in await self._build_pending(first_party, deadline)]
        return {
            "requests": built,
            "redirects": self._redirect_chains(built),
            "websockets": self._build_websockets(first_party),
            "cookies": await self._snapshot_cookies(first_party),
            "storage": pre["storage"] if pre is not None else await self._snapshot_storage(),
            "service_workers": pre["service_workers"] if pre is not None else await self._service_workers(),
            "truncated": self.truncated,
            "first_party_domains": sorted(first_party),
        }
