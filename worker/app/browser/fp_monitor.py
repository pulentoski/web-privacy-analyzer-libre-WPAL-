"""Recibe en el worker los eventos de la instrumentación de fingerprinting (F4).

El canal es un binding de Playwright con nombre aleatorio por scan. El init script
(fp_instrument.js) se queda con la función nativa en un closure y borra del global
todo rastro del binding, así que la página no debería poder llamarlo. Aun así, cada
mensaje se trata como dato NO confiable: token secreto, esquema estricto, tamaños
acotados, rate limit y un catálogo cerrado de nombres de API.
"""

import hmac
import json
import logging
import pathlib
import secrets
import time

logger = logging.getLogger(__name__)

SCRIPT_PATH = pathlib.Path(__file__).with_name("fp_instrument.js")

# Catálogo cerrado: cualquier otro nombre de API se rechaza.
KNOWN_APIS = frozenset(
    {
        "canvas.toDataURL", "canvas.toBlob", "canvas.getImageData", "canvas.fillText", "canvas.strokeText",
        "canvas.measureText",
        "webgl.getParameter", "webgl.UNMASKED_VENDOR_WEBGL", "webgl.UNMASKED_RENDERER_WEBGL", "webgl.getExtension",
        "webgl.getExtension.debug_renderer_info", "webgl.getSupportedExtensions", "webgl.readPixels",
        "audio.OfflineAudioContext", "audio.createOscillator", "audio.createDynamicsCompressor",
        "audio.startRendering", "audio.getChannelData", "audio.getFloatFrequencyData",
        "webrtc.RTCPeerConnection", "webrtc.createDataChannel", "webrtc.createOffer", "webrtc.onicecandidate",
        "navigator.userAgent", "navigator.platform", "navigator.hardwareConcurrency", "navigator.deviceMemory",
        "navigator.languages", "navigator.plugins", "navigator.mimeTypes", "navigator.webdriver",
        "navigator.maxTouchPoints", "navigator.userAgentData.getHighEntropyValues",
        "screen.width", "screen.height", "screen.availWidth", "screen.availHeight", "screen.colorDepth",
        "screen.pixelDepth", "window.devicePixelRatio", "window.matchMedia", "intl.timeZone",
        "fonts.check", "mediaDevices.enumerateDevices", "navigator.getBattery", "permissions.query",
        "gpu.requestAdapter", "speechSynthesis.getVoices", "storage.estimate",
        # v1.4.2: escucha de eventos de interacción (addEventListener / onX). Solo el tipo de evento y el script.
        "events.click", "events.mousemove", "events.scroll", "events.keydown", "events.input", "events.touch",
        "events.visibilitychange",
    }
)

# Límites en la página (se inyectan en el init script).
PAGE_MAX_KEYS = 400  # pares (api, script) distintos por frame
PAGE_MAX_DETAILS = 60  # lecturas de canvas/audio detalladas por frame
PAGE_MAX_HASHES = 12
PAGE_MAX_HASH_BYTES = 2_000_000
PAGE_FLUSH_MS = 500

# Límites en el worker (por scan).
MAX_MESSAGE_CHARS = 131072
MAX_MESSAGES = 3000
MAX_ROWS = 2000  # (api, script, frame) distintos
MAX_READS_PER_ROW = 5
MAX_COUNT_DELTA = 1_000_000
MAX_URL_CHARS = 2048
MAX_VALUE_CHARS = 256
RATE_BURST = 40
RATE_PER_SECOND = 10.0
HEX = frozenset("0123456789abcdef")


class InvalidEvent(ValueError):
    pass


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise InvalidEvent("texto inválido")
    return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


def _api(value: object) -> str:
    if not isinstance(value, str) or value not in KNOWN_APIS:
        raise InvalidEvent("api desconocida")
    return value


def _int(value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise InvalidEvent("entero fuera de rango")
    return value


def _list(value: object, limit: int) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise InvalidEvent("lista inválida")
    return value


def _hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= HEX:
        raise InvalidEvent("hash inválido")
    return value


def parse_message(message: dict) -> dict:
    """Valida un lote completo. Si algo no cumple, se descarta entero (InvalidEvent)."""
    allowed = {"t", "c", "f", "v", "d", "x", "a"}
    if not isinstance(message, dict) or not set(message) <= allowed:
        raise InvalidEvent("forma inválida")
    out = {"counts": [], "fonts": [], "values": [], "reads": [], "truncated": message.get("x") is True, "available": None}
    for item in _list(message.get("c", []), PAGE_MAX_KEYS):
        api, script, count = _list(item, 3) if len(item) == 3 else (None, None, None)
        out["counts"].append((_api(api), _text(script, MAX_URL_CHARS), _int(count, 1, MAX_COUNT_DELTA)))
    for item in _list(message.get("f", []), 50):
        script, distinct = _list(item, 2) if len(item) == 2 else (None, None)
        out["fonts"].append((_text(script, MAX_URL_CHARS), _int(distinct, 0, 500)))
    for item in _list(message.get("v", []), PAGE_MAX_KEYS):
        api, script, value = _list(item, 3) if len(item) == 3 else (None, None, None)
        out["values"].append((_api(api), _text(script, MAX_URL_CHARS), _text(value, MAX_VALUE_CHARS)))
    for item in _list(message.get("d", []), PAGE_MAX_DETAILS):
        if not isinstance(item, dict):
            raise InvalidEvent("detalle inválido")
        kind = item.get("k")
        length = item.get("l")
        read = {
            "api": _api(item.get("a")),
            "script_url": _text(item.get("s"), MAX_URL_CHARS),
            "sha256": _hash(item.get("h")),
            "length": None if length is None else _int(length, 0, 2**31),
        }
        if kind == "canvas" and set(item) == {"k", "a", "s", "cw", "ch", "rw", "rh", "tx", "nc", "h", "l"}:
            if not isinstance(item["tx"], bool):
                raise InvalidEvent("detalle inválido")
            read.update(
                kind="canvas",
                canvas_width=_int(item["cw"], 0, 65535), canvas_height=_int(item["ch"], 0, 65535),
                read_width=_int(item["rw"], -65535, 65535), read_height=_int(item["rh"], -65535, 65535),
                text_written=item["tx"], colors=_int(item["nc"], 0, 8),
            )
        elif kind == "audio" and set(item) == {"k", "a", "s", "h", "l"}:
            read["kind"] = "audio"
        else:
            raise InvalidEvent("detalle inválido")
        out["reads"].append(read)
    if "a" in message:
        # WebGL y WebGL2 comparten nombres: la lista puede traer repetidos.
        out["available"] = sorted({_api(api) for api in _list(message["a"], 4 * len(KNOWN_APIS))})
    return out


class FingerprintMonitor:
    def __init__(self, context) -> None:
        self._context = context
        # Nombre con forma de identificador cualquiera: no delata qué es.
        self._name = "_" + secrets.token_hex(12)
        self._token = secrets.token_hex(24)
        self._rows: dict[tuple[str, str, str], dict] = {}
        self._available: set[str] = set()
        self._messages = 0
        self._rejected = 0
        self._truncated = False
        self._tokens = float(RATE_BURST)
        self._last = time.monotonic()

    async def install(self) -> None:
        """Debe llamarse antes de crear la página: binding primero, init script después."""
        config = {
            "b": self._name, "t": self._token, "maxKeys": PAGE_MAX_KEYS, "maxDetails": PAGE_MAX_DETAILS,
            "maxHashes": PAGE_MAX_HASHES, "maxHashBytes": PAGE_MAX_HASH_BYTES, "flushMs": PAGE_FLUSH_MS,
        }
        source = SCRIPT_PATH.read_text(encoding="utf-8").replace("__WPA_CONFIG__", json.dumps(config))
        await self._context.expose_binding(self._name, self._on_message)
        await self._context.add_init_script(script=source)

    def _reject(self, reason: str) -> None:
        self._rejected += 1
        if self._rejected <= 5:
            logger.warning("fp_event_rejected", extra={"reason": reason})

    def _allow(self) -> bool:
        now = time.monotonic()
        self._tokens = min(RATE_BURST, self._tokens + (now - self._last) * RATE_PER_SECOND)
        self._last = now
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True

    def _row(self, api: str, script_url: str, frame_url: str) -> dict | None:
        key = (api, script_url, frame_url)
        row = self._rows.get(key)
        if row is None:
            if len(self._rows) >= MAX_ROWS:
                self._truncated = True
                return None
            row = self._rows[key] = {"api": api, "script_url": script_url, "frame_url": frame_url, "count": 0, "details": {}}
        return row

    def _on_message(self, source, *args) -> None:
        # Nada de lo que llega aquí es confiable, tampoco la cantidad de argumentos.
        if len(args) != 1 or not isinstance(args[0], str) or len(args[0]) > MAX_MESSAGE_CHARS:
            return self._reject("shape")
        if self._messages >= MAX_MESSAGES or not self._allow():
            self._truncated = True
            return self._reject("rate_limit")
        try:
            message = json.loads(args[0])
        except (ValueError, RecursionError):
            return self._reject("json")
        token = message.pop("t", None) if isinstance(message, dict) else None
        if not isinstance(token, str) or not hmac.compare_digest(token, self._token):
            return self._reject("token")
        try:
            event = parse_message(message)
        except InvalidEvent as exc:
            return self._reject(str(exc))
        self._messages += 1
        try:
            frame_url = (source["frame"].url or "")[:MAX_URL_CHARS]
        except Exception:
            frame_url = ""
        self._truncated = self._truncated or event["truncated"]
        if event["available"] is not None:
            self._available.update(event["available"])
        for api, script_url, count in event["counts"]:
            row = self._row(api, script_url, frame_url)
            if row is not None:
                row["count"] = min(row["count"] + count, 2**31 - 1)
        for api, script_url, value in event["values"]:
            row = self._row(api, script_url, frame_url)
            if row is not None:
                row["details"].setdefault("value", value)
        for script_url, distinct in event["fonts"]:
            row = self._row("canvas.measureText", script_url, frame_url)
            if row is not None:
                row["details"]["distinct_fonts"] = max(row["details"].get("distinct_fonts", 0), distinct)
        for read in event["reads"]:
            row = self._row(read.pop("api"), read.pop("script_url"), frame_url)
            if row is not None:
                reads = row["details"].setdefault("reads", [])
                if len(reads) < MAX_READS_PER_ROW:
                    reads.append(read)

    def result(self) -> dict:
        return {
            "calls": [row for row in self._rows.values() if row["count"] > 0 or row["details"]],
            "available": sorted(self._available),
            "truncated": self._truncated,
            "messages": self._messages,
            "rejected": self._rejected,
        }
