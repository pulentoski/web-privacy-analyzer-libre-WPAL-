"""Decodificación recursiva de valores (URL, Base64, hex, JSON, JWT, query, gzip).

Los valores vienen del sitio analizado y son hostiles por definición:
- sin expresiones regulares (nada que pueda hacer backtracking),
- entrada, salida, profundidad y número de resultados acotados,
- nunca se ejecuta ni se evalúa nada; solo se transforma texto,
- el valor original nunca se modifica: cada resultado lo lleva intacto en raw_value.
"""

import base64
import binascii
import json
import string
import zlib
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

MAX_INPUT_CHARS = 65536
MAX_OUTPUT_CHARS = 16384
MAX_DEPTH = 3
MAX_RESULTS = 40
MAX_LEAVES = 200
MAX_STRUCTURE_DEPTH = 8
MAX_QUERY_PAIRS = 100
MIN_INPUT_CHARS = 4

_B64_STD = frozenset(string.ascii_letters + string.digits + "+/")
_B64_URL = frozenset(string.ascii_letters + string.digits + "-_")
_HEX = frozenset(string.hexdigits)
_QUERY_KEY = frozenset(string.ascii_letters + string.digits + "_.-[]%")
_TEXT_CONTROL = frozenset("\n\r\t")


class QueryPairs(list):
    """Lista de [nombre, valor] de un query anidado (distinta de una lista JSON cualquiera)."""


@dataclass(frozen=True)
class Decoded:
    raw_value: str  # el valor original completo, intacto
    decoded_value: str  # texto resultante (estructuras serializadas como JSON), acotado
    encoding_chain: tuple[str, ...]  # p. ej. ("base64", "json")
    confidence: float  # 0..1: qué tan probable es que la codificación sea intencional
    path: str = ""  # ubicación dentro de la estructura decodificada anterior
    truncated: bool = False
    structure: object = field(default=None, compare=False, repr=False)  # dict/list/QueryPairs o None


def _is_text(value: str) -> bool:
    if not value:
        return False
    bad = sum(1 for ch in value if not (ch.isprintable() or ch in _TEXT_CONTROL))
    return bad * 20 <= len(value)  # >= 95 % imprimible


def _b64_bytes(value: str) -> bytes | None:
    body = value.rstrip("=")
    if len(value) - len(body) > 2 or len(body) < 8 or len(body) % 4 == 1:
        return None
    if all(ch in _B64_STD for ch in body):
        altchars = None
    elif all(ch in _B64_URL for ch in body):
        altchars = b"-_"
    else:
        return None
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None


def _gunzip(data: bytes) -> bytes | None:
    """Descomprime como mucho MAX_OUTPUT_CHARS * 4 bytes: una bomba gzip no pasa de ahí."""
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_OUTPUT_CHARS * 4)
    except zlib.error:
        return None


def _try_jwt(value: str):
    if not value.startswith("eyJ") or value.count(".") != 2:
        return None
    header_b64, payload_b64, _signature = value.split(".")
    parts = []
    for segment in (header_b64, payload_b64):
        data = _b64_bytes(segment) if len(segment) >= 8 else None
        if data is None:
            return None
        try:
            parsed = json.loads(data)
        except (ValueError, RecursionError):
            return None
        if not isinstance(parsed, dict):
            return None
        parts.append(parsed)
    if "alg" not in parts[0] and "typ" not in parts[0]:
        return None
    # La firma NO se verifica: solo se lee lo que el token dice transportar.
    return ("jwt",), {"header": parts[0], "payload": parts[1]}, 0.95


def _try_json(value: str):
    stripped = value.strip()
    if stripped[:1] not in "{[" or stripped[-1:] not in "}]":
        return None
    try:
        parsed = json.loads(stripped)
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, (dict, list)) or not parsed:
        return None
    return ("json",), parsed, 0.95


def _try_url(value: str):
    if "%" not in value:
        return None
    decoded = unquote(value, errors="replace")
    if decoded == value:
        return None
    return ("url",), decoded, 0.9


def _try_hex(value: str):
    if len(value) < 8 or len(value) % 2 or not all(ch in _HEX for ch in value):
        return None
    if value.isdigit():
        return None  # un número (un id, una fecha) no es texto en hexadecimal
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except ValueError:
        return None
    # Un hash o un id en hex casi nunca decodifica a texto: si lo hace, era texto.
    return (("hex",), decoded, 0.6) if _is_text(decoded) and "\x00" not in decoded else None


def _try_base64(value: str):
    data = _b64_bytes(value)
    if data is None:
        return None
    chain = ("base64",)
    if data[:2] == b"\x1f\x8b":
        data = _gunzip(data)
        if data is None:
            return None
        chain = ("base64", "gzip")
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _is_text(decoded) or "\x00" in decoded:
        return None
    # Texto estructurado (JSON, query) => casi seguro intencional. Texto corto cualquiera
    # también puede salir por azar de una cadena alfanumérica.
    structured = decoded.lstrip()[:1] in "{[" or "=" in decoded or len(chain) > 1
    return chain, decoded, 0.9 if structured else 0.5


def _try_query(value: str):
    if "=" not in value or len(value) > 8192 or any(ch in "\n\r\t" for ch in value):
        return None
    pairs = value.split("&")
    # Un query ya URL-decodificado puede traer espacios en los valores («q=cartas pokemon&p=1»);
    # con un solo par y espacios es texto corriente («a = b»), no un query.
    if len(pairs) > MAX_QUERY_PAIRS or (len(pairs) < 2 and " " in value):
        return None
    out = QueryPairs()
    for pair in pairs:
        key, separator, item = pair.partition("=")
        if not separator or not 1 <= len(key) <= 64 or not all(ch in _QUERY_KEY for ch in key):
            return None
        out.append([unquote_plus(key, errors="replace"), unquote_plus(item, errors="replace")])
    # Un solo par cuyo valor es vacío o solo "=" es relleno de Base64 ("abc=", "abc=="), no un query.
    if len(out) == 1 and not out[0][1].strip("="):
        return None
    return ("query",), out, 0.6 if len(out) > 1 else 0.4


_DECODERS = (_try_jwt, _try_json, _try_url, _try_hex, _try_base64, _try_query)


def iter_leaves(structure):
    """(ruta, valor escalar) de una estructura decodificada, con profundidad y cantidad acotadas."""
    if isinstance(structure, QueryPairs):
        for name, value in structure[:MAX_LEAVES]:
            yield name, value
        return
    stack = [("", structure, 0)]
    emitted = 0
    while stack and emitted < MAX_LEAVES:
        path, node, depth = stack.pop()
        if isinstance(node, dict):
            if depth < MAX_STRUCTURE_DEPTH:
                for key in reversed(list(node)[:MAX_LEAVES]):
                    stack.append((f"{path}.{key}" if path else str(key), node[key], depth + 1))
        elif isinstance(node, list):
            if depth < MAX_STRUCTURE_DEPTH:
                for index in reversed(range(min(len(node), MAX_LEAVES))):
                    stack.append((f"{path}[{index}]", node[index], depth + 1))
        elif node is not None:
            emitted += 1
            yield path, node


def _serialize(decoded) -> tuple[str, bool]:
    if isinstance(decoded, str):
        out = decoded
    else:
        try:
            out = json.dumps(decoded, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            out = ""
    return out[:MAX_OUTPUT_CHARS], len(out) > MAX_OUTPUT_CHARS


def _join(base: str, path: str) -> str:
    return f"{base}.{path}" if base and path else base or path


def decode(raw: object) -> list[Decoded]:
    """Todas las decodificaciones encontradas en `raw`, de la más externa a la más interna.

    Nunca lanza: una entrada que no se puede decodificar simplemente no produce resultados.
    """
    if not isinstance(raw, str) or not MIN_INPUT_CHARS <= len(raw) <= MAX_INPUT_CHARS:
        return []
    results: list[Decoded] = []
    # (valor, cadena acumulada, ruta, confianza acumulada)
    pending = [(raw, (), "", 1.0)]
    while pending and len(results) < MAX_RESULTS:
        value, chain, path, confidence = pending.pop(0)
        if len(chain) >= MAX_DEPTH or not MIN_INPUT_CHARS <= len(value) <= MAX_INPUT_CHARS:
            continue
        step = None
        for decoder in _DECODERS:
            try:
                step = decoder(value)
            except Exception:  # un decodificador nunca debe tumbar el análisis
                step = None
            if step is not None:
                break
        if step is None:
            continue
        encodings, decoded, step_confidence = step
        new_chain = (chain + encodings)[: MAX_DEPTH + 1]
        text, truncated = _serialize(decoded)
        if not text:
            continue
        new_confidence = round(confidence * step_confidence, 3)
        results.append(
            Decoded(
                raw_value=raw,
                decoded_value=text,
                encoding_chain=new_chain,
                confidence=new_confidence,
                path=path,
                truncated=truncated,
                structure=None if isinstance(decoded, str) else decoded,
            )
        )
        if isinstance(decoded, str):
            pending.append((decoded, new_chain, path, new_confidence))
        else:
            for leaf_path, leaf in iter_leaves(decoded):
                if isinstance(leaf, str) and len(leaf) >= MIN_INPUT_CHARS:
                    pending.append((leaf, new_chain, _join(path, leaf_path), new_confidence))
    return results
