"""Parámetros de una request: de dónde salen, cómo se llaman y qué forma tiene su valor.

Solo describe. Que un parámetro se llame `uid` no prueba que identifique a nadie, y
que un valor tenga forma de email no dice de quién es: aquí se detecta la FORMA.
"""

import ipaddress
import math
import re
import string
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from app.analyzer.decoding import decode, iter_leaves

MAX_PARAMS_PER_REQUEST = 150
MAX_NAME_CHARS = 256
MAX_SHAPE_CHARS = 4096
MAX_ENTROPY_CHARS = 1024
MAX_FORM_PAIRS = 200
MAX_COOKIE_PAIRS = 100

_HEX = frozenset(string.hexdigits)
_B64 = frozenset(string.ascii_letters + string.digits + "+/=-_")
_ID_CHARS = frozenset(string.ascii_letters + string.digits + "-_.:~|=+/")
_NAME_SEPARATORS = frozenset("_-.:[]/ ")
# Versión de software con puntos: "153.0.8010.12", "v4.2.1". Igual para todo el que usa ese programa.
_VERSION = re.compile(r"^v?\d{1,5}(\.\d{1,6}){2,4}$")
# 2001-09-09 .. 2040-01-01 en segundos.
_TS_MIN, _TS_MAX = 1_000_000_000, 2_208_988_800


@dataclass
class Param:
    request_id: int
    source: str  # query | post_form | post_body | referer | cookie | set_cookie | <fuente>_decoded
    name: str
    value: str
    encoding_chain: tuple[str, ...] = ()
    category: str | None = None
    shapes: tuple[str, ...] = ()
    length: int = 0
    entropy: float = 0.0
    identifier_like: bool = False


# --- nombre -> categoría ---


def name_tokens(name: str) -> list[str]:
    """Tokens en minúsculas, separando por símbolos y por camelCase."""
    tokens, current = [], ""
    previous_lower = False
    for ch in name[:MAX_NAME_CHARS]:
        if ch in _NAME_SEPARATORS:
            if current:
                tokens.append(current)
            current, previous_lower = "", False
            continue
        if ch.isupper() and previous_lower and current:
            tokens.append(current)
            current = ""
        current += ch.lower()
        previous_lower = ch.islower() or ch.isdigit()
    if current:
        tokens.append(current)
    return tokens


class NameCategories:
    def __init__(self, config: dict) -> None:
        self._exact: dict[str, str] = {}
        self._tokens: dict[str, str] = {}
        for category, spec in config.items():
            for name in spec.get("exact", []):
                self._exact.setdefault(str(name).lower(), category)
            for token in spec.get("tokens", []):
                self._tokens.setdefault(str(token).lower(), category)

    def categorize(self, name: str) -> str | None:
        name = name[:MAX_NAME_CHARS]
        lowered = name.lower()
        # En parámetros derivados ("data.user.id") cuenta el último componente y su padre.
        # Los tokens se sacan del nombre original: en minúsculas se pierde el camelCase.
        components = [part.split("[", 1)[0] for part in name.split(".") if part.split("[", 1)[0]]
        leaf = components[-1].lower() if components else lowered
        tokens = name_tokens(components[-1]) if components else []
        candidates = [lowered, leaf]
        if len(tokens) >= 2:
            candidates += [tokens[-2] + tokens[-1], tokens[-2] + "_" + tokens[-1]]
        if len(components) >= 2:
            parent = name_tokens(components[-2])
            if parent:
                candidates += [parent[-1] + leaf, parent[-1] + "_" + leaf]
        for candidate in candidates:
            if candidate in self._exact:
                return self._exact[candidate]
        for token in tokens:
            if token in self._tokens:
                return self._tokens[token]
        return None


# --- forma del valor ---


def shannon_entropy(value: str) -> float:
    sample = value[:MAX_ENTROPY_CHARS]
    if not sample:
        return 0.0
    total = len(sample)
    return round(-sum(n / total * math.log2(n / total) for n in Counter(sample).values()), 3)


def _is_uuid(value: str) -> bool:
    if len(value) != 36 or [value[i] for i in (8, 13, 18, 23)] != ["-"] * 4:
        return False
    return all(ch in _HEX for ch in value.replace("-", ""))


def _is_email(value: str) -> bool:
    if not 6 <= len(value) <= 254 or value.count("@") != 1 or any(ch.isspace() for ch in value):
        return False
    local, domain = value.split("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _is_timestamp(value: str) -> bool:
    if not value.isascii() or not value.isdigit() or len(value) not in (10, 13):
        return False
    seconds = int(value) // (1000 if len(value) == 13 else 1)
    return _TS_MIN <= seconds <= _TS_MAX


def _is_ip(value: str) -> bool:
    if not 7 <= len(value) <= 45 or ("." not in value and ":" not in value):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def value_shapes(value: str) -> tuple[str, ...]:
    """Formas reconocibles del valor. Varias pueden coincidir (un UUID también es id-like)."""
    sample = value[:MAX_SHAPE_CHARS]
    shapes = []
    if not sample:
        return ("empty",)
    if _is_uuid(sample):
        shapes.append("uuid")
    if _is_timestamp(sample):
        shapes.append("timestamp")
    elif sample.isascii() and sample.isdigit():
        shapes.append("numeric")
    if len(sample) >= 16 and len(sample) % 2 == 0 and all(ch in _HEX for ch in sample):
        shapes.append("hex")
    if sample.startswith("eyJ") and sample.count(".") == 2:
        shapes.append("jwt")
    elif len(sample) >= 16 and "hex" not in shapes and all(ch in _B64 for ch in sample):
        if any(ch.isdigit() for ch in sample) and any(ch.isalpha() for ch in sample):
            shapes.append("base64")
    if _is_ip(sample):
        shapes.append("ip")
    if _VERSION.match(sample):
        shapes.append("version")
    lowered = sample[:12].lower()
    if lowered.startswith(("http://", "https://", "http%3a", "https%3a", "//")):
        shapes.append("url")
    if _is_email(sample) or _is_email(unquote(sample)):
        shapes.append("email")
    return tuple(shapes)


def is_identifier_like(value: str, shapes: tuple[str, ...], entropy: float) -> bool:
    """¿Tiene forma de identificador opaco? (largo, sin espacios, variado). No dice de quién."""
    if not 8 <= len(value) <= 512:
        return False
    # Una versión de software no distingue a un visitante: la comparten todos los que usan ese programa.
    if any(shape in shapes for shape in ("url", "timestamp", "ip", "email", "version")):
        return False
    if "uuid" in shapes or "hex" in shapes or "jwt" in shapes:
        return True
    if not all(ch in _ID_CHARS for ch in value):
        return False
    return entropy >= 2.5 and any(ch.isdigit() for ch in value)


def describe(param: Param, names: NameCategories) -> Param:
    param.category = names.categorize(param.name)
    param.shapes = value_shapes(param.value)
    param.length = len(param.value)
    param.entropy = shannon_entropy(param.value)
    param.identifier_like = is_identifier_like(param.value, param.shapes, param.entropy)
    return param


# --- extracción ---


def _header(headers: list | None, name: str) -> list[str]:
    return [
        h["value"]
        for h in (headers if isinstance(headers, list) else [])
        if isinstance(h, dict) and isinstance(h.get("value"), str) and str(h.get("name", "")).lower() == name
    ]


def _join(*parts: str) -> str:
    return ".".join(part for part in parts if part)[:MAX_NAME_CHARS]


def extract(request: dict, names: NameCategories) -> tuple[list[Param], list[dict]]:
    """Parámetros de una request y las decodificaciones de sus valores.

    Además de los parámetros tal como viajan, devuelve los *derivados*: las hojas de
    lo que se pudo decodificar (fuente `<origen>_decoded`, con su encoding_chain).
    """
    request_id = request["request_id"]
    params: list[Param] = []
    decoded_rows: list[dict] = []

    def add(source: str, name: str, value: str, chain: tuple[str, ...] = ()) -> None:
        if len(params) < MAX_PARAMS_PER_REQUEST:
            params.append(describe(Param(request_id, source, name[:MAX_NAME_CHARS], value, chain), names))

    def add_with_decoding(source: str, name: str, value: str, *, keep_raw: bool = True) -> None:
        if keep_raw:
            add(source, name, value)
        for item in decode(value):
            decoded_rows.append(
                {
                    "request_id": request_id,
                    "source": source,
                    "name": name[:MAX_NAME_CHARS],
                    "path": item.path,
                    "raw_value": item.raw_value,
                    "decoded_value": item.decoded_value,
                    "decoded_truncated": item.truncated,
                    "encoding_chain": list(item.encoding_chain),
                    "confidence": item.confidence,
                }
            )
            if item.structure is None:
                add(f"{source}_decoded", _join(name, item.path), item.decoded_value, item.encoding_chain)
            else:
                for leaf_path, leaf in iter_leaves(item.structure):
                    leaf_value = leaf if isinstance(leaf, str) else str(leaf)
                    add(f"{source}_decoded", _join(name, item.path, leaf_path), leaf_value, item.encoding_chain)

    for pair in request.get("query_params") or []:
        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str):
            add_with_decoding("query", unquote(pair[0], errors="replace"), pair[1] if isinstance(pair[1], str) else "")

    body = request.get("post_data")
    if isinstance(body, dict) and body.get("encoding") == "utf8" and isinstance(body.get("data"), str):
        data = body["data"]
        content_type = " ".join(_header(request.get("request_headers"), "content-type")).lower()
        if "application/x-www-form-urlencoded" in content_type:
            for pair in data.split("&")[:MAX_FORM_PAIRS]:
                name, _, value = pair.partition("=")
                if name:
                    add_with_decoding(
                        "post_form", unquote_plus(name, errors="replace"), unquote_plus(value, errors="replace")
                    )
        else:
            # JSON, Base64, texto...: el cuerpo entero es un solo valor que se intenta decodificar.
            add_with_decoding("post_body", "", data, keep_raw=False)

    # Referer hacia terceros: una fuente más de fuga de navegación (lo que efectivamente se envió).
    if request.get("third_party"):
        for header in _header(request.get("request_headers"), "referer")[:1]:
            add("referer", "referer", header)

    for header in _header(request.get("request_headers"), "cookie"):
        for pair in header.split(";")[:MAX_COOKIE_PAIRS]:
            name, separator, value = pair.strip().partition("=")
            if separator and name:
                add("cookie", name, value)
    for header in _header(request.get("response_headers"), "set-cookie"):
        name, separator, value = header.split(";", 1)[0].strip().partition("=")
        if separator and name:
            add("set_cookie", name, value)
    return params, decoded_rows
