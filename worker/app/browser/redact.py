"""Enmascarado de credenciales en los cuerpos de una captura interactiva (v1.4.1, docs/adr/029).

En una captura interactiva escribe una persona: lo que teclea en un campo de contraseña viaja en
el cuerpo de la request. Antes de guardar, el valor de esos campos se reemplaza por una marca con
su largo; de cada uno solo se registra el nombre y el largo. Se enmascaran:
  - los campos que en la página eran `<input type="password">` (su nombre lo informa la sesión);
  - los parámetros o claves llamados password, passwd, pass, pwd, secret, token, otp, pin o cvv,
    solos o como parte de un nombre compuesto (new_password, accessToken, user[pin]).
Formatos: formulario urlencoded, JSON (a cualquier profundidad) y multipart. Un cuerpo que no se
reconoce no se toca. No cubre la query de la URL ni los frames de WebSocket.
"""

import json
import re
from urllib.parse import quote, unquote_plus

SENSITIVE = frozenset({"password", "passwd", "pass", "pwd", "secret", "token", "otp", "pin", "cvv"})
MAX_NAME_CHARS = 128
MAX_JSON_DEPTH = 12
_SEGMENTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_MULTIPART = re.compile(
    rb'(Content-Disposition:\s*form-data;\s*name="([^"\r\n]{1,256})"(?!;\s*filename)[^\r\n]*\r\n(?:[^\r\n]+\r\n)*\r\n)(.*?)(?=\r\n--)',
    re.IGNORECASE | re.DOTALL,
)
_JSON_PAIR = re.compile(r'("((?:[^"\\]|\\.){1,128})"\s*:\s*)"((?:[^"\\]|\\.)*)"')


def mark(length: int) -> str:
    return f"[enmascarado:{length}]"


def is_sensitive(name: object, field_names: frozenset | set = frozenset()) -> bool:
    if not isinstance(name, str) or not name:
        return False
    if name in field_names or name.lower() in SENSITIVE:
        return True
    return any(segment.lower() in SENSITIVE for segment in _SEGMENTS.findall(name))


def _form(text: str, names, found: list) -> str:
    out = []
    for pair in text.split("&"):
        key, separator, value = pair.partition("=")
        name = unquote_plus(key)
        if separator and value and is_sensitive(name, names):
            length = len(unquote_plus(value))
            found.append({"name": name[:MAX_NAME_CHARS], "length": length})
            value = quote(mark(length), safe="")
        out.append(key + separator + value)
    return "&".join(out)


def _walk(node, names, found: list, depth: int = 0):
    if depth > MAX_JSON_DEPTH:
        return node
    if isinstance(node, list):
        return [_walk(item, names, found, depth + 1) for item in node]
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        if is_sensitive(key, names) and isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value) != "":
            found.append({"name": key[:MAX_NAME_CHARS], "length": len(str(value))})
            out[key] = mark(len(str(value)))
        else:
            out[key] = _walk(value, names, found, depth + 1)
    return out


def _json(text: str, names, found: list) -> str:
    try:
        parsed = json.loads(text)
    except ValueError:
        # JSON cortado o inválido: se enmascaran los pares "clave": "valor" reconocibles.
        def replace(match):
            name = match.group(2)
            if not is_sensitive(name, names) or not match.group(3):
                return match.group(0)
            found.append({"name": name[:MAX_NAME_CHARS], "length": len(match.group(3))})
            return f'{match.group(1)}"{mark(len(match.group(3)))}"'

        return _JSON_PAIR.sub(replace, text)
    before = len(found)
    walked = _walk(parsed, names, found)
    return json.dumps(walked, ensure_ascii=False, separators=(",", ":")) if len(found) > before else text


def _multipart(body: bytes, names, found: list) -> bytes:
    def replace(match):
        name = match.group(2).decode("utf-8", "replace")
        if not is_sensitive(name, names) or not match.group(3):
            return match.group(0)
        length = len(match.group(3).decode("utf-8", "replace"))
        found.append({"name": name[:MAX_NAME_CHARS], "length": length})
        return match.group(1) + mark(length).encode()

    return _MULTIPART.sub(replace, body)


def redact_body(body: bytes | str | None, content_type: str | None, field_names=frozenset()) -> tuple[bytes | str | None, list[dict]]:
    """(cuerpo enmascarado, [{name, length}]). Devuelve el mismo objeto si no hubo nada que enmascarar."""
    if not body:
        return body, []
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    kind = (content_type or "").split(";")[0].strip().lower()
    found: list[dict] = []
    if kind == "multipart/form-data" or (not kind and raw.startswith(b"--") and b"Content-Disposition" in raw[:2048]):
        out = _multipart(raw, field_names, found)
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return body, []
        stripped = text.lstrip()
        if kind.endswith("json") or stripped[:1] in ("{", "["):
            out = _json(text, field_names, found).encode("utf-8")
        elif kind == "application/x-www-form-urlencoded" or (kind in ("", "text/plain") and "=" in text and "\n" not in text.strip() and " " not in text.strip()):
            out = _form(text, field_names, found).encode("utf-8")
        else:
            return body, []
    return (out, found) if found else (body, [])
