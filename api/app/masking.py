"""Enmascarado de identificadores en los reportes exportados (F8).

Por defecto un reporte no reproduce valores que podrían ser identificadores: de cada valor
largo en una URL se deja un prefijo y el largo. Mostrar los valores completos es una opción
explícita de quien exporta.
"""

import copy
import re
from urllib.parse import urlsplit, urlunsplit

PREFIX = 4
MIN_LENGTH = 9


def mask_value(value: str) -> str:
    if not isinstance(value, str) or len(value) < MIN_LENGTH:
        return value
    return f"{value[:PREFIX]}…[{len(value)} caracteres]"


UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
DIGITS = re.compile(r"^\d{9,}$")
TOKEN = re.compile(r"^[A-Za-z0-9_\-=~+%]{20,}$")
EXTENSION = re.compile(r"^(.+)(\.[A-Za-z][A-Za-z0-9]{1,5})$")
WORD = re.compile(r"[A-Z]?[a-z]{3,}")
WORDY = 0.7
EMAIL = re.compile(r"^[^@/\s]+(@|%40)[^@/\s]+\.[A-Za-z]{2,}$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'«»,)]+")


def looks_like_id(segment: str) -> bool:
    """¿Este trozo de ruta tiene forma de identificador? Heurística sobre la FORMA, no el significado.

    Sí: UUID, hexadecimal de 16 o más, número de 9 o más cifras, correo electrónico, o un token de 20 o más
    caracteres con al menos 4 dígitos o mezcla de mayúsculas y minúsculas que no esté hecho
    de palabras. No: un slug legible ("oferta-de-verano-2026-10-07") o un nombre en
    CamelCase. Un token largo solo en minúsculas y sin dígitos no se distingue de una palabra.
    """
    if UUID.match(segment) or HEX.match(segment) or DIGITS.match(segment) or EMAIL.match(segment):
        return True
    if not TOKEN.match(segment):
        return False
    letters = sum(ch.isalpha() for ch in segment)
    digits = sum(ch.isdigit() for ch in segment)
    mixed_case = any(ch.isupper() for ch in segment) and any(ch.islower() for ch in segment)
    if digits < 4 and not mixed_case:
        return False
    in_words = sum(len(word) for word in WORD.findall(segment))
    return letters == 0 or in_words / letters < WORDY


def mask_segment(segment: str) -> str:
    """Enmascara un segmento de ruta si tiene forma de ID; conserva la extensión del archivo."""
    if len(segment) < MIN_LENGTH:
        return segment
    if EMAIL.match(segment):
        return mask_value(segment)
    match = EXTENSION.match(segment)
    stem, extension = (match.group(1), match.group(2)) if match else (segment, "")
    # "<id>", "<id>.js" o "app.<hash>.js": basta con que una parte separada por puntos lo sea.
    if looks_like_id(stem) or any(looks_like_id(part) for part in re.split(r"[.@:;!]", stem)):
        return mask_value(stem) + extension
    if looks_like_id(segment):
        return mask_value(segment)
    return segment


def mask_path(path: str) -> str:
    return "/".join(mask_segment(segment) for segment in path.split("/"))


def mask_url(url: object) -> object:
    """Enmascara los valores de la query, el fragmento y los segmentos de ruta con forma de ID.

    El host se conserva siempre. También acepta "host/ruta" sin esquema.
    """
    if not isinstance(url, str) or not url:
        return url
    if not SCHEME.match(url):
        if "://" in url:
            # Texto que cita una URL, p. ej. "(inline o eval en https://sitio/ruta)".
            return mask_text(url)
        head, separator, tail = url.partition("/")
        return head + separator + _mask_tail(tail) if separator else url
    try:
        parts = urlsplit(url)
    except ValueError:
        return mask_value(url)
    if not parts.query and not parts.fragment:
        return urlunsplit((parts.scheme, parts.netloc, mask_path(parts.path), "", ""))
    pairs = []
    for pair in parts.query.split("&") if parts.query else []:
        name, separator, value = pair.partition("=")
        pairs.append(f"{name}={mask_value(value)}" if separator else mask_value(name))
    return urlunsplit((parts.scheme, parts.netloc, mask_path(parts.path), "&".join(pairs), mask_value(parts.fragment) if parts.fragment else ""))


def _mask_tail(tail: str) -> str:
    """Ruta (y query, si la hay) de un recurso escrito sin esquema."""
    path, separator, query = tail.partition("?")
    if not separator:
        return mask_path(path)
    pairs = []
    for pair in query.split("&"):
        name, equals, value = pair.partition("=")
        pairs.append(f"{name}={mask_value(value)}" if equals else mask_value(name))
    return mask_path(path) + "?" + "&".join(pairs)


def mask_text(text: object) -> object:
    """Enmascara las URLs que aparezcan dentro de un texto libre (el claim de un hallazgo)."""
    if not isinstance(text, str) or "://" not in text:
        return text
    return URL_IN_TEXT.sub(lambda match: str(mask_url(match.group(0))), text)


def mask_report(report: dict) -> dict:
    """Copia del reporte con las URLs enmascaradas (query, fragmento y segmentos de ruta con forma de ID).

    Los claims usan vistas parciales de los valores; las URLs que citan se enmascaran igual.
    """
    masked = copy.deepcopy(report)
    for key in ("url", "final_url"):
        masked["scan"][key] = mask_url(masked["scan"].get(key))
    # Captura importada (v1.3): la carga elegida cita la URL de la página.
    load = (masked["scan"].get("import") or {}).get("load")
    if isinstance(load, dict):
        for key in ("page_url", "title"):
            load[key] = mask_url(load.get(key))
    # Captura interactiva (v1.4): las páginas visitadas se enmascaran como cualquier otra URL.
    for entry in (masked["scan"].get("interactive") or {}).get("timeline", []):
        entry["url"] = mask_url(entry.get("url"))
    for group in masked.get("trackers", []):
        for request in group.get("requests", []):
            request["url"] = mask_url(request.get("url"))
    fingerprinting = masked.get("fingerprinting") or {}
    for script in fingerprinting.get("scripts", []):
        script["script_url"] = mask_url(script.get("script_url"))
    for collection in (fingerprinting.get("exfiltrations", []), *(script.get("heuristics", []) for script in fingerprinting.get("scripts", []))):
        for item in collection:
            item["script_url"] = mask_text(mask_url(item.get("script_url")))
            item["claim"] = mask_text(item.get("claim"))
    for script in fingerprinting.get("scripts", []):
        script["script_url"] = mask_text(script["script_url"])
    for finding in masked.get("findings", []):
        finding["claim"] = mask_text(finding.get("claim"))
        if "plain" in finding:
            finding["plain"] = mask_text(finding["plain"])
    # «Hallazgos por grupo» cita los mismos hallazgos: se enmascara igual.
    for step in (masked.get("story") or {}).get("steps", []):
        for item in step.get("items", []):
            item["claim"] = mask_text(item.get("claim"))
            item["plain"] = mask_text(item.get("plain"))
    for attribute in fingerprinting.get("attributes", []):
        attribute["scripts"] = [mask_text(mask_url(script)) for script in attribute.get("scripts", [])]
    masked["masked"] = True
    return masked


def mask_group_report(report: dict) -> dict:
    """Copia del reporte de un Privacy Test con la URL enmascarada.

    Los valores repetidos solo existen como `value_preview` (prefijo + largo) y los recursos
    se listan sin query; de su ruta se enmascaran los segmentos con forma de ID.
    """
    masked = copy.deepcopy(report)
    masked["group"]["url"] = mask_url(masked["group"].get("url"))
    # Recursos "host/ruta" de los hallazgos de consentimiento: la ruta puede llevar un ID.
    for finding in ((masked.get("result") or {}).get("consent") or {}).get("findings", {}).values():
        for item in finding.get("items", []):
            item["resource"] = mask_url(item.get("resource"))
    masked["masked"] = True
    return masked
