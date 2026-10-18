"""Linker de Google (_gl) en URLs de navegación y redirección (v1.4.10, docs/adr/037).

Tres cosas distintas, que no se mezclan:
  presencia   el parámetro _gl apareció en una URL de navegación o de redirección capturada (EVIDENCIA);
  campos      los pares nombre/valor que se pudieron decodificar del formato reconocido, con el valor enmascarado. Solo
              se informa lo que se extrajo: no se supone que el valor lleve _ga o _gcl_au;
  conclusión  la transferencia del parámetro en esa URL. No se afirma que el destino reconociera al visitante ni que se
              completara una atribución: eso ocurre (o no) en el servidor de destino y no se observa.

El valor viene del sitio: no confiable. Se acota el largo, los nombres de campo deben tener un alfabeto cerrado y un valor
decodificado se acepta solo si es texto imprimible. El hash del formato no se verifica (depende del navegador y de la hora).
"""

import base64
import binascii
import re
from urllib.parse import parse_qsl, urlsplit

PARAM = "_gl"
MAX_VALUE_CHARS = 2048
MAX_FIELDS = 12
MAX_ITEMS = 40
MAX_CHAIN = 10
MAX_EVIDENCE = 5
FORMAT_V1 = "linker_v1"
UNRECOGNIZED = "no_reconocido"
# Mismo criterio que el enmascarado de los reportes (api/app/masking.py): prefijo de 4 y el largo.
MASK_PREFIX = 4
MASK_MIN_LENGTH = 9
_HASH = re.compile(r"^[0-9A-Za-z]{1,16}$")
_KEY = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_B64 = re.compile(r"^[A-Za-z0-9+/_\-]+\.{0,2}$")


def mask(value: str) -> str:
    return value if len(value) < MASK_MIN_LENGTH else f"{value[:MASK_PREFIX]}…[{len(value)} caracteres]"


def strip_url(url: str | None) -> str | None:
    """Origen y ruta, sin query ni fragmento (donde viajan _gl y otros identificadores)."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    return f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.scheme in ("http", "https") and parts.netloc else None


def host_of(url: str | None) -> str | None:
    try:
        return (urlsplit(url or "").hostname or "").lower() or None
    except ValueError:
        return None


def gl_value(url: str | None) -> str | None:
    """Valor de _gl en la query o en el fragmento de la URL; None si no está."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    for part in (parts.query, parts.fragment):
        for name, value in parse_qsl(part, keep_blank_values=True):
            if name == PARAM:
                return value
    return None


def _b64(raw: str) -> str | None:
    """Valor de un campo del linker (base64 con «.» como relleno); None si no decodifica a texto imprimible."""
    if not _B64.match(raw):
        return None
    text = raw.rstrip(".").replace("-", "+").replace("_", "/")
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("ascii")
    except (binascii.Error, ValueError):
        return None
    return decoded if decoded and all(" " <= char <= "~" for char in decoded) else None


def decode(value: str) -> tuple[dict, set[str]]:
    """(informe público, valores decodificados completos solo para comparar en memoria).

    Formato reconocido (linker v1): «1*<hash>*<nombre>*<valor>*…». Si no coincide, solo consta la presencia.
    """
    report = {"present": True, "length": len(value), "format": UNRECOGNIZED, "fields": [], "undecoded_fields": 0,
              "hash_verified": False}
    parts = value[:MAX_VALUE_CHARS].split("*")
    pairs = list(zip(parts[2::2], parts[3::2]))
    if len(parts) < 4 or parts[0] != "1" or not _HASH.match(parts[1]) or len(parts[2:]) % 2 or not all(_KEY.match(k) for k, _ in pairs):
        return report, set()
    report["format"] = FORMAT_V1
    values = set()
    for name, raw in pairs[:MAX_FIELDS]:
        decoded = _b64(raw)
        if decoded is None:
            report["undecoded_fields"] += 1
            continue
        report["fields"].append({"name": name, "value": mask(decoded), "length": len(decoded)})
        values.add(decoded)
    report["undecoded_fields"] += max(0, len(pairs) - MAX_FIELDS)
    return report, values


def _referer(request: dict) -> str | None:
    return next((h.get("value") for h in request.get("request_headers") or []
                 if isinstance(h, dict) and str(h.get("name", "")).lower() == "referer" and isinstance(h.get("value"), str)), None)


def candidates(requests: list[dict], *, timeline: list | None, page_url: str | None, start_url: str | None) -> list[dict]:
    """URLs de navegación y de redirección con _gl: [{source, request_id, url, origin, chain, gl, values, evidence}].

    Fuentes: requests de navegación (documentos) y saltos 3xx; además, las páginas de la línea de tiempo de una captura
    interactiva y la URL final, cuando su navegación no quedó como request (p. ej. una pestaña nueva).
    """
    by_seq = {request.get("seq"): request for request in requests}
    found: list[dict] = []
    seen: set[str] = set()
    navigations = sorted((r for r in requests if r.get("is_navigation")), key=lambda r: r.get("seq") or 0)
    for request in requests:
        redirected = request.get("redirected_from_seq") is not None
        if not (request.get("is_navigation") or redirected or request.get("resource_type") == "document"):
            continue
        value = gl_value(request.get("url"))
        if value is None:
            continue
        chain, hop = [], request
        while hop is not None and len(chain) < MAX_CHAIN:
            chain.append({"seq": hop.get("seq"), "request_id": hop.get("request_id"), "url": strip_url(hop.get("url")),
                          "status": hop.get("response_status") if hop is not request else None})
            hop = by_seq.get(hop.get("redirected_from_seq")) if hop.get("redirected_from_seq") is not None else None
        chain.reverse()
        first = by_seq.get(chain[0]["seq"]) or request
        if _referer(first):
            origin = {"url": strip_url(_referer(first)), "via": "referer"}
        elif redirected:
            origin = {"url": chain[0]["url"], "via": "redirect"}
        elif request.get("seq") == 0:
            origin = {"url": None, "via": "url_de_entrada"}
        else:
            previous = next((r for r in reversed(navigations) if (r.get("seq") or 0) < (request.get("seq") or 0)
                             and r.get("frame_url") == r.get("url")), None)
            origin = {"url": strip_url(previous.get("url")), "via": "pagina_anterior"} if previous else {"url": None, "via": None}
        gl, values = decode(value)
        found.append({"source": "redirect" if redirected else "navigation", "request_id": request.get("request_id"),
                      "url": request.get("url"), "origin": origin, "chain": chain if redirected else None,
                      "gl": gl, "values": values | {value}, "evidence": [request.get("request_id")]})
        seen.add((request.get("url") or "").split("#")[0])

    # Páginas sin request de navegación (línea de tiempo de la captura interactiva, URL final del scan).
    pages = [entry for entry in timeline or [] if isinstance(entry, dict) and isinstance(entry.get("url"), str)]
    if not pages and page_url and page_url != start_url:
        pages = [{"url": start_url}, {"url": page_url}]
    for index, entry in enumerate(pages):
        url = entry["url"]
        value = gl_value(url)
        if value is None or url.split("#")[0] in seen:
            continue
        seen.add(url.split("#")[0])
        previous = pages[index - 1]["url"] if index > 0 else None
        # Evidencia: requests hechas desde ese documento (su frame_url es la URL con _gl).
        evidence = [r.get("request_id") for r in requests if r.get("frame_url") == url][:MAX_EVIDENCE]
        gl, values = decode(value)
        found.append({"source": "navigation", "request_id": None, "url": url,
                      "origin": {"url": strip_url(previous), "via": "pagina_anterior"} if previous else {"url": None, "via": None},
                      "chain": None, "gl": gl, "values": values | {value}, "evidence": evidence, "tab": entry.get("tab")})
    return found[:MAX_ITEMS]
