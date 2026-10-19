"""Importar un archivo HAR (captura hecha por el navegador real del usuario). v1.3, docs/adr/025.

Todo lo que trae el HAR es dato NO confiable: se valida el esquema y el tamaño, se acota cada
cadena y solo se conserva texto. Antes de guardar nada se descartan los valores de Cookie,
Set-Cookie y Authorization (queda el nombre de la cabecera y el largo del valor) y los arreglos
`cookies` de cada entrada. Los cuerpos de respuesta (`content.text`) nunca se guardan.

La api solo valida, depura y deja las entradas normalizadas en `har_imports`; el worker las
convierte en una captura y las pasa por el mismo analizador que un scan.
"""

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from app.errors import AppError
from app.proxy_headers import is_proxy_header

MAX_ENTRIES = 20000  # entradas que se aceptan en el archivo
MAX_LOAD_ENTRIES = 5000  # entradas de la carga elegida que se guardan (el worker aplica MAX_REQUESTS)
MAX_PAGES = 200
MAX_URL_CHARS = 8192
MAX_HEADERS = 200
MAX_HEADER_NAME_CHARS = 256
MAX_HEADER_VALUE_CHARS = 8192
MAX_BODY_CHARS = 65536
MAX_LABEL_CHARS = 300
# Un silencio mayor separa dos cargas cuando las entradas no traen `pageref`.
LOAD_GAP_S = 30
# Margen para sumar a una página las entradas sin `pageref` de su misma ventana de tiempo.
PAGE_TAIL_S = 5
BLOCKED_BY_CLIENT = "net::ERR_BLOCKED_BY_CLIENT"
# Cabeceras cuyo valor se descarta antes de guardar: credenciales e identificadores de sesión.
SENSITIVE_HEADERS = {"cookie": "cookie", "set-cookie": "set_cookie", "authorization": "authorization", "proxy-authorization": "authorization"}
SOURCE_NOTE = "Captura importada: navegador real del usuario."
NO_FINGERPRINTING_NOTE = (
    "Un HAR solo registra el tráfico de red: no incluye la instrumentación de fingerprinting "
    "(lecturas de canvas, WebGL, audio y navigator), que solo existe en los scans del worker."
)


def invalid(message: str, **details) -> AppError:
    return AppError("HAR_INVALID", message, stage="har_validation", status_code=400, details=details or None)


def clean_text(value: object, limit: int) -> str | None:
    """Cadena acotada y almacenable (sin NUL ni surrogates sueltos); None si no es texto."""
    if not isinstance(value, str):
        return None
    return value[:limit].replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _http_url(value: object) -> str | None:
    url = clean_text(value, MAX_URL_CHARS)
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return url if parts.scheme in ("http", "https") and parts.hostname else None


def _number(value: object) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def parse(raw: bytes) -> dict:
    """JSON del HAR con el esquema mínimo validado: `log.entries[]` con request y response."""
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise invalid("El archivo no es un JSON válido en UTF-8.") from exc
    log = document.get("log") if isinstance(document, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise invalid("El archivo no tiene la estructura de un HAR (falta log.entries).")
    if len(log["entries"]) > MAX_ENTRIES:
        raise invalid(f"El HAR tiene demasiadas entradas (máximo {MAX_ENTRIES}).", entries=len(log["entries"]))
    if not isinstance(log.get("pages", []), list):
        raise invalid("El campo log.pages del HAR no es una lista.")
    return log


def _entries(log: dict) -> tuple[list[dict], int]:
    """Entradas con lo mínimo exigible (URL http(s), método y fecha), en orden de tiempo."""
    valid, dropped = [], 0
    for index, entry in enumerate(log["entries"]):
        request = entry.get("request") if isinstance(entry, dict) else None
        ts = _timestamp(entry.get("startedDateTime")) if isinstance(entry, dict) else None
        url = _http_url(request.get("url")) if isinstance(request, dict) else None
        if ts is None or url is None or not isinstance(request.get("method"), str):
            dropped += 1  # data:, blob:, extensiones o entradas mal formadas: no son requests de red
            continue
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        valid.append({"index": index, "ts": ts, "url": url, "entry": entry, "request": request, "response": response,
                      "pageref": entry.get("pageref") if isinstance(entry.get("pageref"), str) else None})
    valid.sort(key=lambda item: (item["ts"], item["index"]))
    return valid, dropped


def _error(item: dict) -> str | None:
    return clean_text(item["response"].get("_error"), 200) or None


def _resource_type(item: dict) -> str | None:
    return clean_text(item["entry"].get("_resourceType"), 32)


def _load(load_id: str, kind: str, items: list[dict], *, title: str | None = None, started: datetime | None = None) -> dict:
    documents = [item for item in items if _resource_type(item) == "document"]
    referers = Counter(
        header.get("value") for item in items for header in item["request"].get("headers") or []
        if isinstance(header, dict) and str(header.get("name", "")).lower() == "referer" and _http_url(header.get("value"))
    )
    # URL de la página: el título de la página (Chrome pone ahí la URL), el primer documento,
    # el Referer más repetido o, si no hay nada mejor, la primera request.
    page_url = _http_url(title) or (documents[0]["url"] if documents else None) or (
        _http_url(referers.most_common(1)[0][0]) if referers else None) or (items[0]["url"] if items else None)
    return {
        "id": load_id,
        "kind": kind,  # page = página del HAR (pageref) · time = entradas sin página, agrupadas por tiempo
        "started_at": (started or items[0]["ts"]).astimezone(timezone.utc).isoformat() if (started or items) else None,
        "ended_at": items[-1]["ts"].astimezone(timezone.utc).isoformat() if items else None,
        "title": clean_text(title, MAX_LABEL_CHARS),
        "page_url": page_url,
        "requests": len(items),
        "documents": len(documents),
        "blocked_by_client": sum(1 for item in items if _error(item) == BLOCKED_BY_CLIENT),
        "_items": items,
    }


def find_loads(log: dict) -> tuple[list[dict], int]:
    """Cargas de página que trae el HAR: una por `pageref` y una por cada tramo de tiempo sin página.

    Un HAR de DevTools con «Preserve log» mezcla varias visitas; las entradas sin `pageref` se
    suman a la página en cuya ventana de tiempo caen y el resto se agrupa por silencios.
    """
    entries, dropped = _entries(log)
    pages = [page for page in log.get("pages") or [] if isinstance(page, dict) and isinstance(page.get("id"), str)][:MAX_PAGES]
    by_page: dict[str, list[dict]] = {page["id"]: [] for page in pages}
    orphans = []
    for item in entries:
        (by_page[item["pageref"]] if item["pageref"] in by_page else orphans).append(item)
    windows = []
    for page in pages:
        items = by_page[page["id"]]
        start = _timestamp(page.get("startedDateTime")) or (items[0]["ts"] if items else None)
        if start is not None:
            end = max([item["ts"] for item in items] + [start]) + timedelta(seconds=PAGE_TAIL_S)
            windows.append((start - timedelta(seconds=1), end, page["id"]))
    loose = []
    for item in orphans:
        owner = next((page_id for start, end, page_id in windows if start <= item["ts"] <= end), None)
        (by_page[owner] if owner is not None else loose).append(item)
    loads = []
    for number, page in enumerate(pages):
        items = sorted(by_page[page["id"]], key=lambda item: (item["ts"], item["index"]))
        if items:
            loads.append(_load(f"page:{number}", "page", items, title=page.get("title"), started=_timestamp(page.get("startedDateTime"))))
    group: list[dict] = []
    groups = []
    for item in loose:
        if group and (item["ts"] - group[-1]["ts"]).total_seconds() > LOAD_GAP_S:
            groups.append(group)
            group = []
        group.append(item)
    if group:
        groups.append(group)
    loads += [_load(f"time:{number}", "time", items) for number, items in enumerate(groups)]
    loads.sort(key=lambda load: load["started_at"] or "")
    return loads, dropped


def default_load(loads: list[dict]) -> dict | None:
    """La carga con documento y más requests; a igualdad, la más reciente."""
    if not loads:
        return None
    return max(loads, key=lambda load: (load["documents"] > 0, load["requests"], load["started_at"] or ""))


def _headers(headers: object, removed: Counter) -> list[dict]:
    """Cabeceras acotadas. De las sensibles solo quedan el nombre y el largo del valor."""
    out = []
    for header in headers[:MAX_HEADERS] if isinstance(headers, list) else []:
        if not isinstance(header, dict):
            continue
        name = clean_text(header.get("name"), MAX_HEADER_NAME_CHARS)
        value = header.get("value")
        if not name or not isinstance(value, str):
            continue
        kind = SENSITIVE_HEADERS.get(name.lower())
        if is_proxy_header(name):
            # Del navegador con su proxy (v1.5.3): ni el nombre se guarda. Proxy-Authorization cuenta como credencial descartada.
            if kind is not None:
                removed[kind] += 1
            continue
        if kind is not None:
            removed[kind] += 1
            out.append({"name": name, "value": "", "redacted": True, "length": len(value)})
        else:
            out.append({"name": name, "value": clean_text(value, MAX_HEADER_VALUE_CHARS)})
    return out


def _post_data(request: dict) -> dict | None:
    post = request.get("postData")
    if not isinstance(post, dict):
        return None
    body = post.get("text")
    if not isinstance(body, str) and isinstance(post.get("params"), list):
        pairs = [(str(p.get("name", "")), str(p.get("value", ""))) for p in post["params"][:500] if isinstance(p, dict)]
        body = urlencode(pairs)
    if not isinstance(body, str):
        return None
    return {"text": clean_text(body, MAX_BODY_CHARS), "size": len(body.encode("utf-8", "replace")), "truncated": len(body) > MAX_BODY_CHARS,
            "mime": clean_text(post.get("mimeType"), 255)}


def _initiator(entry: dict) -> dict | None:
    """Tipo y URL del iniciador (campo `_initiator` de Chrome); el stack se reduce a su primer script."""
    initiator = entry.get("_initiator")
    if not isinstance(initiator, dict):
        return None
    url = _http_url(initiator.get("url"))
    stack, depth = initiator.get("stack"), 0
    while url is None and isinstance(stack, dict) and depth < 10:
        for frame in stack.get("callFrames") if isinstance(stack.get("callFrames"), list) else []:
            if isinstance(frame, dict) and _http_url(frame.get("url")):
                url = _http_url(frame.get("url"))
                break
        stack, depth = stack.get("parent"), depth + 1
    return {"type": clean_text(initiator.get("type"), 32), "url": url}


def sensitive_counts(items: list[dict]) -> dict:
    """Cuántas cabeceras sensibles y cookies trae la carga, sin leer sus valores."""
    counts: Counter = Counter()
    for item in items:
        for side in (item["request"], item["response"]):
            for header in side.get("headers") if isinstance(side.get("headers"), list) else []:
                kind = SENSITIVE_HEADERS.get(str(header.get("name", "")).lower()) if isinstance(header, dict) else None
                if kind is not None:
                    counts[kind] += 1
            if isinstance(side.get("cookies"), list):
                counts["cookie_objects"] += len(side["cookies"])
    return {key: counts.get(key, 0) for key in ("cookie", "set_cookie", "authorization", "cookie_objects")}


def public_load(load: dict) -> dict:
    return {key: value for key, value in load.items() if not key.startswith("_")}


def inspect(raw: bytes) -> dict:
    """Qué trae el archivo, sin guardar nada: cargas, bloqueos y datos sensibles que se descartarán."""
    log = parse(raw)
    loads, dropped = find_loads(log)
    if not loads:
        raise invalid("El HAR no contiene ninguna request http(s) con fecha válida.")
    chosen = default_load(loads)
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    browser = log.get("browser") if isinstance(log.get("browser"), dict) else {}
    sensitive = sensitive_counts([item for load in loads for item in load["_items"]])
    warnings = []
    if any(sensitive.values()):
        warnings.append(
            f"El archivo contiene {sensitive['cookie']} cabecera(s) Cookie, {sensitive['set_cookie']} Set-Cookie, "
            f"{sensitive['authorization']} Authorization y {sensitive['cookie_objects']} cookie(s) registradas. "
            "Sus valores se descartan antes de guardar: solo se conservan el nombre y el largo."
        )
    return {
        "bytes": len(raw),
        "har_version": clean_text(log.get("version"), 16),
        "creator": clean_text(" ".join(str(creator.get(key, "")) for key in ("name", "version")).strip(), 120) or None,
        "browser": clean_text(" ".join(str(browser.get(key, "")) for key in ("name", "version")).strip(), 120) or None,
        "entries_total": len(log["entries"]),
        "entries_ignored": dropped,
        "loads": [public_load(load) for load in loads],
        "default_load": chosen["id"],
        "sensitive": sensitive,
        "warnings": warnings,
        "notes": [SOURCE_NOTE, NO_FINGERPRINTING_NOTE],
    }


def build_import(raw: bytes, load_id: str | None, file_name: str | None = None) -> dict:
    """Carga elegida, depurada y normalizada: lo único del HAR que se guarda."""
    log = parse(raw)
    loads, dropped = find_loads(log)
    if not loads:
        raise invalid("El HAR no contiene ninguna request http(s) con fecha válida.")
    load = default_load(loads) if load_id is None else next((item for item in loads if item["id"] == load_id), None)
    if load is None:
        raise invalid("La carga elegida no existe en este HAR.", loads=[item["id"] for item in loads])
    if load["page_url"] is None:
        raise invalid("No se pudo determinar la URL de la página de esa carga.")
    items = load["_items"]
    removed: Counter = Counter()
    cookie_objects = 0
    entries = []
    for item in items[:MAX_LOAD_ENTRIES]:
        entry, request, response = item["entry"], item["request"], item["response"]
        cookie_objects += sum(len(side["cookies"]) for side in (request, response) if isinstance(side.get("cookies"), list))
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        status = response.get("status")
        entries.append({
            "ts": item["ts"].astimezone(timezone.utc).isoformat(),
            "method": clean_text(request["method"], 32),
            "url": item["url"],
            "url_truncated": len(request["url"]) > MAX_URL_CHARS,
            "http_version": clean_text(request.get("httpVersion"), 32),
            "request_headers": _headers(request.get("headers"), removed),
            "post_data": _post_data(request),
            # status 0 = sin respuesta (bloqueada, abortada o fallida).
            "status": status if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599 else None,
            "response_headers": _headers(response.get("headers"), removed) if response.get("headers") else None,
            "mime": clean_text(content.get("mimeType"), 255),
            "resource_type": _resource_type(item),
            "initiator": _initiator(entry),
            "error": _error(item),
            "server_ip": clean_text(entry.get("serverIPAddress"), 64) or None,
            "time_ms": _number(entry.get("time")),
            "sizes": {key: value for key, value in (
                ("requestBodySize", _number(request.get("bodySize"))), ("requestHeadersSize", _number(request.get("headersSize"))),
                ("responseBodySize", _number(response.get("bodySize"))), ("responseHeadersSize", _number(response.get("headersSize"))),
            ) if value is not None and value >= 0},
        })
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    return {
        "page_url": load["page_url"],
        "entries": entries,
        "meta": {
            "file_name": clean_text(file_name, 200),
            "har_version": clean_text(log.get("version"), 16),
            "creator": clean_text(" ".join(str(creator.get(key, "")) for key in ("name", "version")).strip(), 120) or None,
            "load": public_load(load),
            "loads_in_file": len(loads),
            "entries_total": len(log["entries"]),
            "entries_ignored": dropped,
            "entries_load": len(items),
            "truncated": len(items) > MAX_LOAD_ENTRIES,
            "blocked_by_client": load["blocked_by_client"],
            # Solo conteos: los valores ya no existen.
            "sensitive_removed": {"cookie": removed.get("cookie", 0), "set_cookie": removed.get("set_cookie", 0),
                                  "authorization": removed.get("authorization", 0), "cookie_objects": cookie_objects},
            "notes": [SOURCE_NOTE, NO_FINGERPRINTING_NOTE],
        },
    }
