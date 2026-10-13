"""Captura a partir de un HAR importado (v1.3, docs/adr/025).

La api ya validó el archivo, eligió la carga y descartó los valores de Cookie, Set-Cookie y
Authorization. Aquí las entradas se convierten al mismo formato que produce el monitor de red,
para que el analizador sea exactamente el mismo que el de un scan. Los datos siguen siendo no
confiables: se vuelve a comprobar tipo y tamaño de cada campo.

Lo que un HAR no trae queda vacío y se declara: sin instrumentación de fingerprinting, sin
snapshot de cookies ni storage, sin frames de WebSocket.
"""

from collections import Counter
from datetime import datetime, timezone

from app.browser.network_monitor import (
    MAX_FAILURE_CHARS, MAX_HEADER_NAME_CHARS, MAX_HEADER_VALUE_CHARS, MAX_HEADERS, MAX_URL_CHARS, encode_body, split_url, text,
)
from app.browser.parties import is_third_party, registrable_domain

SOURCE = "har_import"
# Tipos de recurso que usa el monitor (los de Playwright). Lo demás es "other".
RESOURCE_TYPES = frozenset({
    "document", "stylesheet", "image", "media", "font", "script", "texttrack", "xhr", "fetch", "eventsource", "websocket",
    "manifest", "other", "ping", "preflight",
})
MIME_TYPES = (("html", "document"), ("javascript", "script"), ("ecmascript", "script"), ("css", "stylesheet"), ("image/", "image"),
              ("font", "font"), ("audio/", "media"), ("video/", "media"), ("json", "xhr"))


class InvalidImport(ValueError):
    pass


def _headers(headers: object) -> list[dict]:
    out = []
    for header in headers[:MAX_HEADERS] if isinstance(headers, list) else []:
        if not isinstance(header, dict):
            continue
        name, value = text(header.get("name"), MAX_HEADER_NAME_CHARS), text(header.get("value"), MAX_HEADER_VALUE_CHARS)
        if name is None or value is None:
            continue
        if header.get("redacted") is True:
            # Cabecera sensible: la api guardó solo el nombre y el largo del valor.
            length = header.get("length")
            out.append({"name": name, "value": "", "redacted": True, "length": length if isinstance(length, int) and length >= 0 else None})
        else:
            out.append({"name": name, "value": value})
    return out


def _resource_type(entry: dict, mime: str | None) -> str:
    declared = entry.get("resource_type")
    if isinstance(declared, str) and declared.lower() in RESOURCE_TYPES:
        return declared.lower()
    for marker, kind in MIME_TYPES if mime else ():
        if marker in mime:
            return kind
    return "other"


def _timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return parsed if parsed is None or parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def build_capture(payload: object, *, max_requests: int, max_body_bytes: int) -> tuple[dict, dict]:
    """(result, capture) con la misma forma que deja `run_scan`."""
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list) or not isinstance(payload.get("page_url"), str):
        raise InvalidImport("payload")
    page_url = text(payload["page_url"], MAX_URL_CHARS)
    page_host = split_url(page_url)["host"]
    page_domain = registrable_domain(page_host)
    if page_domain is None:
        raise InvalidImport("page_url")
    first_party = {page_domain}
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}

    requests, connections, http_status = [], Counter(), None
    usable = [entry for entry in payload["entries"] if isinstance(entry, dict)]
    for entry in usable:
        ts, url = _timestamp(entry.get("ts")), text(entry.get("url"), MAX_URL_CHARS)
        if ts is None or not url or len(requests) >= max_requests:
            continue
        parts = split_url(url)
        if parts["scheme"] not in ("http", "https") or not parts["host"]:
            continue
        status = entry.get("status") if isinstance(entry.get("status"), int) and not isinstance(entry.get("status"), bool) else None
        mime = text(entry.get("mime"), 255)
        mime = mime.split(";")[0].strip().lower() or None if mime else None
        resource_type = _resource_type(entry, mime)
        post = entry.get("post_data") if isinstance(entry.get("post_data"), dict) else None
        body = None
        if post is not None and isinstance(post.get("text"), str):
            body = encode_body(post["text"].encode("utf-8", "replace"), max_body_bytes)
            if post.get("truncated") is True:
                body["truncated"] = True
            if isinstance(post.get("size"), int) and post["size"] >= body["size"]:
                body["size"] = post["size"]
        initiator = entry.get("initiator") if isinstance(entry.get("initiator"), dict) else None
        if initiator is not None:
            kind, initiator_url = text(initiator.get("type"), 32), text(initiator.get("url"), MAX_URL_CHARS)
            initiator = {"type": kind, "url": initiator_url, "line": None,
                         "script_url": initiator_url if kind == "script" else None, "stack": []}
        response_headers = _headers(entry.get("response_headers")) if entry.get("response_headers") is not None else None
        if resource_type == "document" and http_status is None and url == page_url:
            http_status = status
        sizes = entry.get("sizes") if isinstance(entry.get("sizes"), dict) else {}
        time_ms = entry.get("time_ms")
        requests.append({
            "seq": len(requests),
            "ts": ts,
            "method": text(entry.get("method"), 32),
            "url": url,
            "url_truncated": entry.get("url_truncated") is True,
            **parts,
            "resource_type": resource_type,
            "frame_url": None,  # el HAR no dice en qué frame ocurrió la request
            "is_navigation": resource_type == "document",
            "initiator": initiator,
            "request_headers": _headers(entry.get("request_headers")),
            "post_data": body,
            "post_data_source": "har" if body else None,
            "response_status": status,
            "response_headers": response_headers,
            "mime_type": mime,
            "sizes": {key: value for key, value in sizes.items() if isinstance(key, str) and len(key) <= 32 and isinstance(value, int)
                      and not isinstance(value, bool)} or None,
            "timing": {"time_ms": time_ms} if isinstance(time_ms, (int, float)) and not isinstance(time_ms, bool) else {},
            # P. ej. net::ERR_BLOCKED_BY_CLIENT: la bloqueó una extensión del navegador del usuario.
            "failure_text": text(entry.get("error"), MAX_FAILURE_CHARS) or None,
            "blocked_by_proxy": False,
            "third_party": is_third_party(parts["host"], first_party),
            "registrable_domain": registrable_domain(parts["host"]),
            "redirected_from_seq": None,
        })
        server_ip = text(entry.get("server_ip"), 64)
        if server_ip:
            connections[(parts["host"], server_ip.strip("[]"))] += 1

    truncated = len(usable) > len(requests) or meta.get("truncated") is True
    duration_ms = round((requests[-1]["ts"] - requests[0]["ts"]).total_seconds() * 1000) if requests else 0
    capture = {
        "requests": requests,
        "redirects": [],
        "websockets": [],
        # El HAR depurado no trae cookies ni storage: no hay snapshot.
        "cookies": [],
        "storage": [],
        # IP del servidor tal como la registró el navegador del usuario.
        "destinations": [{"host": host, "ip": ip, "connections": count} for (host, ip), count in connections.items()],
        "artifacts": [],
        # None = sin instrumentación: un HAR solo trae red, no las lecturas de APIs del navegador.
        "fingerprinting": None,
        "truncated": truncated,
        "end_reason": SOURCE,
        "duration_ms": max(0, duration_ms),
        "service_workers": {"blocked_attempts": 0, "registrations": None, "active_workers": 0},
        "first_party_domains": sorted(first_party),
    }
    result = {
        "http_status": http_status,
        "title": None,
        "final_url": page_url,
        "tcf": None,
        "source": SOURCE,
        "import": meta,
    }
    return result, capture
