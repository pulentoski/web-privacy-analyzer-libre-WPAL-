"""Comparación de visitas (v1.5.2, docs/adr/040): función pura sobre las tres capturas ya guardadas.

Visita 1 = perfil A limpio; visita 2 = perfil A persistente (mismo directorio, tras cerrar el navegador y esperar el
intervalo); visita 3 = perfil B limpio de control. Se comparan valores exactos en su contexto (mismo destino y mismo
campo), nunca solo nombres. Es una comparación reproducible, no un detector: tres visitas no prueban causalidad.

No escribe nada: se calcula al leer, con los datos de los scans tal como quedaron.
"""

import pathlib
import re
from datetime import datetime

import yaml

from app.masking import looks_like_id, mask_identifiers

VISITS = (1, 2, 3)
MAX_ITEMS = 200  # por clase; el total se informa siempre

PERSISTENT_TEXT = ("se observó un identificador persistente entre dos visitas con el mismo perfil; "
                   "el perfil limpio de control mostró un resultado distinto")
ONLY_V2_TEXT = "cambio observado en el perfil persistente que no apareció en los perfiles limpios"
ALSO_CONTROL_TEXT = "también observado en el control"
PROFILE_A_TEXT = "observado en las dos visitas con el mismo perfil y no en el perfil limpio de control"
CLEAN_ONLY_TEXT = "observado solo en visitas con perfil limpio"
ABSENT_TEXT = "no observado en esta captura"
DIFFERENT_TEXT = "valor distinto"
OBSERVED_TEXT = "observado"
WARNING = ("Tres visitas no prueban causalidad. Una diferencia puede deberse a publicidad dinámica, pruebas A/B, estado "
           "del servidor o a la propia captura. Este resultado no indica que el sitio haya reconocido al visitante.")
LIMITS = [
    "Las tres visitas salen por la misma IP: lo que el sitio asocie a la IP también alcanza al perfil de control.",
    "Solo se compara lo que pasó por la captura. Lo que no aparece quedó «no observado en esta captura», que no "
    "significa que no exista.",
    "Las visitas de una comparación usan un perfil en disco (contexto persistente). No se comparan con scans sueltos, "
    "que usan un contexto efímero.",
]

# Elementos que se comparan y su contexto. `value` = se compara el valor; si no, solo la presencia.
KINDS = {
    "requests": {"label": "Requests", "context": ("method", "host", "path"), "value": False},
    "destinations": {"label": "Destinos", "context": ("host",), "value": False},
    "organizations": {"label": "Organizaciones", "context": ("organization",), "value": False},
    "cookies": {"label": "Cookies", "context": ("domain", "path", "name"), "value": True},
    "cookie_identifiers": {"label": "Identificadores en cookies", "context": ("host", "source", "name"), "value": True},
    "storage": {"label": "Storage", "context": ("origin", "storage_type", "key"), "value": True},
    "url": {"label": "URL", "context": ("host", "path", "source", "name"), "value": True},
    "headers": {"label": "Cabeceras", "context": ("host", "path", "header"), "value": True},
    "bodies": {"label": "Cuerpos", "context": ("host", "path", "source", "name"), "value": True},
}
URL_SOURCES = ("query", "query_decoded", "referer", "referer_decoded")
BODY_SOURCES = ("post_form", "post_form_decoded", "post_body", "post_body_decoded")
COOKIE_SOURCES = ("cookie", "cookie_decoded", "set_cookie", "set_cookie_decoded")
# Cabeceras que no se comparan: las que genera el navegador en cada request (iguales para todo visitante o derivadas
# del tipo de request), las de la herramienta con el proxy, y Cookie y Referer, que ya se comparan campo a campo
# (cookie_identifiers y url). Quedan las que pone el sitio (x-*, authorization, validadores de caché...).
SKIPPED_HEADERS = {
    "accept", "accept-encoding", "accept-language", "cache-control", "connection", "content-length", "content-type", "cookie",
    "host", "origin", "pragma", "priority", "proxy-authorization", "proxy-connection", "purpose", "referer", "sec-purpose",
    "upgrade-insecure-requests", "user-agent",
}
SKIPPED_HEADER_PREFIXES = ("sec-ch-", "sec-fetch-")

CLASSES = {
    "persistent": PERSISTENT_TEXT,
    "only_visit_2": ONLY_V2_TEXT,
    "also_control": ALSO_CONTROL_TEXT,
    "profile_a": PROFILE_A_TEXT,
    "clean_only": CLEAN_ONLY_TEXT,
}
DISCARDS = {
    "static": "igual en las tres visitas (estático)",
    "session": "de sesión: no puede sobrevivir al cierre del navegador",
    "constant": "constante conocida (data/shared_constants.yaml)",
    "not_identifier": "sin forma de identificador",
    "varies": "cambia en cada visita (marca de tiempo, nonce o valor de una sola visita)",
}


def load_constants(data_dir: str) -> list[re.Pattern]:
    """Versiones de software y claves de configuración de data/shared_constants.yaml: iguales para todo visitante."""
    try:
        raw = yaml.safe_load((pathlib.Path(data_dir) / "shared_constants.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    patterns = list(raw.get("version_patterns") or []) + [item.get("pattern") for item in raw.get("constant_patterns") or [] if isinstance(item, dict)]
    out = []
    for pattern in patterns:
        try:
            out.append(re.compile(pattern))
        except (re.error, TypeError):
            continue
    return out


def observations(data: dict) -> dict:
    """Observaciones de una visita: {kind: {contexto: {valor: {"session": bool, "identifier_like": bool}}}}.

    `data` trae las filas de la visita: requests, analysis (entidad por request), destinations, cookies, storage y
    parameters (con host y ruta de su request).
    """
    out: dict = {kind: {} for kind in KINDS}

    def add(kind: str, context: tuple, value, *, session: bool = False, identifier_like: bool = False) -> None:
        slot = out[kind].setdefault(context, {}).setdefault(value, {"session": False, "identifier_like": False})
        slot["session"] = slot["session"] or session
        slot["identifier_like"] = slot["identifier_like"] or identifier_like

    # Valores de las cookies de sesión de esta visita: también son de sesión cuando viajan en la cabecera Cookie.
    session_values = {(row["name"], row["value"]) for row in data.get("cookies", [])
                      if not isinstance(row.get("expires"), (int, float)) or row["expires"] <= 0}
    for row in data.get("requests", []):
        add("requests", (row["method"], row["host"], generic_path(row["path"])), None)
        for header in row.get("request_headers") or []:
            name = header.get("name").lower() if isinstance(header, dict) and isinstance(header.get("name"), str) else None
            if name and name not in SKIPPED_HEADERS and not name.startswith(SKIPPED_HEADER_PREFIXES):
                add("headers", (row["host"], generic_path(row["path"]), name), str(header.get("value") or ""))
    for host in data.get("destinations", []):
        add("destinations", (host,), None)
    for entity in data.get("organizations", []):
        add("organizations", (entity,), None)
    for row in data.get("cookies", []):
        expires = row.get("expires")
        add("cookies", (row["domain"], row["path"], row["name"]), row["value"],
            session=not isinstance(expires, (int, float)) or expires <= 0)
    for row in data.get("storage", []):
        add("storage", (row["origin"], row["storage_type"], row["key"]), row["value"], session=row["storage_type"] == "session")
    for row in data.get("parameters", []):
        source = row["source"]
        if source in URL_SOURCES:
            kind, context = "url", (row["host"], row["path"], source, row["name"])
        elif source in BODY_SOURCES:
            kind, context = "bodies", (row["host"], row["path"], source, row["name"])
        elif source in COOKIE_SOURCES:
            kind, context = "cookie_identifiers", (row["host"], source, row["name"])
        else:
            continue
        add(kind, context, row["value"], identifier_like=bool(row.get("identifier_like")),
            session=kind == "cookie_identifiers" and (row["name"], row["value"]) in session_values)
    return out


def generic_path(path: str | None) -> str:
    """Ruta con los tramos con forma de identificador como «:id»: la misma request con otro ID es la misma request."""
    return "/".join(":id" if len(segment) >= 9 and looks_like_id(segment) else segment for segment in (path or "").split("/"))


def _identifier(value: str, meta: list[dict]) -> bool:
    if any(item and item["identifier_like"] for item in meta):
        return True
    return isinstance(value, str) and (looks_like_id(value) or any(looks_like_id(part) for part in re.split(r"[^A-Za-z0-9_\-=~+%]+", value) if len(part) >= 9))


def _constant(value: str, constants: list[re.Pattern]) -> bool:
    return isinstance(value, str) and any(pattern.fullmatch(value) for pattern in constants)


def _status(by_visit: dict, visit: int, value) -> str:
    values = by_visit.get(visit)
    if not values:
        return ABSENT_TEXT
    return OBSERVED_TEXT if value in values else DIFFERENT_TEXT


def classify(visits: dict, constants: list[re.Pattern], reveal: bool = False) -> dict:
    """Clasifica cada valor (o presencia) por las visitas en que se observó, en su contexto.

    `visits`: {1: observations(...), 2: ..., 3: ...}. Devuelve las clases con sus textos fijos, lo descartado y por qué.
    """
    classes = {name: {"text": text, "total": 0, "items": []} for name, text in CLASSES.items()}
    discarded = {name: {"reason": reason, "total": 0} for name, reason in DISCARDS.items()}
    by_kind = {kind: {name: 0 for name in CLASSES} for kind in KINDS}

    for kind, spec in KINDS.items():
        contexts = set().union(*(visits[visit][kind].keys() for visit in VISITS))
        for context in sorted(contexts, key=lambda item: tuple(str(part) for part in item)):
            by_visit = {visit: visits[visit][kind].get(context, {}) for visit in VISITS}
            values = set().union(*(set(found) for found in by_visit.values()))
            for value in sorted(values, key=str):
                seen = frozenset(visit for visit in VISITS if value in by_visit[visit])
                meta = [by_visit[visit].get(value) for visit in seen]
                if seen == {1, 2, 3}:
                    discarded["static"]["total"] += 1
                    continue
                if spec["value"] and any(item and item["session"] for item in meta):
                    discarded["session"]["total"] += 1
                    continue
                if seen == {1, 2}:
                    if not spec["value"]:
                        name = "profile_a"
                    elif _constant(value, constants):
                        discarded["constant"]["total"] += 1
                        continue
                    elif not _identifier(value, meta):
                        discarded["not_identifier"]["total"] += 1
                        continue
                    else:
                        name = "persistent"
                elif seen == {2}:
                    in_1, in_3 = bool(by_visit[1]), bool(by_visit[3])
                    # Solo cuenta si el campo no estaba en los perfiles limpios, o si estaba y ambos coincidían en otro
                    # valor. Si cada visita trae un valor propio (marca de tiempo, nonce), no es un cambio del perfil.
                    if spec["value"] and (in_1 or in_3) and not (in_1 and in_3 and set(by_visit[1]) & set(by_visit[3])):
                        discarded["varies"]["total"] += 1
                        continue
                    name = "only_visit_2"
                elif seen == {2, 3}:
                    name = "also_control"
                else:
                    name = "clean_only"
                target = classes[name]
                target["total"] += 1
                by_kind[kind][name] += 1
                if len(target["items"]) < MAX_ITEMS:
                    shown = value if reveal or value is None else mask_identifiers(value)
                    target["items"].append({
                        "kind": kind,
                        "kind_label": spec["label"],
                        "context": dict(zip(spec["context"], context)),
                        "value": shown,
                        "visits": {str(visit): _status(by_visit, visit, value) for visit in VISITS},
                    })
    return {"classes": classes, "discarded": discarded, "by_kind": by_kind}


CONDITION_LABELS = {
    "url": "URL", "browser_version": "Versión de Chromium", "browser_mode": "Modo del navegador", "locale": "Idioma",
    "timezone": "Zona horaria", "accept_language": "Accept-Language", "fp_instrumentation": "Instrumentación de fingerprinting",
    "visit_protocol_version": "Versión del protocolo de visita", "scan_timeout_s": "SCAN_TIMEOUT_S", "max_requests": "MAX_REQUESTS",
    "max_body_capture_bytes": "MAX_BODY_CAPTURE_BYTES", "chromium_args_sha256": "Argumentos de Chromium",
    "egress_country": "País de la IP de salida", "worker_id": "Worker", "profile_mode": "Modo de perfil",
}


def condition_differences(state_visits: dict) -> list[dict]:
    """Condiciones que no fueron iguales en las visitas registradas."""
    out = []
    for key, label in CONDITION_LABELS.items():
        values = {visit: ((state_visits.get(str(visit)) or {}).get("conditions") or {}).get(key, "no_disponible") for visit in VISITS
                  if str(visit) in state_visits}
        if len({repr(value) for value in values.values()}) > 1:
            out.append({"condition": key, "label": label, "values": {str(visit): value for visit, value in values.items()}})
    return out


def _parse(moment: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(moment) if moment else None
    except ValueError:
        return None


def interval(config: dict, state_visits: dict) -> dict:
    """Intervalo configurado y real: del cierre del navegador en la visita 1 a su apertura en la visita 2."""
    closed = _parse((state_visits.get("1") or {}).get("closed_at"))
    launched = _parse((state_visits.get("2") or {}).get("launched_at"))
    real = round((launched - closed).total_seconds(), 1) if closed and launched else None
    return {"configured_s": config.get("interval_s"), "real_s": real}


def validity(jobs: dict, state_visits: dict) -> dict:
    """¿Vale la comparación? Necesita las tres visitas analizadas, el estado de A conservado y los perfiles limpios vacíos."""
    reasons = [f"La visita {visit} no está (se borró del historial)." for visit in VISITS if visit not in jobs]
    pending = [visit for visit in VISITS if (jobs.get(visit) or {}).get("pending")]
    failed = [visit for visit in VISITS if (jobs.get(visit) or {}).get("status") == "failed"]
    unanalyzed = [visit for visit in VISITS if (jobs.get(visit) or {}).get("status") == "completed"
                  and (jobs.get(visit) or {}).get("analysis_status") != "completed" and not (jobs.get(visit) or {}).get("pending")]
    for visit in failed:
        code = (jobs[visit].get("error") or {}).get("error_code")
        if code == "COMPARISON_STATE_LOST":
            reasons.append("Se perdió el estado del perfil A: su directorio no estaba al empezar la visita 2.")
        elif code == "COMPARISON_ABORTED":
            reasons.append(f"La visita {visit} no se hizo porque falló una visita anterior.")
        else:
            reasons.append(f"La visita {visit} falló ({code or 'no_disponible'}).")
    for visit in unanalyzed:
        reasons.append(f"La visita {visit} no tiene análisis.")
    for visit in (1, 3):
        start = (state_visits.get(str(visit)) or {}).get("start") or {}
        if not start:
            continue
        if start.get("dir_existed") or start.get("files_before_launch", 0) != 0:
            reasons.append(f"El perfil de la visita {visit} no estaba vacío al empezar.")
        if start.get("cookies_read") and start.get("cookies_at_start", 0) != 0:
            reasons.append(f"El perfil de la visita {visit} tenía cookies antes de navegar.")
        if visit == 3 and start.get("separate_from_a") is False:
            reasons.append("El perfil B no estaba separado del perfil A.")
    start2 = (state_visits.get("2") or {}).get("start") or {}
    if start2:
        if start2.get("manifest_matches") is False:
            reasons.append(f"El estado de A en disco cambió entre las visitas 1 y 2 ({start2.get('manifest_changed_count', 'no_disponible')} archivos).")
        if start2.get("cookies_read") is False:
            reasons.append("No se pudieron leer las cookies del perfil A al empezar la visita 2: el estado no se pudo verificar.")
        elif start2.get("persistent_cookies_missing"):
            reasons.append(f"Se perdió el estado del perfil A: {start2['persistent_cookies_missing']} cookies persistentes de la visita 1 "
                           "no estaban al empezar la visita 2.")
    if pending and not failed and len(jobs) == len(VISITS):
        return {"status": "en_curso", "valid": None, "reasons": reasons}
    return {"status": "no_valida" if reasons else "valida", "valid": not reasons, "reasons": reasons}


def state_summary(state_visits: dict) -> dict:
    """Lo que se muestra del estado de los perfiles: huellas resumidas, nunca la lista de archivos ni valores."""
    out = {}
    for visit in VISITS:
        item = state_visits.get(str(visit))
        if not item:
            continue
        start, end = item.get("start") or {}, item.get("end") or {}
        cookies = end.get("cookies") or {}
        out[str(visit)] = {
            "profile": item.get("profile"),
            "launched_at": item.get("launched_at"),
            "closed_at": item.get("closed_at"),
            "start": {key: start.get(key) for key in (
                "dir_existed", "files_before_launch", "separate_from_a", "manifest_matches", "manifest_changed_count",
                "cookies_read", "cookies_at_start", "persistent_cookies_expected", "persistent_cookies_missing") if key in start},
            "end": {
                "persistent_cookies": len(cookies.get("persistent") or []) if cookies else None,
                "session_cookies": cookies.get("session") if cookies else None,
                "files": len((end.get("manifest") or {}).get("files") or {}) if end.get("manifest") else None,
                "inventory": end.get("inventory"),
            },
            "error_code": item.get("error_code"),
        }
    return out
