"""Condiciones de la medición, protocolo de visita y cobertura por contexto (v1.5.0, docs/adr/038).

Lo escribe el worker en jobs.result["measurement"]; aquí se revalida tipo y tamaño (el resultado incluye datos que
pasaron por el navegador) y se completa con lo que sabe el análisis (versiones del analizador y de las listas). La
tabla de cobertura sale de data/coverage.yaml, que es el resultado de la auditoría reproducible del worker.
"""

import pathlib
import re
from functools import lru_cache

import yaml

from app.config import get_settings

UNKNOWN = "no_disponible"
COUNTRY_UNKNOWN = "desconocido"
NOT_APPLICABLE = "no_aplica"
STAGES = ("carga", "espera", "scroll", "espera", "cierre")
CLOSING_NOTICE = ("La captura sigue activa durante el cierre de la pestaña y de esa etapa se registran solo los envíos "
                  "efectivamente observados. El cierre no garantiza capturar todos los beacons de salida.")
REASONS = {
    "network_idle": "terminó con la red en calma",
    "duration_elapsed": "se cumplió el tiempo de la etapa",
    "document_end": "llegó al final del documento",
    "max_time": "se cumplió el tiempo máximo sin llegar al final del documento",
    "tab_closed": "la pestaña se cerró",
    "tab_not_closed": "la pestaña no se cerró en el tiempo de observación",
    "scan_timeout": "se agotó el tiempo máximo del scan (SCAN_TIMEOUT_S)",
    "max_requests": "se alcanzó el máximo de requests (MAX_REQUESTS)",
    "page_closed": "la página se cerró sola",
    "scroll_failed": "el navegador no aceptó el desplazamiento",
    "navigation_failed": "la navegación falló",
    "navigation_timeout_partial": "la navegación no terminó a tiempo (scan parcial)",
    "previous_stage_incomplete": "no se ejecutó: la etapa anterior no se completó",
}
INCLUDES = {
    "consent_scenario": "incluye el escenario de consentimiento del Privacy Test",
    "pre_close_dump": "incluye el volcado de la captura previo al cierre",
}
NO_PROTOCOL = {
    "har_import": "Captura HAR importada: la navegación la hizo el usuario en su navegador; no sigue el protocolo de visita.",
    "interactive": "Captura interactiva: la visita la condujo el usuario; no sigue el protocolo de visita.",
    "legacy": "Scan anterior a v1.5.0: se hizo sin el protocolo de visita fijo (solo carga y red en calma).",
}
MIXED_NOTE = ("Los scans comparados no siguieron el mismo protocolo de visita (versión {versions}): parte de las "
              "diferencias puede deberse a cómo se visitó cada sitio, no al sitio.")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+(Z|[+-]\d{2}:\d{2})$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.\-+]{1,64}$")
MAX_STAGE_SEQS = 200


@lru_cache
def coverage() -> dict:
    """data/coverage.yaml: cobertura por contexto (lo que mide worker/tests/v150/test_coverage_audit.py)."""
    raw = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "coverage.yaml").read_text(encoding="utf-8"))
    contexts = [
        {"id": row["id"], "label": row["label"], "instrumentation": bool(row["instrumentation"]),
         "apis_observed": [str(api) for api in row["apis_observed"]], "traffic_captured": bool(row["traffic_captured"]),
         "limitation": row.get("limitation")}
        for row in raw["contexts"]
    ]
    events = [{"event": row["event"], "captured": row["captured"]} for row in raw["closing_events"]]
    return {"audited_with": raw["audited_with"], "probe_apis": list(raw["probe_apis"]), "contexts": contexts,
            "closing_events": events, "closing_limitation": raw["closing_limitation"]}


def coverage_limitations() -> list[str]:
    """Textos de «Límites de la medición» de lo que la auditoría encontró sin cubrir."""
    data = coverage()
    return [row["limitation"] for row in data["contexts"] if row["limitation"]] + [data["closing_limitation"]]


def _iso(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) <= 40 and ISO_RE.match(value) else None


def _int(value: object, low: int = 0, high: int = 2**31) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def protocol_version(result: dict | None) -> int | None:
    """Versión del protocolo de visita de un scan. None = sin protocolo (anterior a v1.5.0, HAR o interactiva)."""
    raw = ((result or {}).get("measurement") or {}).get("visit_protocol")
    return _int(raw.get("protocol_version"), 1, 10_000) if isinstance(raw, dict) else None


def mixed_protocols(versions: list[int | None]) -> dict:
    """Aviso cuando un ranking o una comparación juntan scans con distinto protocolo (None = sin protocolo)."""
    distinct = sorted({version for version in versions}, key=lambda version: (version is not None, version or 0))
    mixed = len(distinct) > 1
    labels = ["sin protocolo" if version is None else str(version) for version in distinct]
    return {"versions": distinct, "mixed": mixed, "note": MIXED_NOTE.format(versions=", ".join(labels)) if mixed else None}


def _stage(raw: object, index: int) -> dict:
    """Etapa revalidada. Lo que no cumple el formato se presenta como no completado y sin datos."""
    raw = raw if isinstance(raw, dict) else {}
    reason = raw.get("reason") if raw.get("reason") in REASONS else None
    planned = raw.get("planned") if isinstance(raw.get("planned"), dict) else {}
    stage = {
        "name": STAGES[index], "order": index + 1,
        "planned": {key: value for key, value in planned.items()
                    if key in ("duration_s", "max_s", "step_interval_ms", "observe_s") and isinstance(value, (int, float)) and not isinstance(value, bool)},
        "completed": raw.get("completed") is True and raw.get("name") == STAGES[index],
        "started_at": _iso(raw.get("started_at")), "ended_at": _iso(raw.get("ended_at")),
        "reason": reason, "reason_text": REASONS.get(reason, UNKNOWN),
        "requests": _int(raw.get("requests")) or 0,
        "request_seqs": [seq for seq in (raw.get("request_seqs") if isinstance(raw.get("request_seqs"), list) else [])[:MAX_STAGE_SEQS]
                         if _int(seq) is not None],
        "includes": [INCLUDES[item] for item in (raw.get("includes") if isinstance(raw.get("includes"), list) else []) if item in INCLUDES],
    }
    if STAGES[index] == "scroll":
        stage["reached_end"] = raw.get("reached_end") if isinstance(raw.get("reached_end"), bool) else None
    return stage


def visit_protocol(result: dict, source: str) -> dict:
    raw = (result.get("measurement") or {}).get("visit_protocol") if isinstance(result.get("measurement"), dict) else None
    version = protocol_version(result)
    if source in ("har_import", "interactive") or not isinstance(raw, dict) or raw.get("applies") is not True or version is None:
        note = NO_PROTOCOL.get(source) or NO_PROTOCOL["legacy"]
        return {"applies": False, "protocol_version": None, "stages": [], "note": note, "closing_notice": CLOSING_NOTICE}
    stages_raw = raw.get("stages") if isinstance(raw.get("stages"), list) else []
    stages = [_stage(stages_raw[index] if index < len(stages_raw) else None, index) for index in range(len(STAGES))]
    return {"applies": True, "protocol_version": version, "stages": stages, "note": None, "closing_notice": CLOSING_NOTICE}


def egress_country(result: dict, source: str) -> dict:
    if source == "har_import":
        return {"status": COUNTRY_UNKNOWN, "country_code": None, "country": COUNTRY_UNKNOWN, "source": None,
                "reason": "Captura HAR importada: la salida a internet fue la de la red del usuario, que no se consulta."}
    raw = (result.get("measurement") or {}).get("egress_country") if isinstance(result.get("measurement"), dict) else None
    if not isinstance(raw, dict) or raw.get("status") != "ok":
        reason = raw.get("reason") if isinstance(raw, dict) and isinstance(raw.get("reason"), str) else None
        return {"status": COUNTRY_UNKNOWN, "country_code": None, "country": COUNTRY_UNKNOWN, "source": None,
                "reason": (reason or "Scan anterior a v1.5.0: no se registró la IP de salida.")[:200]}
    code = raw.get("country_code")
    if not (isinstance(code, str) and re.fullmatch(r"[A-Z]{2}", code)):
        return {"status": COUNTRY_UNKNOWN, "country_code": None, "country": COUNTRY_UNKNOWN, "source": None,
                "reason": "El país registrado no tiene un formato válido."}
    country = raw.get("country") if isinstance(raw.get("country"), str) else code
    source_name = raw.get("source") if isinstance(raw.get("source"), str) else None
    return {"status": "ok", "country_code": code, "country": country[:80], "source": source_name[:80] if source_name else None, "reason": None}


def conditions(result: dict, source: str, *, started_at: str | None, analysis: dict) -> dict:
    """Condiciones de la medición: navegador, modo, fecha y hora, versiones y país de la IP de salida."""
    raw = result.get("measurement") if isinstance(result.get("measurement"), dict) else {}
    browser = raw.get("browser") if isinstance(raw.get("browser"), dict) else {}
    version = browser.get("version") if isinstance(browser.get("version"), str) and VERSION_RE.match(browser.get("version")) else None
    if source == "har_import":
        browser_info, mode = {"name": None, "version": NOT_APPLICABLE}, NOT_APPLICABLE
    else:
        browser_info = {"name": "Chromium", "version": version or UNKNOWN}
        mode = raw.get("browser_mode") if raw.get("browser_mode") in ("headful", "headless") else UNKNOWN
    lists = [{"id": str(item.get("id")), "version": item.get("version") if isinstance(item.get("version"), str) and item.get("version") else UNKNOWN}
             for item in analysis.get("lists") or [] if isinstance(item, dict) and item.get("id")]
    return {
        "browser": browser_info,
        "browser_mode": mode,
        # Hora de inicio de la visita según el worker; en scans anteriores, la del job.
        "measured_at": _iso(raw.get("started_at")) or started_at or UNKNOWN,
        "analyzer_version": analysis.get("analyzer_version") or UNKNOWN,
        "lists_version": analysis.get("lists_version") or UNKNOWN,
        "lists": lists,
        "egress_country": egress_country(result, source),
    }


def closing_sends(stages: list[dict], requests: dict[int, dict]) -> list[dict]:
    """Envíos observados durante el cierre de la pestaña (seq, método, host, ruta y tipo); nada más."""
    closing = next((stage for stage in stages if stage["name"] == "cierre"), None)
    if closing is None:
        return []
    return [requests[seq] for seq in closing["request_seqs"] if seq in requests]


def section(result: dict | None, source: str, *, started_at: str | None, analysis: dict, requests: dict[int, dict]) -> dict:
    result = result if isinstance(result, dict) else {}
    protocol = visit_protocol(result, source)
    protocol["closing_sends"] = closing_sends(protocol["stages"], requests)
    data = coverage()
    return {
        "protocol_version": protocol["protocol_version"],
        "conditions": conditions(result, source, started_at=started_at, analysis=analysis),
        "visit_protocol": protocol,
        "coverage": {"audited_with": data["audited_with"], "probe_apis": data["probe_apis"],
                     "contexts": data["contexts"], "closing_events": data["closing_events"]},
    }
