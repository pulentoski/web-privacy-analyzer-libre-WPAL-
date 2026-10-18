"""Resultados del analizador (F3): trackers, reporte y re-análisis.

La api no analiza: el análisis lo ejecuta el worker y aquí solo se lee. Re-analizar
es encolar (analysis_status='queued'); el worker lo toma sin volver a navegar.
"""

import json
import pathlib
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends
from jsonschema import Draft202012Validator
from sqlalchemy import and_, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.service_types import service_types

from app.attribute_usage import scan_table
from app.config import get_settings
from app.db import get_session
from app.destinations import build_destinations
from app.errors import AppError
from app.explain import explanations, glossary
from app.failures import failure, partial_navigation
from app import measurement
from app.models import RequestAnalysis, ScanRequest
from app.bands import BANDS, TRACKER_BANDS
from app.routes.scans import _get_job, _summary

router = APIRouter(prefix="/api/scans")

REPORT_SCHEMA_VERSION = "1.11.0"
INTERACTIVE_END_REASONS = ("user_stop", "idle_timeout", "max_duration", "max_requests", "window_closed", "browser_closed")


def interactive_section(result: dict) -> dict | None:
    """Línea de tiempo de una captura interactiva. Viene del sitio visitado: se revalida tipo y tamaño."""
    raw = result.get("interactive") if result.get("source") == "interactive" else None
    if not isinstance(raw, dict):
        return None
    timeline = []
    for entry in (raw.get("timeline") if isinstance(raw.get("timeline"), list) else [])[:300]:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        title = entry.get("title")
        timeline.append({
            "seq": len(timeline), "ts": str(entry.get("ts") or "")[:40], "url": entry["url"][:2048],
            "title": title[:512] if isinstance(title, str) else None, "tab": entry["tab"] if isinstance(entry.get("tab"), int) else 1,
        })
    masked = []
    for item in (raw.get("masked_fields") if isinstance(raw.get("masked_fields"), list) else [])[:200]:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("length"), int):
            masked.append({"name": item["name"][:128], "length": max(0, item["length"]), "seq": item["seq"] if isinstance(item.get("seq"), int) else None})
    limit = lambda key: raw[key] if isinstance(raw.get(key), int) else None  # noqa: E731
    return {
        "timeline": timeline, "timeline_truncated": raw.get("timeline_truncated") is True,
        "tabs": raw["tabs"] if isinstance(raw.get("tabs"), int) else 1,
        "end_reason": raw.get("end_reason") if raw.get("end_reason") in INTERACTIVE_END_REASONS else "user_stop",
        "idle_limit_s": limit("idle_limit_s"), "max_duration_s": limit("max_duration_s"),
        # v1.4.1: credenciales enmascaradas antes de guardar (nombre del campo y largo; nunca el valor).
        # None = captura anterior a v1.4.1: no se enmascaró nada.
        "masked_fields": masked if isinstance(raw.get("masked_fields"), list) else None,
    }
SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "schemas" / f"report-{REPORT_SCHEMA_VERSION}.schema.json"
UNKNOWN = "no_disponible"

LIMITATIONS = [
    "Los scores son estimaciones basadas en señales observables, no veredictos.",
    "Un recurso de terceros no es un tracker por sí solo, y un nombre de parámetro no prueba qué contiene.",
    "Los hallazgos de nivel INFERENCIA o POSIBLE no son hechos observados.",
    "Playwright no ve todo el tráfico del navegador (p. ej. favicon) y solo se capturan los cuerpos de las requests.",
    "El scan lo hace un Chromium automatizado, en una sola visita y normalmente sin interacción: un navegador real puede recibir más o menos tráfico.",
    "La entidad de un dominio viene de un mapa offline y puede faltar (\"no_disponible\") o estar desactualizada.",
    "\"Fingerprinting\" es siempre una inferencia a partir de un patrón de uso de APIs; solo son evidencia la llamada y el valor que aparece en una request.",
    # v1.5.0: lo que no cubre por contexto (workers, service workers, cierre de pestaña) sale de data/coverage.yaml.
    "La instrumentación no cubre OffscreenCanvas, y un sitio puede detectarla o falsear su propia atribución.",
    "El país y la red de un servidor se estiman a partir de su IP (DB-IP Lite): es una ubicación aproximada y no indica dónde se almacenan o procesan los datos.",
    "El estado TCF es lo que la propia plataforma de consentimiento declara; no se verifica que el sitio lo respete. gdprApplies depende de desde dónde se visita (aquí, la red del analizador).",
    "Consent Mode: `gcs` está documentado por Google; `gcd` se decodifica con una tabla no oficial que puede cambiar.",
    "CNAME cloaking: solo se revisan subdominios del propio sitio presentes en la captura, contra una lista corta de destinos conocidos.",
    "Este reporte describe hechos técnicos observados; no evalúa el cumplimiento de ninguna ley.",
    "La exfiltración solo se detecta si el valor viaja tal cual o como sha256/sha1/md5; otros hashes (p. ej. murmur) no se reconocen.",
]

# v1.4.9: se añade cuando la página creó conexiones WebRTC (hallazgo webrtc_connection).
WEBRTC_LIMITATION = ("El navegador de captura no tiene salida UDP; los candidatos ICE obtenidos por STUN (IP pública) no son "
                     "observables. Un visitante real podría exponerlos.")


def limitations_for(fingerprinting: dict | None) -> list[str]:
    """Límites de la medición de este scan: los fijos y los que dependen de lo observado."""
    fingerprinting = fingerprinting or {}
    heuristics = {item.get("heuristic") for item in fingerprinting.get("findings") or [] if isinstance(item, dict)}
    for script in fingerprinting.get("scripts") or []:
        heuristics |= {item.get("heuristic") for item in script.get("heuristics") or [] if isinstance(item, dict)}
    return LIMITATIONS + measurement.coverage_limitations() + ([WEBRTC_LIMITATION] if "webrtc_connection" in heuristics else [])


EVIDENCE_LEVELS = {
    "EVIDENCIA": "Hecho observado directamente en el tráfico o en el navegador durante la visita.",
    "INFERENCIA": "Conclusión razonable a partir de hechos observados; no fue observada directamente.",
    "POSIBLE": "Indicio débil: compatible con lo observado, pero con otras explicaciones plausibles.",
    "DESCONOCIDO": "No hay datos suficientes para afirmar nada.",
}
LEGAL_NOTICE = (
    "Este documento es un análisis técnico automatizado. No constituye asesoría legal ni una evaluación de "
    "cumplimiento normativo. Para decisiones legales consulte a un profesional."
)


def _manifest_version(directory: str, key: str) -> str:
    try:
        manifest = json.loads((pathlib.Path(get_settings().data_dir) / directory / "MANIFEST.json").read_text(encoding="utf-8"))
        return str(manifest["sources"][0].get(key) or UNKNOWN)
    except (OSError, ValueError, KeyError, IndexError):
        return UNKNOWN


LICENSE_PROFILES = {
    "no_comercial": "No comercial: incluye fuentes con licencia NC (mapa de entidades de DuckDuckGo) o sin licencia explícita (lista de CMP de IAB).",
    "comercial": "Comercial: sin fuentes NC ni sin licencia explícita. Organizaciones según AdGuard companiesdb (CC BY-SA 4.0); las CMP se identifican solo por número.",
}
CMP_EXCLUDED = "excluida (perfil comercial)"


def consent_section(consent: dict | None) -> dict:
    """Consentimiento del reporte. v1.4.10: `banner_interaction` (antes `user_interaction`, que traen los análisis
    anteriores y se lee con su nombre anterior): si el escenario pulsó un botón del aviso de consentimiento. No son los
    clics ni desplazamientos de la captura interactiva."""
    out = dict(consent) if isinstance(consent, dict) else {"tcf": None, "consent_mode": None}
    legacy = out.pop("user_interaction", None)
    out["banner_interaction"] = bool(out.get("banner_interaction", legacy))
    out.setdefault("tcf", None)
    out.setdefault("consent_mode", None)
    return out


def license_profile_of(summary: dict | None) -> str:
    """Perfil con el que se hizo el análisis. Los análisis anteriores a F9 usaron el no comercial."""
    profile = (summary or {}).get("license_profile")
    return profile if profile in LICENSE_PROFILES else "no_comercial"


def attributions(lists: list, profile: str = "no_comercial") -> list[dict]:
    known = {
        "easylist": ("EasyList", "https://easylist.to/", "Filtros de EasyList (The EasyList authors)."),
        "easyprivacy": ("EasyPrivacy", "https://easylist.to/", "Filtros de EasyPrivacy (The EasyList authors)."),
        "entity_map": ("DuckDuckGo Tracker Radar", "https://github.com/duckduckgo/tracker-radar", "Entity data from DuckDuckGo Tracker Radar, CC BY-NC-SA 4.0. Uso no comercial."),
        "companiesdb": ("AdGuard companiesdb", "https://github.com/AdguardTeam/companiesdb", "Company data from AdGuard companiesdb (based on whotracks.me), CC BY-SA 4.0."),
    }
    out = []
    for item in lists or []:
        if item.get("id") in known:
            name, url, note = known[item["id"]]
            out.append({"source": name, "license": str(item.get("license") or UNKNOWN), "text": note, "url": url, "noncommercial": bool(item.get("noncommercial"))})
    out.append({"source": "DB-IP Lite (país y ASN)", "license": "CC-BY-4.0", "text": "IP Geolocation by DB-IP", "url": "https://db-ip.com", "noncommercial": False})
    if profile != "comercial":
        out.append({"source": "Lista de CMP de IAB Europe", "license": "sin licencia explícita (ver data/iab/LICENSES.md)",
                    "text": "CMP list: IAB Europe Transparency & Consent Framework", "url": "https://iabeurope.eu/cmp-list/", "noncommercial": False})
    return out


@lru_cache
def report_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _domain_of(url: str | None) -> str | None:
    """Host de una URL de script, para buscar su giro (point 5). El resolutor hace la coincidencia por sufijo."""
    try:
        return urlsplit(url or "").hostname
    except ValueError:
        return None


async def _tracker_groups(session: AsyncSession, job_id: uuid.UUID) -> list[dict]:
    rows = (
        await session.execute(
            select(RequestAnalysis, ScanRequest.url, ScanRequest.registrable_domain)
            .join(ScanRequest, ScanRequest.id == RequestAnalysis.request_id)
            .where(
                RequestAnalysis.job_id == job_id,
                RequestAnalysis.band.in_(TRACKER_BANDS),
                # "Rastreadores" = terceros de OTRA organización (point 1). NULL (filas anteriores a
                # v1.2.1, aún sin reanalizar) cae al criterio antiguo por dominio.
                or_(
                    RequestAnalysis.party == "third_party",
                    and_(RequestAnalysis.party.is_(None), ScanRequest.third_party.is_(True)),
                ),
            )
            .order_by(RequestAnalysis.score.desc(), ScanRequest.seq)
        )
    ).all()
    resolver = service_types()
    summary = await session.scalar(text("SELECT summary FROM site_analysis WHERE job_id = :job_id"), {"job_id": job_id}) or {}
    server_side = {item["domain"]: item.get("label") for item in summary.get("server_side") or []
                   if isinstance(item, dict) and item.get("domain") and item.get("label")}
    groups: dict[tuple, dict] = {}
    for analysis, url, domain in rows:
        # Sin entidad conocida no se agrupan dominios distintos: no hay evidencia de que sean lo mismo.
        key = (analysis.entity,) if analysis.entity != UNKNOWN else (UNKNOWN, domain)
        group = groups.setdefault(
            key,
            {"entity": analysis.entity, "domains": [], "request_count": 0, "max_score": 0, "categories": [],
             "service_type": None, "service_label": None, "requests": []},
        )
        if domain and domain not in group["domains"]:
            group["domains"].append(domain)
        if analysis.category not in group["categories"]:
            group["categories"].append(analysis.category)
        group["request_count"] += 1
        group["max_score"] = max(group["max_score"], analysis.score)
        group["requests"].append(
            {
                "request_id": analysis.request_id,
                "url": url,
                "score": analysis.score,
                "band": analysis.band,
                "category": analysis.category,
                "mechanism": analysis.mechanism,
                "reasons": analysis.reasons,
                # Frase técnica de la request (F10): qué pasó, antes del detalle.
                "plain": explanations().request_phrase(reasons=analysis.reasons, entity=analysis.entity, domain=domain, third_party=True,
                                                       party=analysis.party),
            }
        )
    out = []
    for group in groups.values():
        group["max_band"] = max((request["band"] for request in group["requests"]), key=BANDS.index)
        # Giro del servicio (point 5): por organización o, si no, por el primer dominio del grupo.
        service = resolver.of(entity=group["entity"], domain=next(iter(sorted(group["domains"])), None),
                              urls=[request["url"] for request in group["requests"][:200]])
        if service is None and set(group["domains"]) & set(server_side):
            # Host de nube genérico con señales de eventos de Meta (v1.4.2): inferencia, no dueño conocido.
            service = {"type": "server_side_meta", "label": server_side[next(iter(set(group["domains"]) & set(server_side)))]}
        if service:
            group["service_type"], group["service_label"] = service["type"], service["label"]
        out.append(group)
    return sorted(out, key=lambda group: (-group["max_score"], -group["request_count"], group["entity"]))


async def _site_analysis(session: AsyncSession, job_id: uuid.UUID):
    return (
        await session.execute(text("SELECT * FROM site_analysis WHERE job_id = :job_id"), {"job_id": job_id})
    ).mappings().one_or_none()


# Heurísticas que hacen que un script cuente como "fingerprinting inferido".
FP_INFERRED = frozenset(
    {"canvas_fingerprinting", "font_enumeration", "audio_fingerprinting", "webgl_fingerprinting", "webrtc_ip_discovery",
     "property_sweep"}
)


async def _fingerprinting(session: AsyncSession, job) -> dict:
    """Por script: APIs usadas, conteos y heurísticas; estado por atributo; exfiltraciones."""
    meta = ((job.result or {}).get("capture") or {}).get("fingerprinting")
    params = {"job_id": job.id}
    calls = (
        await session.execute(
            text(
                # Misma regla que script_key() del analizador: sin URL de script, se atribuye al frame.
                "WITH calls AS (SELECT job_id, api, count, CASE WHEN script_url <> '' THEN script_url "
                " WHEN frame_url <> '' THEN '(inline o eval en ' || split_part(split_part(frame_url, '?', 1), '#', 1) || ')' "
                # Las escuchas de eventos (events.*, v1.4.2) no son lecturas de atributos: van en «Registro de interacción».
                " ELSE '' END AS script_url FROM fp_api_calls WHERE job_id = :job_id AND api NOT LIKE 'events.%' AND frame_url NOT LIKE 'chrome-error://%' AND script_url NOT LIKE 'chrome-error://%') "
                "SELECT c.script_url, c.api, sum(c.count) AS count, "
                "(SELECT a.entity FROM scan_requests r JOIN request_analysis a ON a.request_id = r.id "
                " WHERE r.job_id = c.job_id AND r.url = c.script_url LIMIT 1) AS entity, "
                # El «script» es un documento: son los scripts inline de esa página o frame (v1.4.2).
                "EXISTS (SELECT 1 FROM scan_requests r WHERE r.job_id = c.job_id AND r.url = c.script_url AND r.resource_type = 'document') AS is_document "
                "FROM calls c GROUP BY c.job_id, c.script_url, c.api ORDER BY c.script_url, c.api"
            ),
            params,
        )
    ).mappings().all()
    findings = (
        await session.execute(
            text(
                "SELECT script_url, heuristic, level, claim, call_refs, request_refs, details FROM fp_findings "
                "WHERE job_id = :job_id ORDER BY id"
            ),
            params,
        )
    ).mappings().all()
    attributes = (
        await session.execute(
            text(
                "SELECT attribute, status, value, scripts, call_refs, request_refs FROM fp_attributes "
                "WHERE job_id = :job_id ORDER BY id"
            ),
            params,
        )
    ).mappings().all()

    def finding(row) -> dict:
        return {
            "script_url": row["script_url"],
            "heuristic": row["heuristic"],
            "level": row["level"],
            "claim": row["claim"],
            "evidence_refs": {"calls": row["call_refs"], "requests": row["request_refs"]},
            "details": row["details"],
        }

    resolver = service_types()
    inline = await _inline_owners(session, job.id)
    scripts: dict[str, dict] = {}
    for row in calls:
        # Script inline o eval (v1.4.2): es código del documento donde corrió; se atribuye a su organización.
        entity = row["entity"] if row["entity"] and row["entity"] != UNKNOWN else None
        if entity is None:
            entity = inline.get(row["script_url"]) or ((_host_of(row["script_url"]) or None) if row["is_document"] else None) or UNKNOWN
        service = resolver.of(entity=entity, domain=_domain_of(row["script_url"]))
        script = scripts.setdefault(
            row["script_url"],
            {"script_url": row["script_url"], "entity": entity, "apis": [], "total_calls": 0,
             # Giro del servicio (point 5): contexto, no evidencia del uso concreto.
             "service_type": service["type"] if service else None,
             "service_label": service["label"] if service else None,
             "fingerprinting_inferred": False, "heuristics": []},
        )
        script["apis"].append({"api": row["api"], "count": row["count"]})
        script["total_calls"] += row["count"]
    for row in findings:
        if row["heuristic"] == "exfiltration" or row["script_url"] not in scripts:
            continue
        scripts[row["script_url"]]["heuristics"].append(finding(row))
        if row["heuristic"] in FP_INFERRED and row["script_url"]:
            scripts[row["script_url"]]["fingerprinting_inferred"] = True
    return {
        # false = scan sin instrumentación: listas vacías NO significan "sin fingerprinting".
        "instrumented": meta is not None,
        "truncated": meta.get("truncated") if meta else None,
        "rejected_events": meta.get("rejected") if meta else None,
        "scripts": sorted(scripts.values(), key=lambda s: (not s["fingerprinting_inferred"], -s["total_calls"], s["script_url"])),
        "attributes": [
            {"attribute": row["attribute"], "status": row["status"], "value": row["value"], "scripts": row["scripts"],
             "evidence_refs": {"calls": row["call_refs"], "requests": row["request_refs"]}}
            for row in attributes
        ],
        "exfiltrations": [finding(row) for row in findings if row["heuristic"] == "exfiltration"],
    }


@router.get("/{job_id}/fingerprinting")
async def get_fingerprinting(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    job = await _get_job(session, job_id)
    # Las llamadas crudas, para poder seguir un evidence_ref "calls" hasta su fila.
    calls = (
        await session.execute(
            text(
                "SELECT id AS call_id, api, script_url, frame_url, count, details FROM fp_api_calls "
                "WHERE job_id = :job_id AND frame_url NOT LIKE 'chrome-error://%' AND script_url NOT LIKE 'chrome-error://%' "
                "ORDER BY id LIMIT 2000"
            ),
            {"job_id": job_id},
        )
    ).mappings().all()
    return {
        "job_id": str(job_id),
        "analysis_status": job.analysis_status,
        **await _fingerprinting(session, job),
        # Tabla «Atributos de su navegador que leyó este sitio» (v1.2): atributo · leído por · enviado a.
        "browser_attributes": await scan_table(session, job_id, await _inline_owners(session, job_id)),
        "calls": [dict(row) for row in calls],
        # v1.4.5: recuadros que no cargaron (página de error de Chromium); sus llamadas no se cuentan.
        "error_frames": ((await _site_analysis(session, job_id) or {}).get("summary") or {}).get("error_frames"),
    }


@router.get("/{job_id}/findings")
async def get_findings(
    job_id: uuid.UUID,
    level: Literal["EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO"] | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Todos los hallazgos del scan (generales y de fingerprinting) con sus referencias."""
    job = await _get_job(session, job_id)
    rows = await _all_findings(session, job_id)
    entities, scripts = await _entity_maps(session, job_id)
    explainer = explanations()
    items = []
    for row in rows:
        if level is not None and row["level"] != level:
            continue
        phrase = explainer.finding_phrase(row, entities, scripts)
        items.append({
            "id": row["id"], "kind": row["kind"], "type": row["type"], "level": row["level"], "claim": row["claim"],
            "script_url": row["script_url"], "evidence_refs": row["evidence_refs"],
            # Frase técnica, del mismo nivel que el hallazgo, y paso de «Hallazgos por grupo».
            "plain": phrase["text"], "step": phrase["step"],
            # Organizaciones del hallazgo: con el tipo y el nivel forman la clave de agrupación (v1.4.2).
            "organizations": sorted({name for name in phrase["companies"] if name}),
        })
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["level"]] = counts.get(row["level"], 0) + 1
    return {"job_id": str(job_id), "analysis_status": job.analysis_status, "by_level": counts, "items": items,
            "groups": group_findings(items)}


def group_findings(items: list[dict]) -> list[dict]:
    """Hallazgos repetidos en una fila (v1.4.2): mismo tipo, mismo nivel y mismas organizaciones.

    Cada grupo dice cuántos hallazgos reúne (cada uno es un valor, parámetro o script distinto) y cuántas
    requests y llamadas distintas los respaldan. `items` son índices en la lista de hallazgos: nada se pierde.
    """
    groups: dict[tuple, dict] = {}
    for index, item in enumerate(items):
        key = (item["type"], item["level"], tuple(item["organizations"]))
        group = groups.setdefault(key, {
            "type": item["type"], "level": item["level"], "organizations": item["organizations"], "step": item["step"],
            "plain": item["plain"], "items": [], "_requests": set(), "_calls": set(),
        })
        group["items"].append(index)
        group["_requests"].update(item["evidence_refs"].get("requests") or [])
        group["_calls"].update(item["evidence_refs"].get("calls") or [])
    out = []
    for group in groups.values():
        out.append({**{key: value for key, value in group.items() if not key.startswith("_")},
                    "count": len(group["items"]), "requests": len(group["_requests"]), "calls": len(group["_calls"])})
    return out


async def _all_findings(session: AsyncSession, job_id: uuid.UUID) -> list[dict]:
    """Hallazgos generales y de fingerprinting con la misma forma: {key, kind, type, level, claim, evidence_refs, details}."""
    rows = (
        await session.execute(
            text(
                "SELECT id, 'general' AS kind, type, level, claim, '[]'::jsonb AS call_refs, evidence_refs AS request_refs, "
                "NULL AS script_url, details FROM findings WHERE job_id = :job_id "
                "UNION ALL SELECT id, 'fingerprinting', heuristic, level, claim, call_refs, request_refs, script_url, details "
                "FROM fp_findings WHERE job_id = :job_id ORDER BY kind, id"
            ),
            {"job_id": job_id},
        )
    ).mappings().all()
    return [
        {
            "id": row["id"], "key": f"{row['kind']}-{row['id']}", "kind": row["kind"], "type": row["type"], "level": row["level"],
            "claim": row["claim"], "script_url": row["script_url"], "details": row["details"] or {},
            "evidence_refs": {"calls": row["call_refs"], "requests": row["request_refs"]},
        }
        for row in rows
    ]


async def _entity_maps(session: AsyncSession, job_id: uuid.UUID) -> tuple[dict[str, str], dict[str, str]]:
    """(dominio registrable → organización, URL de script → organización) de este scan."""
    rows = (
        await session.execute(
            text(
                "SELECT r.registrable_domain AS domain, r.url, a.entity FROM scan_requests r "
                "JOIN request_analysis a ON a.request_id = r.id WHERE r.job_id = :job_id AND a.entity <> 'no_disponible'"
            ),
            {"job_id": job_id},
        )
    ).mappings().all()
    scripts = {row["url"]: row["entity"] for row in rows if row["url"]}
    scripts.update(await _inline_owners(session, job_id))
    return {row["domain"]: row["entity"] for row in rows if row["domain"]}, scripts


INLINE_PREFIX = "(inline o eval en "


def _host_of(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


async def _inline_owners(session: AsyncSession, job_id: uuid.UUID) -> dict[str, str]:
    """«(inline o eval en <documento>)» → organización del documento; si no se conoce, su host.

    Un script sin URL propia es código de la página (o del frame) donde corrió: su dueño es el de ese documento.
    """
    frames = (
        await session.execute(
            text("SELECT DISTINCT split_part(split_part(frame_url, '?', 1), '#', 1) AS frame FROM fp_api_calls "
                 "WHERE job_id = :job_id AND script_url = '' AND frame_url <> '' AND frame_url NOT LIKE 'chrome-error://%' LIMIT 500"),
            {"job_id": job_id},
        )
    ).scalars().all()
    if not frames:
        return {}
    hosts = {
        row["host"]: row["entity"] for row in (
            await session.execute(
                text("SELECT r.host, max(a.entity) FILTER (WHERE a.entity <> 'no_disponible') AS entity FROM scan_requests r "
                     "LEFT JOIN request_analysis a ON a.request_id = r.id WHERE r.job_id = :job_id AND r.host IS NOT NULL GROUP BY r.host"),
                {"job_id": job_id},
            )
        ).mappings().all()
    }
    out = {}
    for frame in frames:
        try:
            host = (urlsplit(frame).hostname or "").lower()
        except ValueError:
            host = ""
        if host:
            out[f"{INLINE_PREFIX}{frame})"] = hosts.get(host) or host
    return out


async def _script_call_refs(session: AsyncSession, job_id: uuid.UUID) -> dict[str, list[int]]:
    """Llamadas registradas de cada script (misma regla de atribución que script_key() del analizador)."""
    rows = (
        await session.execute(
            text(
                "SELECT CASE WHEN script_url <> '' THEN script_url WHEN frame_url <> '' THEN "
                "'(inline o eval en ' || split_part(split_part(frame_url, '?', 1), '#', 1) || ')' ELSE '' END AS script, "
                "array_agg(id ORDER BY id) AS calls FROM fp_api_calls WHERE job_id = :job_id AND api NOT LIKE 'events.%' AND frame_url NOT LIKE 'chrome-error://%' AND script_url NOT LIKE 'chrome-error://%' GROUP BY 1"
            ),
            {"job_id": job_id},
        )
    ).mappings().all()
    return {row["script"]: list(row["calls"]) for row in rows}


async def build_story(session: AsyncSession, job_id: uuid.UUID, fingerprinting: dict, destinations: dict, source: str = "scan") -> dict:
    """«Hallazgos por grupo»: los hallazgos del scan ordenados en pasos fijos (F10; ocho desde v1.4.2)."""
    explainer = explanations()
    entities, scripts = await _entity_maps(session, job_id)
    findings = await _all_findings(session, job_id)
    # Lecturas de APIs por script: EVIDENCIA de «revisaron su equipo», aparte de la inferencia.
    findings += explainer.fp_reads(fingerprinting.get("scripts") or [], await _script_call_refs(session, job_id))
    for item in (destinations.get("cname_cloaking") or {}).get("findings") or []:
        findings.append({
            "key": None, "kind": "general", "type": "cname_cloaking", "level": item.get("level"), "claim": item.get("claim"),
            "script_url": None, "details": {key: item.get(key) for key in ("host", "cname_target", "organization")},
            "evidence_refs": {"requests": item.get("evidence_refs") or [], "calls": []},
        })
    return explainer.story(findings, entities, scripts, source)



@router.get("/{job_id}/domains")
async def get_domains(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    """Un nodo por dominio registrable, para el grafo sitio → categoría → organización → dominio."""
    job = await _get_job(session, job_id)
    rows = (
        await session.execute(
            text(
                "SELECT r.registrable_domain AS domain, bool_or(COALESCE(a.party = 'third_party', r.third_party)) AS third_party, "
                "bool_or(a.party = 'same_org') AS same_org, count(*) AS requests, "
                "max(a.score) AS max_score, mode() WITHIN GROUP (ORDER BY a.category) AS category, "
                "max(a.entity) FILTER (WHERE a.entity <> 'no_disponible') AS entity, "
                "count(*) FILTER (WHERE a.band = ANY(:tracker_bands)) AS tracker_requests, "
                "bool_or(a.reasons @> '[{\"signal\": \"fp_script\"}]' OR a.reasons @> '[{\"signal\": \"fp_exfiltration\"}]' "
                " OR a.reasons @> '[{\"signal\": \"fp_script_initiator\"}]') AS fingerprinting "
                "FROM scan_requests r LEFT JOIN request_analysis a ON a.request_id = r.id "
                "WHERE r.job_id = :job_id AND r.registrable_domain IS NOT NULL "
                "GROUP BY r.registrable_domain ORDER BY count(*) DESC LIMIT 300"
            ),
            {"job_id": job_id, "tracker_bands": list(TRACKER_BANDS)},
        )
    ).mappings().all()
    return {
        "job_id": str(job_id),
        "analysis_status": job.analysis_status,
        "domains": [
            {
                "domain": row["domain"], "third_party": bool(row["third_party"]),
                "party": "third_party" if row["third_party"] else "same_org" if row["same_org"] else "first_party",
                "requests": row["requests"],
                "max_score": row["max_score"], "category": row["category"], "entity": row["entity"] or UNKNOWN,
                "tracker_requests": row["tracker_requests"], "tracker": row["tracker_requests"] > 0,
                "fingerprinting": bool(row["fingerprinting"]),
            }
            for row in rows
        ],
    }


@router.get("/{job_id}/trackers")
async def get_trackers(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    job = await _get_job(session, job_id)
    groups = await _tracker_groups(session, job_id)
    return {
        "job_id": str(job_id),
        "analysis_status": job.analysis_status,
        "min_band": TRACKER_BANDS[0],
        "tracker_requests": sum(group["request_count"] for group in groups),
        "entities": groups,
    }


@router.post("/{job_id}/reanalyze", status_code=202)
async def reanalyze(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    job = await _get_job(session, job_id)
    updated = await session.scalar(
        text(
            "UPDATE jobs SET analysis_status = 'queued', updated_at = now() "
            "WHERE id = :job_id AND status IN ('completed', 'failed') "
            "AND analysis_status IS DISTINCT FROM 'running' "
            "AND EXISTS (SELECT 1 FROM scan_requests WHERE job_id = :job_id) RETURNING id"
        ),
        {"job_id": job_id},
    )
    await session.commit()
    if updated is None:
        if job.analysis_status == "running":
            raise AppError("ANALYSIS_RUNNING", "Ya hay un análisis en curso para este scan.", stage="analysis", status_code=409)
        raise AppError("NO_CAPTURE", "El scan no tiene una captura guardada que analizar.", stage="analysis", status_code=409)
    return {"job_id": str(job_id), "analysis_status": "queued"}


@router.get("/{job_id}/destinations")
async def get_destinations(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    """IP, red y país de cada dominio contactado, y CNAME cloaking (F8)."""
    job = await _get_job(session, job_id)
    return {"job_id": str(job_id), **await build_destinations(session, job)}


@router.get("/{job_id}/report")
async def get_report(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    return await build_report(session, job_id)


async def _measurement(session: AsyncSession, job, result: dict, source: str, site: dict) -> dict:
    """Sección measurement. Los envíos del cierre se describen con lo mínimo (seq, método, host, ruta, tipo)."""
    seqs = [seq for stage in measurement.visit_protocol(result, source)["stages"] if stage["name"] == "cierre"
            for seq in stage["request_seqs"]]
    requests = {}
    if seqs:
        rows = (
            await session.execute(
                text("SELECT seq, method, host, path, resource_type FROM scan_requests WHERE job_id = :job_id AND seq = ANY(:seqs) ORDER BY seq"),
                {"job_id": job.id, "seqs": seqs},
            )
        ).mappings().all()
        requests = {row["seq"]: {"seq": row["seq"], "method": row["method"], "host": row["host"], "path": row["path"],
                                 "resource_type": row["resource_type"]} for row in rows}
    return measurement.section(result, source, started_at=job.started_at.isoformat() if job.started_at else None,
                               analysis=site, requests=requests)


async def build_report(session: AsyncSession, job_id: uuid.UUID) -> dict:
    job = await _get_job(session, job_id)
    site = await _site_analysis(session, job_id)
    if site is None:
        raise AppError(
            "ANALYSIS_NOT_READY",
            "El scan aún no tiene análisis.",
            stage="analysis",
            status_code=409,
            details={"status": job.status, "analysis_status": job.analysis_status},
        )
    result = job.result or {}
    summary = await _summary(session, job)
    profile = license_profile_of(site["summary"])
    findings = (
        await session.execute(
            text("SELECT type, claim, level, evidence_refs, details FROM findings WHERE job_id = :job_id ORDER BY id"),
            {"job_id": job_id},
        )
    ).mappings().all()
    entities, scripts = await _entity_maps(session, job_id)
    fingerprinting = await _fingerprinting(session, job)
    destinations = await build_destinations(session, job)
    source = result.get("source") if result.get("source") in ("har_import", "interactive") else "scan"
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "job_id": str(job.id),
            "url": job.url,
            "final_url": result.get("final_url") or UNKNOWN,
            "status": job.status,
            "http_status": result.get("http_status"),
            "title": result.get("title"),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            # scan = navegador del worker · har_import = captura importada del navegador real del usuario (v1.3).
            # interactive = captura interactiva: el usuario navegó en el Chromium del worker (v1.4).
            "source": result.get("source") if result.get("source") in ("har_import", "interactive") else "scan",
            "import": result.get("import") if result.get("source") == "har_import" else None,
            "interactive": interactive_section(result),
            # v1.4.8 (docs/adr/035): scan fallido = sin medición; scan parcial = goto agotó el tiempo con respuestas.
            "failure": failure(job.status, job.error),
            "partial_navigation": partial_navigation(result),
        },
        "analysis": {
            "analyzer_version": site["analyzer_version"],
            "lists_version": site["lists_version"],
            "lists": site["lists"],
            "analyzed_at": site["analyzed_at"].isoformat(),
            "partial": site["partial"],
            "duration_ms": site["duration_ms"],
        },
        "site": {
            "exposure_score": site["score"],
            "band": site["band"],
            "breakdown": site["breakdown"],
            "data_categories": site["data_categories"],
            "mechanisms": site["mechanisms"],
            "summary": {**(site["summary"] or {}), **({"consent": consent_section(site["summary"]["consent"])}
                                                      if isinstance((site["summary"] or {}).get("consent"), dict) else {})},
        },
        "capture": {
            key: summary[key]
            for key in ("total_requests", "first_party", "third_party", "same_org", "blocked", "blocked_by_client", "capture_truncated")
        },
        "trackers": await _tracker_groups(session, job_id),
        "findings": [{**dict(finding), "plain": explanations().finding_phrase(dict(finding), entities, scripts)["text"]} for finding in findings],
        # «Hallazgos por grupo»: los mismos hallazgos, en pasos fijos y con frase técnica (F10).
        "story": await build_story(session, job_id, fingerprinting, destinations,
                                   result.get("source") if result.get("source") in ("har_import", "interactive") else "scan"),
        "fingerprinting": fingerprinting,
        "consent": consent_section((site["summary"] or {}).get("consent")),
        "destinations": destinations,
        "versions": {
            "analyzer": site["analyzer_version"], "lists": site["lists_version"],
            "ip_database": f"DB-IP Lite {_manifest_version('ipdb', 'edition')}",
            "cmp_list": CMP_EXCLUDED if profile == "comercial" else _manifest_version("iab", "version"),
        },
        # v1.5.0 (docs/adr/038): condiciones de la medición, protocolo de visita y cobertura por contexto.
        "measurement": await _measurement(session, job, result, source, site),
        "license_profile": profile,
        "attributions": attributions(site["lists"], profile),
        "evidence_levels": EVIDENCE_LEVELS,
        "legal_notice": LEGAL_NOTICE,
        "masked": False,
        "limitations": limitations_for(fingerprinting),
    }
    errors = sorted(report_validator().iter_errors(report), key=lambda error: list(error.absolute_path))
    if errors:
        # Un reporte que no cumple su schema no se entrega.
        raise AppError(
            "REPORT_INVALID",
            "El reporte generado no cumple el schema.",
            stage="report",
            status_code=500,
            details={"schema_version": REPORT_SCHEMA_VERSION, "errors": [error.message[:200] for error in errors[:5]]},
        )
    return report
