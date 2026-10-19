"""HAR: importar una captura del navegador del usuario, exportar un scan y comparar ambos (v1.3)."""

import bisect
import json
import pathlib
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlsplit

import yaml
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import har_import
from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.measurement import protocol_version
from app.models import HarImport, Job, ScanRequest
from app.proxy_headers import is_proxy_header
from app.ratelimit import client_ip, scan_limiter
from app.routes.scans import BLOCKED_BY_CLIENT, _get_job, _serialize
from app.version import APP_VERSION

router = APIRouter(prefix="/api", tags=["har"])

UNKNOWN = "no_disponible"
SOURCE_HAR = "har_import"
EXPORT_SENSITIVE = frozenset(har_import.SENSITIVE_HEADERS)
MAX_EXPORT_REQUESTS = 5000


def job_source(job) -> str:
    return SOURCE_HAR if (job.options or {}).get("source") == SOURCE_HAR else "scan"


async def _read_har(request: Request) -> bytes:
    """Cuerpo de la request con tope de tamaño: se corta en cuanto lo supera, sin leerlo entero."""
    limit = get_settings().har_max_bytes
    too_large = AppError(
        "HAR_TOO_LARGE", f"El archivo supera el máximo de {limit // (1024 * 1024)} MB.", stage="har_validation", status_code=413,
        details={"max_bytes": limit},
    )
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise too_large
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise too_large
        chunks.append(chunk)
    if size == 0:
        raise har_import.invalid("El archivo está vacío.")
    return b"".join(chunks)


@router.post("/har/inspect")
async def inspect_har(request: Request) -> dict:
    """Qué trae el HAR (cargas, bloqueos, cabeceras sensibles). No guarda nada."""
    return har_import.inspect(await _read_har(request))


@router.post("/har/import", status_code=202)
async def import_har(request: Request, load: str | None = None, name: str | None = None,
                     session: AsyncSession = Depends(get_session)) -> dict:
    """Guarda la carga elegida, ya depurada, y la encola para el mismo analizador que un scan."""
    settings = get_settings()
    raw = await _read_har(request)
    imported = har_import.build_import(raw, load[:64] if load else None, name)
    del raw  # el archivo original no se conserva
    retry_after = scan_limiter.check(client_ip(request), settings.scan_rate_limit, settings.scan_rate_window_s)
    if retry_after is not None:
        raise AppError(
            "RATE_LIMITED", f"Demasiados scans desde esta dirección. Máximo {settings.scan_rate_limit} cada {settings.scan_rate_window_s} segundos.",
            stage="rate_limit", status_code=429,
            details={"limit": settings.scan_rate_limit, "window_s": settings.scan_rate_window_s, "retry_after_s": round(retry_after, 1)},
        )
    queued = await session.scalar(select(func.count()).select_from(Job).where(Job.status == "queued"))
    if queued >= settings.max_queued_jobs:
        raise AppError("QUEUE_FULL", "Hay demasiados scans en cola. Intenta de nuevo en unos minutos.", stage="queue", status_code=429,
                       details={"queued": queued, "max_queued_jobs": settings.max_queued_jobs})
    job = Job(url=imported["page_url"], original_url=imported["page_url"], options={"source": SOURCE_HAR})
    session.add(job)
    await session.flush()
    session.add(HarImport(job_id=job.id, payload=imported))
    await session.commit()
    await session.refresh(job)
    return {**_serialize(job), "import": imported["meta"]}


# --- exportar ---

def _export_headers(headers: list | None, include_sensitive: bool) -> tuple[list[dict], int]:
    out, removed = [], 0
    for header in headers or []:
        if not isinstance(header, dict) or not isinstance(header.get("name"), str):
            continue
        if is_proxy_header(header["name"]):
            continue  # del navegador con el egress-proxy: no se exporta nunca, ni con include_sensitive (v1.5.3)
        if header["name"].lower() in EXPORT_SENSITIVE and (not include_sensitive or header.get("redacted")):
            removed += 1
            continue
        out.append({"name": header["name"], "value": str(header.get("value") or "")})
    return out, removed


def _export_pages(job, first_ts):
    """(log.pages, función ts → pageref). Captura interactiva (v1.4.2): una página por cada página visitada;
    cada entrada va con la última página cargada antes de ella. Un scan tiene una sola página."""
    started = first_ts.astimezone(timezone.utc)
    timeline = ((job.result or {}).get("interactive") or {}).get("timeline") if (job.options or {}).get("source") == "interactive" else None
    marks = []
    for entry in timeline if isinstance(timeline, list) else []:
        try:
            when = datetime.fromisoformat(entry["ts"]) if isinstance(entry, dict) and isinstance(entry.get("url"), str) else None
        except (KeyError, TypeError, ValueError):
            when = None
        if when is not None:
            marks.append((when if when.tzinfo else when.replace(tzinfo=timezone.utc), entry))
    marks.sort(key=lambda item: item[0])
    if not marks:
        return [{"id": "page_1", "startedDateTime": started.isoformat(), "title": job.url, "pageTimings": {}}], lambda ts: "page_1"
    pages = [{"id": f"page_{index}", "startedDateTime": when.astimezone(timezone.utc).isoformat(),
              "title": str(entry.get("title") or entry["url"])[:512], "pageTimings": {},
              "comment": f"{str(entry['url'])[:2048]} · pestaña {entry.get('tab') if isinstance(entry.get('tab'), int) else 1}"}
             for index, (when, entry) in enumerate(marks, start=1)]
    stamps = [when for when, _ in marks]

    def page_of(ts) -> str:
        index = bisect.bisect_right(stamps, ts)
        return f"page_{max(1, index)}"  # lo anterior a la primera navegación registrada va con la primera página

    return pages, page_of


@router.get("/scans/{job_id}/har")
async def export_har(job_id: uuid.UUID, include_sensitive: bool = False, session: AsyncSession = Depends(get_session)) -> Response:
    """El scan como HAR 1.2. Por defecto sin Cookie, Set-Cookie ni Authorization."""
    job = await _get_job(session, job_id)
    rows = (
        await session.execute(select(ScanRequest).where(ScanRequest.job_id == job_id).order_by(ScanRequest.seq).limit(MAX_EXPORT_REQUESTS))
    ).scalars().all()
    if not rows:
        raise AppError("CAPTURE_NOT_READY", "El scan aún no tiene captura para exportar.", stage="export", status_code=409)
    removed_total, entries = 0, []
    pages, page_of = _export_pages(job, rows[0].ts)
    for row in rows:
        request_headers, removed_request = _export_headers(row.request_headers, include_sensitive)
        response_headers, removed_response = _export_headers(row.response_headers, include_sensitive)
        removed_total += removed_request + removed_response
        sizes, timing = row.sizes or {}, row.timing or {}
        request = {
            "method": row.method or "GET", "url": row.url or "", "httpVersion": "", "cookies": [], "headers": request_headers,
            "queryString": [{"name": pair[0] or "", "value": pair[1] or ""} for pair in row.query_params or [] if isinstance(pair, list) and len(pair) == 2],
            "headersSize": sizes.get("requestHeadersSize", -1), "bodySize": row.post_data_size if row.post_data_size is not None else 0,
        }
        if row.post_data is not None:
            content_type = next((h["value"] for h in request_headers if h["name"].lower() == "content-type"), "")
            request["postData"] = {"mimeType": content_type, "text": row.post_data}
            if row.post_data_encoding == "base64":
                request["postData"]["_encoding"] = "base64"
            if row.post_data_truncated:
                request["postData"]["comment"] = "Cuerpo truncado en la captura."
        response = {
            "status": row.response_status or 0, "statusText": "", "httpVersion": "", "cookies": [], "headers": response_headers,
            "content": {"size": sizes.get("responseBodySize", -1), "mimeType": row.mime_type or ""}, "redirectURL": "",
            "headersSize": sizes.get("responseHeadersSize", -1), "bodySize": sizes.get("responseBodySize", -1),
        }
        if row.failure_text:
            response["_error"] = row.failure_text
        duration = timing.get("time_ms")
        if duration is None and isinstance(timing.get("responseEnd"), (int, float)) and timing["responseEnd"] >= 0:
            duration = timing["responseEnd"]
        entries.append({
            "pageref": page_of(row.ts), "startedDateTime": row.ts.astimezone(timezone.utc).isoformat(), "time": duration if duration is not None else -1,
            "request": request, "response": response, "cache": {},
            "timings": {"send": -1, "wait": -1, "receive": -1},
            **({"_resourceType": row.resource_type} if row.resource_type else {}),
        })
    document = {"log": {
        "version": "1.2",
        "creator": {"name": "Web Privacy & Tracker Analyzer", "version": APP_VERSION},
        "pages": pages,
        "entries": entries,
        "comment": (
            "Exportado con las cabeceras Cookie, Set-Cookie y Authorization." if include_sensitive else
            f"Exportado sin las cabeceras Cookie, Set-Cookie ni Authorization ({removed_total} omitidas)."
        ),
    }}
    return Response(
        content=json.dumps(document, ensure_ascii=False, default=str), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan-{job_id}.har"', "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )


# --- comparar scan vs HAR importado ---

@lru_cache
def _comparison_templates() -> dict:
    path = pathlib.Path(get_settings().data_dir) / "har_signals.yaml"
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("comparison") or {}


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


async def _side(session: AsyncSession, job: Job) -> dict:
    site = (
        await session.execute(text("SELECT analyzer_version, summary FROM site_analysis WHERE job_id = :job_id"), {"job_id": job.id})
    ).mappings().one_or_none()
    if site is None:
        raise AppError("ANALYSIS_NOT_READY", "Uno de los dos scans aún no tiene análisis.", stage="analysis", status_code=409,
                       details={"job_id": str(job.id)})
    rows = (
        await session.execute(
            text(
                # Solo terceros = otra organización (request_analysis.party). Sin dueño conocido, el dominio hace de organización.
                "SELECT COALESCE(NULLIF(a.entity, 'no_disponible'), r.registrable_domain) AS organization, count(*) AS requests, "
                "count(*) FILTER (WHERE r.failure_text LIKE :blocked) AS blocked, "
                "array_agg(DISTINCT r.registrable_domain) AS domains "
                "FROM scan_requests r JOIN request_analysis a ON a.request_id = r.id "
                "WHERE r.job_id = :job_id AND a.party = 'third_party' AND r.registrable_domain IS NOT NULL GROUP BY 1"
            ),
            {"job_id": job.id, "blocked": f"%{BLOCKED_BY_CLIENT}%"},
        )
    ).mappings().all()
    total = await session.scalar(select(func.count()).select_from(ScanRequest).where(ScanRequest.job_id == job.id))
    summary = site["summary"] or {}
    return {
        "job_id": str(job.id), "url": job.url, "source": job_source(job), "analyzer_version": site["analyzer_version"],
        "finished_at": job.finished_at, "requests": total,
        # v1.5.0: protocolo de visita del scan; None = sin protocolo (HAR, captura interactiva o scan anterior a v1.5.0).
        "protocol_version": protocol_version(job.result),
        "import": (job.result or {}).get("import") if job_source(job) == SOURCE_HAR else None,
        # None = análisis anterior a v1.3 (sin la medición): hay que reanalizar, no se inventa «sin ola».
        "sync_wave": summary.get("sync_wave"),
        # v1.3.1: la comparación usa requests de rastreo y organizaciones, no el índice (el del HAR es parcial).
        "trackers": summary.get("trackers"),
        "possibly_blocked": bool((summary.get("blocking") or {}).get("blocked")),
        "organizations": {row["organization"]: {"requests": row["requests"], "blocked": row["blocked"], "domains": sorted(row["domains"])[:8]}
                          for row in rows},
    }


def _render(template: str | None, values: dict) -> str | None:
    try:
        return template.format(**values) if template else None
    except (KeyError, IndexError, ValueError):
        return None


def compare_sides(scan: dict, har: dict) -> dict:
    """Diferencias entre el scan (navegador del worker) y el HAR (navegador del usuario)."""
    def listing(names: set[str], side: dict) -> list[dict]:
        return sorted(({"organization": name, **side["organizations"][name]} for name in names), key=lambda item: (-item["requests"], item["organization"]))

    scan_orgs, har_orgs = set(scan["organizations"]), set(har["organizations"])
    blocked = [{"organization": name, "requests": data["blocked"], "domains": data["domains"]}
               for name, data in har["organizations"].items() if data["blocked"]]
    blocked.sort(key=lambda item: (-item["requests"], item["organization"]))
    blocked_requests = ((har.get("import") or {}).get("blocked_by_client")) or sum(item["requests"] for item in blocked)
    scan_wave, har_wave = scan["sync_wave"], har["sync_wave"]
    known = all(wave is not None and wave.get("available", True) for wave in (scan_wave, har_wave))
    if not known:
        wave_state = "unknown"
    else:
        wave_state = {(True, False): "only_har", (False, True): "only_scan", (True, True): "both", (False, False): "none"}[
            (bool(har_wave["detected"]), bool(scan_wave["detected"]))]
    wave = har_wave if wave_state in ("only_har", "both") else scan_wave if wave_state == "only_scan" else None
    values = {
        "solo_har": len(har_orgs - scan_orgs), "solo_scan": len(scan_orgs - har_orgs), "comunes": len(har_orgs & scan_orgs),
        "bloqueadas": blocked_requests,
        "n": (wave or {}).get("requests"), "k": (wave or {}).get("organizations"), "iniciador": (wave or {}).get("initiator") or "origen no identificado",
    }
    templates = _comparison_templates()
    conclusion = _render((templates.get("conclusions") or {}).get(wave_state), values)
    scan_trackers, har_trackers = scan.get("trackers"), har.get("trackers")
    if conclusion and scan_trackers is not None and har_trackers is not None:
        conclusion += " " + (_render(templates.get("tracking_suffix"), {"rastreo_har": har_trackers, "rastreo_scan": scan_trackers}) or "")
    if conclusion and blocked_requests:
        conclusion += " " + (_render(templates.get("blocked_suffix"), values) or "")
    if conclusion and scan.get("possibly_blocked"):
        conclusion += " " + (templates.get("scan_blocked_suffix") or "")
    return {
        "scan": {**{key: scan[key] for key in ("job_id", "url", "source", "analyzer_version", "finished_at", "requests")},
                 "protocol_version": scan.get("protocol_version")},
        "har": {key: har[key] for key in ("job_id", "url", "source", "analyzer_version", "finished_at", "requests", "import")},
        "organizations": {
            "only_scan": listing(scan_orgs - har_orgs, scan), "only_har": listing(har_orgs - scan_orgs, har),
            "both": sorted(scan_orgs & har_orgs),
        },
        "sync_wave": {"state": wave_state, "scan": scan_wave, "har": har_wave},
        # Lo que se compara (v1.3.1). None = análisis sin esa cifra: no se inventa.
        "tracking": {
            "scan": {"trackers": scan_trackers, "organizations": len(scan_orgs), "possibly_blocked": bool(scan.get("possibly_blocked"))},
            "har": {"trackers": har_trackers, "organizations": len(har_orgs)},
            "index_note": templates.get("index_note") or "",
        },
        "blocked_by_extension": {"requests": blocked_requests, "organizations": blocked},
        # Todo lo comparado se observó en cada captura; la diferencia no prueba su causa.
        "conclusion": {"text": conclusion.strip() if conclusion else UNKNOWN, "level": "EVIDENCIA" if conclusion and known else "DESCONOCIDO"},
        "note": templates.get("note") or "",
        # v1.5.0: el HAR no sigue el protocolo de visita; si el scan sí, la comparación junta dos formas de visitar.
        "protocol": compare_protocol(scan.get("protocol_version")),
    }


def compare_protocol(scan_version: int | None) -> dict:
    """Aviso de protocolo de una comparación scan ↔ HAR (el HAR nunca tiene protocolo de visita)."""
    if scan_version is None:
        scan_text = "El scan es anterior a v1.5.0 (sin protocolo de visita fijo)"
    else:
        scan_text = f"El scan siguió el protocolo de visita {scan_version} (carga, espera, scroll, espera y cierre)"
    return {
        "scan": scan_version, "har": None, "mixed": True,
        "note": f"{scan_text}; el HAR importado es una navegación libre del usuario, sin protocolo de visita. "
                "Parte de las diferencias puede deberse a cómo se visitó el sitio en cada captura.",
    }


@router.get("/scans/{job_id}/compare-candidates")
async def compare_candidates(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    """Capturas del otro tipo (HAR importado ↔ scan) ya analizadas; primero las del mismo sitio."""
    job = await _get_job(session, job_id)
    wanted_har = job_source(job) != SOURCE_HAR
    rows = (
        await session.execute(
            text(
                "SELECT j.id, j.url, j.finished_at, j.options, (SELECT count(*) FROM scan_requests r WHERE r.job_id = j.id) AS requests "
                "FROM jobs j JOIN site_analysis s ON s.job_id = j.id WHERE j.id <> :job_id AND j.status = 'completed' "
                "AND (COALESCE(j.options->>'source', 'scan') = 'har_import') = :wanted_har ORDER BY j.finished_at DESC NULLS LAST LIMIT 200"
            ),
            {"job_id": job_id, "wanted_har": wanted_har},
        )
    ).mappings().all()
    host = _host(job.url)
    items = [{"job_id": str(row["id"]), "url": row["url"], "finished_at": row["finished_at"], "requests": row["requests"],
              "source": SOURCE_HAR if wanted_har else "scan", "same_site": _host(row["url"]) == host} for row in rows]
    items.sort(key=lambda item: not item["same_site"])
    return {"job_id": str(job_id), "source": job_source(job), "candidates": items[:50]}


@router.get("/scans/{job_id}/compare/{other_id}")
async def compare(job_id: uuid.UUID, other_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    first, second = await _get_job(session, job_id), await _get_job(session, other_id)
    sources = {job_source(first), job_source(second)}
    if sources != {"scan", SOURCE_HAR}:
        raise AppError("COMPARE_NEEDS_SCAN_AND_HAR", "La comparación es entre un scan y una captura HAR importada.", stage="compare", status_code=400)
    scan, har = (first, second) if job_source(second) == SOURCE_HAR else (second, first)
    return compare_sides(await _side(session, scan), await _side(session, har))
