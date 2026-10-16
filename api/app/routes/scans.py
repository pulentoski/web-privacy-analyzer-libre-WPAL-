import uuid
from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, StrictBool
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.bands import BANDS
from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.explain import explanations
from app.failures import failure, net_error, partial_navigation
from app.models import Job, RequestAnalysis, ScanRedirect, ScanRequest
from app.ratelimit import client_ip, scan_limiter
from app.security.url_validator import MAX_URL_LENGTH, UrlValidationError, validate_url
from app.testscans import is_test_scan
from app.url_cleaning import clean_url, describe, inspect

# Fallo que Chromium anota cuando una extensión (bloqueador) cancela la request; solo en HAR importados.
BLOCKED_BY_CLIENT = "ERR_BLOCKED_BY_CLIENT"

router = APIRouter(prefix="/api/scans")

MAX_PAGE_SIZE = 200
# Bandas del tracking_score, de menor a mayor: nombres y límites en data/scoring.yaml (app/bands.py).


class ScanOptions(BaseModel):
    model_config = {"extra": "forbid"}

    # false = scan sin instrumentación de fingerprinting (experimentos de control, ADR 009).
    fp_instrumentation: StrictBool | None = None


class ScanRequestBody(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    options: ScanOptions | None = None
    # true (por defecto) = quitar los parámetros de seguimiento de la URL antes de escanear.
    clean_url: StrictBool = True


class InspectUrlBody(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


SORTS = {
    "time": (ScanRequest.seq.asc(),),
    "-time": (ScanRequest.seq.desc(),),
    # Sin análisis (score NULL) al final en ambos sentidos.
    "score": (RequestAnalysis.score.asc().nulls_last(), ScanRequest.seq.asc()),
    "-score": (RequestAnalysis.score.desc().nulls_last(), ScanRequest.seq.asc()),
}


# Etapas que ve la interfaz, en orden (F10). "failed" no es una etapa de la barra: es su final.
STAGES = ("queued", "opening", "capturing", "analyzing", "building", "done")


def scan_progress(job, now: datetime | None = None) -> dict:
    """Etapa y contadores reales del scan. Nada aquí se estima: lo que falta es None.

    `job` puede ser un Job o una fila con las mismas columnas (status, analysis_status,
    progress, result).
    """
    reported = job.progress if isinstance(job.progress, dict) else {}
    capture = ((job.result or {}).get("capture") or {}) if isinstance(job.result, dict) else {}
    if job.status == "queued":
        stage = "queued"
    elif job.status == "running":
        stage = "capturing" if reported.get("stage") == "capturing" else "opening"
    elif job.analysis_status in ("queued", "running"):
        stage = "building" if reported.get("stage") == "building" else "analyzing"
    elif job.status == "failed" or job.analysis_status == "failed":
        stage = "failed"
    else:
        stage = "done"
    requests = capture.get("total_requests")
    if not isinstance(requests, int):
        requests = reported.get("requests") if isinstance(reported.get("requests"), int) else None
    elapsed = None
    if job.status == "running":
        try:
            started = datetime.fromisoformat(reported.get("capture_started_at") or "")
            elapsed = max(0.0, round(((now or datetime.now(timezone.utc)) - started).total_seconds(), 1))
        except (TypeError, ValueError):
            elapsed = None
    elif isinstance(capture.get("duration_ms"), (int, float)):
        elapsed = round(capture["duration_ms"] / 1000, 1)
    max_s = reported.get("max_s")
    return {
        "stage": stage,
        # Dónde se quedó un scan fallido: la última etapa que publicó el worker.
        "failed_at": (reported.get("stage") if reported.get("stage") in STAGES else None) if stage == "failed" else None,
        "requests": requests,
        # Segundos de captura transcurridos (en curso) o que tomó (terminada), frente al máximo.
        "capture_elapsed_s": elapsed,
        "capture_max_s": max_s if isinstance(max_s, (int, float)) else None,
    }


def _serialize(job: Job) -> dict:
    return {
        "progress": scan_progress(job),
        "job_id": str(job.id),
        "url": job.url,
        **describe(job.url, job.original_url),
        "status": job.status,
        # v1.4.8: un scan fallido no es una medición; su código net::ERR_* real, si el navegador dio uno.
        "measured": job.status != "failed",
        "failure": failure(job.status, job.error),
        "partial_navigation": partial_navigation(job.result),
        "attempts": job.attempts,
        "result": job.result,
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "analysis_status": job.analysis_status,
        # scan | har_import | interactive (captura interactiva, v1.4).
        "source": (job.options or {}).get("source") if (job.options or {}).get("source") in ("har_import", "interactive") else "scan",
        "options": job.options,
    }


async def _get_job(session: AsyncSession, job_id: uuid.UUID) -> Job:
    job = await session.get(Job, job_id)
    if job is None:
        raise AppError("JOB_NOT_FOUND", "El job no existe.", stage="queue", status_code=404)
    return job


def external_party():
    """Request a un tercero = a OTRA organización (`request_analysis.party`, v1.2.1).

    Sin análisis (o anterior a v1.2.1) no hay `party`: se usa el dominio registrable.
    """
    return or_(RequestAnalysis.party == "third_party", and_(RequestAnalysis.party.is_(None), ScanRequest.third_party.is_(True)))


def not_external_party():
    """Complemento de `external_party` escrito a mano: con NULL (sin análisis), NOT(...) daría NULL."""
    return or_(RequestAnalysis.party.in_(("first_party", "same_org")), and_(RequestAnalysis.party.is_(None), ScanRequest.third_party.is_(False)))


async def _summary(session: AsyncSession, job: Job) -> dict:
    """Conteos de la captura. Los de terceros salen de `request_analysis.party` (otra organización)."""
    by_type = (
        await session.execute(
            select(ScanRequest.resource_type, func.count())
            .where(ScanRequest.job_id == job.id)
            .group_by(ScanRequest.resource_type)
        )
    ).all()
    counts = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(ScanRequest.third_party.is_(False)),
                func.count().filter(external_party()),
                func.count().filter(ScanRequest.third_party.is_(None)),
                func.count().filter(ScanRequest.blocked_by_proxy.is_(True)),
                func.count().filter(RequestAnalysis.party == "same_org"),
                func.count().filter(ScanRequest.failure_text.like(f"%{BLOCKED_BY_CLIENT}%")),
            ).select_from(ScanRequest.__table__.outerjoin(RequestAnalysis.__table__, RequestAnalysis.request_id == ScanRequest.id))
            .where(ScanRequest.job_id == job.id)
        )
    ).one()
    others = (
        await session.execute(
            text(
                "SELECT (SELECT count(*) FROM scan_websockets WHERE job_id = :job_id),"
                " (SELECT count(*) FROM scan_cookies WHERE job_id = :job_id),"
                " (SELECT count(*) FROM scan_storage WHERE job_id = :job_id),"
                " (SELECT count(DISTINCT chain_index) FROM scan_redirects WHERE job_id = :job_id)"
            ),
            {"job_id": job.id},
        )
    ).one()
    capture = (job.result or {}).get("capture") or {}
    return {
        "total_requests": counts[0],
        "by_resource_type": {resource_type or "unknown": count for resource_type, count in sorted(by_type, key=str)},
        "first_party": counts[1],
        "third_party": counts[2],
        # Otro dominio del mismo dueño que el sitio: se cuenta aparte, no es tercero.
        "same_org": counts[5],
        # Solo en capturas importadas (HAR): el navegador del usuario las bloqueó con una extensión.
        "blocked_by_client": counts[6],
        "party_unknown": counts[3],
        "blocked": counts[4],
        # None = el worker no dejó el dato (job sin terminar o fallido).
        "capture_truncated": capture.get("truncated"),
        "websockets": others[0],
        "cookies": others[1],
        "storage_items": others[2],
        "redirect_chains": others[3],
    }


def _plain(request: ScanRequest, analysis: RequestAnalysis | None) -> dict | None:
    """Frase técnica de la request (F10): {text, level, signal}. None = aún sin análisis."""
    if analysis is None:
        return None
    phrase = explanations().request_phrase(
        reasons=analysis.reasons, entity=analysis.entity, domain=request.registrable_domain or request.host,
        third_party=request.third_party, party=analysis.party,
    )
    return {key: phrase[key] for key in ("text", "level", "signal")}


def score_by_level(reasons) -> dict | None:
    """Suma de pesos por nivel de evidencia (v1.4.9): «Evidencia X + Inferencia Y». El score se acota a 0–100;
    `clamped` indica que la suma lo excede y por eso no coincide con el total. None = sin análisis."""
    if reasons is None:
        return None
    sums = {"EVIDENCIA": 0, "INFERENCIA": 0, "POSIBLE": 0}
    for reason in reasons:
        if isinstance(reason, dict) and reason.get("level") in sums and isinstance(reason.get("weight"), (int, float)):
            sums[reason["level"]] += reason["weight"]
    total = sum(sums.values())
    return {**sums, "clamped": total > 100 or total < 0}


def _analysis_item(analysis: RequestAnalysis | None) -> dict:
    # None en todos = la request aún no tiene análisis (no es lo mismo que score 0).
    return {
        "score": analysis.score if analysis else None,
        "score_by_level": score_by_level(analysis.reasons) if analysis else None,
        "band": analysis.band if analysis else None,
        "category": analysis.category if analysis else None,
        "mechanism": analysis.mechanism if analysis else None,
        "entity": analysis.entity if analysis else None,
        # Qué reveló la cabecera Referer a un tercero: full_url | origin_only | absent.
        "referer": analysis.referer if analysis else None,
        # first_party | same_org | third_party (otra organización); None = sin análisis.
        "party": analysis.party if analysis else None,
    }


def _request_item(request: ScanRequest, analysis: RequestAnalysis | None = None) -> dict:
    return {
        **_analysis_item(analysis),
        "plain": _plain(request, analysis),
        "request_id": request.id,
        "seq": request.seq,
        "timestamp": request.ts,
        "method": request.method,
        "url": request.url,
        "host": request.host,
        "resource_type": request.resource_type,
        "response_status": request.response_status,
        "mime_type": request.mime_type,
        "is_navigation": request.is_navigation,
        "third_party": request.third_party,
        "blocked_by_proxy": request.blocked_by_proxy,
        "failure_text": request.failure_text,
        "has_post_data": request.post_data is not None,
    }


def _request_detail(
    request: ScanRequest, redirect_chain: list[ScanRedirect], analysis: RequestAnalysis | None = None
) -> dict:
    post_data = None
    if request.post_data is not None:
        post_data = {
            "data": request.post_data,
            "encoding": request.post_data_encoding,
            "sha256": request.post_data_sha256,
            "size": request.post_data_size,
            "truncated": request.post_data_truncated,
            "source": request.post_data_source,
        }
    return {
        **_request_item(request, analysis),
        "reasons": analysis.reasons if analysis else None,
        "list_matches": analysis.list_matches if analysis else None,
        "analyzer_version": analysis.analyzer_version if analysis else None,
        "job_id": str(request.job_id),
        "url_truncated": request.url_truncated,
        "scheme": request.scheme,
        "path": request.path,
        "query_params": request.query_params,
        "frame_url": request.frame_url,
        "initiator": request.initiator,
        "request_headers": request.request_headers,
        "post_data": post_data,
        "response_headers": request.response_headers,
        "sizes": request.sizes,
        "timing": request.timing,
        "registrable_domain": request.registrable_domain,
        "redirected_from_seq": request.redirected_from_seq,
        # v1.4.9: cada salto con su Location (la URL del salto siguiente) y la request a la que llevó.
        "redirect_chain": [
            {"hop": hop.hop_index, "request_seq": hop.request_seq, "url": hop.url, "status": hop.status,
             "location": redirect_chain[index + 1].url if index + 1 < len(redirect_chain) else None,
             "next_request_seq": redirect_chain[index + 1].request_seq if index + 1 < len(redirect_chain) else None}
            for index, hop in enumerate(redirect_chain)
        ],
    }


@router.post("/inspect-url")
async def inspect_url(body: InspectUrlBody) -> dict:
    """Parámetros de seguimiento que trae una URL y cómo queda sin ellos. No valida ni visita nada.

    POST: la URL viaja en el cuerpo y no queda en el log de accesos.
    """
    return inspect(body.url.strip())


@router.post("", status_code=202)
async def create_scan(body: ScanRequestBody, request: Request, session: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    original = body.url.strip()
    target = clean_url(original)[0] if body.clean_url else original
    try:
        validated = await validate_url(target, allow_fixtures=settings.allow_fixtures)
    except UrlValidationError as exc:
        raise AppError(exc.code, exc.message, stage="url_validation", status_code=400) from exc
    # Los límites se aplican a URLs válidas: un error de tipeo no consume cupo.
    retry_after = scan_limiter.check(client_ip(request), settings.scan_rate_limit, settings.scan_rate_window_s)
    if retry_after is not None:
        raise AppError(
            "RATE_LIMITED",
            f"Demasiados scans desde esta dirección. Máximo {settings.scan_rate_limit} cada "
            f"{settings.scan_rate_window_s} segundos.",
            stage="rate_limit",
            status_code=429,
            details={"limit": settings.scan_rate_limit, "window_s": settings.scan_rate_window_s,
                     "retry_after_s": round(retry_after, 1)},
        )
    queued = await session.scalar(select(func.count()).select_from(Job).where(Job.status == "queued"))
    if queued >= settings.max_queued_jobs:
        raise AppError(
            "QUEUE_FULL",
            "Hay demasiados scans en cola. Intenta de nuevo en unos minutos.",
            stage="queue",
            status_code=429,
            details={"queued": queued, "max_queued_jobs": settings.max_queued_jobs},
        )
    options = body.options.model_dump(exclude_none=True) if body.options else None
    job = Job(url=validated.url, original_url=original, options=options or None)
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return _serialize(job)


STATUS_FILTERS = {
    "done": "j.status = 'completed' AND coalesce(j.analysis_status, 'completed') IN ('completed', 'failed')",
    "failed": "j.status = 'failed'",
    "active": "(j.status IN ('queued', 'running') OR (j.status = 'completed' AND j.analysis_status IN ('queued', 'running')))",
}


def like_pattern(value: str) -> str:
    """Texto del usuario como patrón de ILIKE literal (sin comodines)."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def date_bounds(date_from: date | None, date_to: date | None) -> tuple[datetime | None, datetime | None]:
    """Días completos en UTC: [date_from 00:00, date_to + 1 día)."""
    start = datetime.combine(date_from, time.min, tzinfo=timezone.utc) if date_from else None
    end = datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc) if date_to else None
    return start, end


@router.get("")
async def list_scans(
    limit: int = Query(20, ge=1, le=MAX_PAGE_SIZE),
    site: str | None = Query(None, max_length=200),
    status: Literal["done", "failed", "active"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    grouped: bool | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Scans, del más nuevo al más antiguo. Filtros del Historial: sitio, estado y fechas (UTC)."""
    where, params = ["true"], {"limit": limit}
    if site and site.strip():
        where.append("j.url ILIKE :site ESCAPE '\\'")
        params["site"] = like_pattern(site.strip())
    if status:
        where.append(STATUS_FILTERS[status])
    start, end = date_bounds(date_from, date_to)
    if start:
        where.append("j.created_at >= :start")
        params["start"] = start
    if end:
        where.append("j.created_at < :end")
        params["end"] = end
    if grouped is not None:
        where.append("j.group_id IS NOT NULL" if grouped else "j.group_id IS NULL")
    condition = " AND ".join(where)
    total = await session.scalar(text(f"SELECT count(*) FROM jobs j WHERE {condition}"), params)
    rows = (
        await session.execute(
            text(
                "SELECT j.id, j.url, j.original_url, j.status, j.analysis_status, j.created_at, j.finished_at, j.result->>'title' AS title, COALESCE(j.options->>'source', 'scan') AS source, "
                "j.progress, j.result, j.group_id, "
                "j.error->>'error_code' AS error_code, j.error, s.score, s.band, (s.summary->>'trackers')::int AS trackers, "
                "coalesce((s.summary->'blocking'->>'blocked')::boolean, false) AS blocked, "
                "coalesce((s.summary->'blocking'->>'partial')::boolean, false) AS partial_block "
                f"FROM jobs j LEFT JOIN site_analysis s ON s.job_id = j.id WHERE {condition} ORDER BY j.created_at DESC LIMIT :limit"
            ),
            params,
        )
    ).mappings().all()
    return {
        "total": total,
        "items": [
            {
                "job_id": str(row["id"]), "url": row["url"], "status": row["status"],
                **describe(row["url"], row["original_url"]),
                "analysis_status": row["analysis_status"], "created_at": row["created_at"],
                "finished_at": row["finished_at"], "title": row["title"], "error_code": row["error_code"],
                "net_error": net_error(row["error"]), "measured": row["status"] != "failed",
                "partial_navigation": partial_navigation(row["result"]) is not None,
                # scan | har_import (captura importada: navegador real del usuario).
                "source": row["source"],
                # Scan fallido: sin índice (lo guardado no es una medición, docs/adr/035).
                "site_exposure_score": row["score"] if row["status"] != "failed" else None,
                "band": row["band"] if row["status"] != "failed" else None,
                "trackers": row["trackers"] if row["status"] != "failed" else None,
                "blocked": bool(row["blocked"]) and row["status"] != "failed",
                # Bloqueo parcial (v1.3.2): informativo, el scan sigue en el ranking.
                "partial_block": bool(row["partial_block"]),
                "stage": scan_progress(SimpleNamespace(**row))["stage"], "group_id": str(row["group_id"]) if row["group_id"] else None,
                "is_test": is_test_scan(row["url"]),
            }
            for row in rows
        ],
    }


@router.get("/{job_id}")
async def get_scan(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    job = await _get_job(session, job_id)
    site = (
        await session.execute(
            text(
                "SELECT analyzer_version, lists_version, score, band, summary, partial, duration_ms, analyzed_at "
                "FROM site_analysis WHERE job_id = :job_id"
            ),
            {"job_id": job_id},
        )
    ).mappings().one_or_none()
    analysis = None
    if site is not None:
        analysis = {
            "analyzer_version": site["analyzer_version"],
            "lists_version": site["lists_version"],
            "site_exposure_score": site["score"],
            "band": site["band"],
            "trackers": site["summary"].get("trackers"),
            "bands": site["summary"].get("bands"),
            "partial": site["partial"],
            "duration_ms": site["duration_ms"],
            "analyzed_at": site["analyzed_at"],
        }
    out = {**_serialize(job), "summary": await _summary(session, job), "analysis": analysis,
           # En modo demo no se puede borrar el historial: la interfaz no ofrece el botón.
           "can_delete": not get_settings().demo}
    if job.status == "queued":
        # Posición real en la cola: cuántos scans esperan desde antes, más este.
        out["progress"]["queue_position"] = 1 + await session.scalar(
            select(func.count()).select_from(Job).where(Job.status == "queued", Job.created_at < job.created_at)
        )
    return out


@router.get("/{job_id}/requests")
async def list_requests(
    job_id: uuid.UUID,
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    resource_type: str | None = Query(None, max_length=32),
    third_party: bool | None = None,
    blocked: bool | None = None,
    band: Literal[BANDS] | None = None,
    category: str | None = Query(None, max_length=32),
    mechanism: str | None = Query(None, max_length=32),
    domain: str | None = Query(None, max_length=255),
    sort: Literal["time", "-time", "score", "-score"] = "time",
    session: AsyncSession = Depends(get_session),
) -> dict:
    await _get_job(session, job_id)
    conditions = [ScanRequest.job_id == job_id]
    if mechanism is not None:
        conditions.append(RequestAnalysis.mechanism == mechanism)
    if domain:
        # Búsqueda por subcadena en el host; el texto del usuario nunca actúa como patrón.
        escaped = domain.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(func.lower(ScanRequest.host).like(f"%{escaped}%", escape="\\"))
    if band is not None:
        conditions.append(RequestAnalysis.band == band)
    if category is not None:
        conditions.append(RequestAnalysis.category == category)
    if resource_type is not None:
        conditions.append(ScanRequest.resource_type == resource_type)
    if third_party is not None:
        conditions.append(external_party() if third_party else not_external_party())
    if blocked is not None:
        conditions.append(ScanRequest.blocked_by_proxy.is_(blocked))
    joined = ScanRequest.__table__.outerjoin(
        RequestAnalysis.__table__, RequestAnalysis.request_id == ScanRequest.id
    )
    total = await session.scalar(select(func.count()).select_from(joined).where(*conditions))
    rows = (
        await session.execute(
            select(ScanRequest, RequestAnalysis)
            .outerjoin(RequestAnalysis, RequestAnalysis.request_id == ScanRequest.id)
            .where(*conditions)
            .order_by(*SORTS[sort])
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return {
        "job_id": str(job_id),
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [_request_item(request, analysis) for request, analysis in rows],
    }


async def _request_client_hints(session: AsyncSession, job_id: uuid.UUID, request_id: int) -> dict | None:
    """Client Hints de esta request (v1.4.9): solicitud, envío y la delegación del sitio. None = análisis anterior."""
    summary = await session.scalar(text("SELECT summary->'client_hints' FROM site_analysis WHERE job_id = :job_id"), {"job_id": job_id})
    if not isinstance(summary, dict):
        return None
    asked = next((item for item in summary.get("requests") or [] if request_id in (item.get("request_ids") or [])), None)
    sent = next((item for item in summary.get("sends") or [] if item.get("request_id") == request_id), None)
    return {
        # Solicitud: esta respuesta pidió hints. Nunca prueba que se recibieran.
        "requested": {"organization": asked["organization"], "hints": asked["hints"], "sent": asked["sent"],
                      "sent_hints": asked.get("sent_hints") or [], "text": summary.get("request_text")} if asked else None,
        # Envío: esta request llevó las cabeceras.
        "sent": {"organization": sent["organization"], "hints": sent["hints"], "after_request": sent.get("after_request")} if sent else None,
        "delegation": summary.get("delegation"),
        "notes": summary.get("notes") or [],
    }


@router.get("/{job_id}/requests/{request_id}")
async def get_request(
    job_id: uuid.UUID, request_id: int, session: AsyncSession = Depends(get_session)
) -> dict:
    await _get_job(session, job_id)
    # Postgres bigint: fuera de rango no puede existir.
    request = await session.get(ScanRequest, request_id) if 0 < request_id < 2**63 else None
    if request is None or request.job_id != job_id:
        raise AppError("REQUEST_NOT_FOUND", "La request no existe en este scan.", stage="capture", status_code=404)
    chain_index = await session.scalar(
        select(ScanRedirect.chain_index).where(
            ScanRedirect.job_id == job_id, ScanRedirect.request_seq == request.seq
        )
    )
    chain: list[ScanRedirect] = []
    if chain_index is not None:
        chain = list(
            (
                await session.scalars(
                    select(ScanRedirect)
                    .where(ScanRedirect.job_id == job_id, ScanRedirect.chain_index == chain_index)
                    .order_by(ScanRedirect.hop_index)
                )
            ).all()
        )
    analysis = await session.scalar(select(RequestAnalysis).where(RequestAnalysis.request_id == request.id))
    params = {"job_id": job_id, "request_id": request.id, "ref": f"[{request.id}]"}
    parameters = (
        await session.execute(
            text(
                "SELECT source, name, value, value_truncated, category, shapes, length, entropy, identifier_like, "
                "encoding_chain FROM parameters WHERE job_id = :job_id AND request_id = :request_id ORDER BY id"
            ),
            params,
        )
    ).mappings().all()
    decoded = (
        await session.execute(
            text(
                "SELECT source, name, path, raw_value, decoded_value, decoded_truncated, encoding_chain, confidence "
                "FROM decoded_values WHERE job_id = :job_id AND request_id = :request_id ORDER BY id"
            ),
            params,
        )
    ).mappings().all()
    # Hallazgos que citan esta request como evidencia.
    findings = (
        await session.execute(
            text(
                # v1.4.9: con sus referencias, para que los conteos sean los del scan (no 0).
                "SELECT id, 'general' AS kind, type, level, claim, details, NULL AS script_url, evidence_refs FROM findings "
                "WHERE job_id = :job_id AND evidence_refs @> CAST(:ref AS jsonb) "
                "UNION ALL SELECT id, 'fingerprinting', heuristic, level, claim, details, script_url, request_refs FROM fp_findings "
                "WHERE job_id = :job_id AND request_refs @> CAST(:ref AS jsonb) ORDER BY kind, id"
            ),
            params,
        )
    ).mappings().all()
    entities = {
        row.domain: row.entity
        for row in await session.execute(
            text("SELECT DISTINCT r.registrable_domain AS domain, a.entity FROM scan_requests r JOIN request_analysis a ON a.request_id = r.id "
                 "WHERE r.job_id = :job_id AND a.entity <> 'no_disponible' AND r.registrable_domain IS NOT NULL"),
            {"job_id": job_id},
        )
    }
    detail = _request_detail(request, chain, analysis)
    detail["client_hints"] = await _request_client_hints(session, job_id, request.id)
    if chain:
        # Request, host y organización de cada salto (para enlazar «→ request #n»).
        hops = (await session.execute(
            text("SELECT r.seq, r.id, r.host, a.entity FROM scan_requests r LEFT JOIN request_analysis a ON a.request_id = r.id "
                 "WHERE r.job_id = :job_id AND r.seq = ANY(:seqs)"),
            {"job_id": job_id, "seqs": [hop.request_seq for hop in chain]},
        )).mappings().all()
        by_seq = {row["seq"]: row for row in hops}
        for hop in detail["redirect_chain"]:
            row = by_seq.get(hop["request_seq"]) or {}
            hop.update({"request_id": row.get("id"), "host": row.get("host"), "entity": row.get("entity")})
            following = by_seq.get(hop["next_request_seq"]) or {}
            hop["next_request_id"] = following.get("id")
    return {
        **detail,
        "parameters": [dict(row) for row in parameters],
        "decoded_values": [dict(row) for row in decoded],
        "findings": [
            {
                "id": row["id"], "kind": row["kind"], "type": row["type"], "level": row["level"], "claim": row["claim"],
                "plain": explanations().finding_phrase(dict(row), entities, in_request=True)["text"],
            }
            for row in findings
        ],
    }
