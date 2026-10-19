"""Comparación de visitas (v1.5.2, docs/adr/040): crear, listar y leer.

Tres visitas a la misma URL: perfil A limpio, perfil A persistente tras un intervalo, perfil B limpio de control. Cada
visita es un job normal (mismo protocolo de visita, mismo análisis, mismo puntaje); lo que añade la comparación se
calcula al leer (app/comparison.py) y no cambia nada de los scans.
"""

import json
import uuid
from datetime import date
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, StrictBool, StrictInt
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import comparison
from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.models import Job
from app.ratelimit import client_ip, scan_limiter
from app.routes.scans import date_bounds, like_pattern, scan_progress
from app.security.url_validator import MAX_URL_LENGTH, UrlValidationError, validate_url
from app.testscans import is_test_scan
from app.url_cleaning import clean_url, describe

router = APIRouter(prefix="/api/comparisons")
MAX_INTERVAL_S = 86_400
PROFILES = {1: "A", 2: "A", 3: "B"}
VISIT_LABELS = {
    1: "Perfil A limpio",
    2: "Perfil A persistente (mismo perfil, tras el intervalo)",
    3: "Perfil B limpio de control",
}


class ComparisonBody(BaseModel):
    model_config = {"extra": "forbid"}
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    # Segundos entre el cierre del navegador en la visita 1 y su apertura en la visita 2. None = el valor por defecto.
    interval_s: StrictInt | None = Field(default=None, ge=0, le=MAX_INTERVAL_S)
    clean_url: StrictBool = True


@router.post("", status_code=202)
async def create_comparison(body: ComparisonBody, request: Request, session: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    original = body.url.strip()
    target = clean_url(original)[0] if body.clean_url else original
    try:
        validated = await validate_url(target, allow_fixtures=settings.allow_fixtures)
    except UrlValidationError as exc:
        raise AppError(exc.code, exc.message, stage="url_validation", status_code=400) from exc
    interval_s = settings.visit_comparison_interval_s if body.interval_s is None else body.interval_s
    total = len(PROFILES)
    # Las tres visitas cuentan para el rate limit: o caben todas, o no se crea ninguna.
    retry_after = scan_limiter.check_many(client_ip(request), total, settings.scan_rate_limit, settings.scan_rate_window_s)
    if retry_after is not None:
        raise AppError(
            "RATE_LIMITED",
            f"Una comparación son {total} scans y el límite es de {settings.scan_rate_limit} cada {settings.scan_rate_window_s} segundos.",
            stage="rate_limit", status_code=429,
            details={"requested": total, "limit": settings.scan_rate_limit, "window_s": settings.scan_rate_window_s, "retry_after_s": round(retry_after, 1)},
        )
    queued = await session.scalar(select(func.count()).select_from(Job).where(Job.status == "queued"))
    if queued + total > settings.max_queued_jobs:
        raise AppError("QUEUE_FULL", "No hay espacio en la cola para esta comparación. Intenta en unos minutos.", stage="queue",
                       status_code=429, details={"queued": queued, "requested": total, "max_queued_jobs": settings.max_queued_jobs})
    comparison_id = uuid.uuid4()
    config = {"interval_s": interval_s}
    await session.execute(
        text("INSERT INTO visit_comparisons (id, url, original_url, config, state) "
             "VALUES (:id, :url, :original, CAST(:config AS jsonb), CAST('{\"visits\": {}}' AS jsonb))"),
        {"id": comparison_id, "url": validated.url, "original": original, "config": json.dumps(config)},
    )
    for visit, profile in PROFILES.items():
        job = Job(url=validated.url, original_url=original, options={"comparison": {"id": str(comparison_id), "visit": visit, "profile": profile}})
        session.add(job)
        await session.flush()
        # Un solo intento: repetir una visita cambiaría el perfil en disco. La 2 y la 3 esperan a la anterior
        # (el worker les pone la hora al terminar la visita previa).
        await session.execute(
            text("UPDATE jobs SET comparison_id = :comparison, max_attempts = 1, "
                 "not_before = CASE WHEN :visit = 1 THEN NULL ELSE 'infinity'::timestamptz END WHERE id = :id"),
            {"comparison": comparison_id, "visit": visit, "id": job.id},
        )
    await session.commit()
    return {"comparison_id": str(comparison_id), "url": validated.url, **describe(validated.url, original), "config": config, "status": "running"}


@router.get("")
async def list_comparisons(
    limit: int = Query(50, ge=1, le=200),
    site: str | None = Query(None, max_length=200),
    status: Literal["done", "failed", "active"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Comparaciones del Historial, de la más nueva a la más antigua, con los mismos filtros que los grupos."""
    where, params = ["true"], {"limit": limit}
    if site and site.strip():
        where.append("c.url ILIKE :site ESCAPE '\\'")
        params["site"] = like_pattern(site.strip())
    start, end = date_bounds(date_from, date_to)
    if start:
        where.append("c.created_at >= :start")
        params["start"] = start
    if end:
        where.append("c.created_at < :end")
        params["end"] = end
    having = {
        None: "",
        "active": "WHERE pending > 0",
        "failed": "WHERE pending = 0 AND failed > 0",
        "done": "WHERE pending = 0 AND failed = 0",
    }[status]
    rows = (
        await session.execute(
            text(
                "SELECT * FROM (SELECT c.id, c.url, c.original_url, c.config, c.created_at, count(j.id) AS total, "
                "count(j.id) FILTER (WHERE j.status = 'failed') AS failed, "
                "count(j.id) FILTER (WHERE j.status IN ('queued', 'running') OR (j.status = 'completed' AND j.analysis_status IN ('queued', 'running'))) AS pending "
                f"FROM visit_comparisons c LEFT JOIN jobs j ON j.comparison_id = c.id WHERE {' AND '.join(where)} "
                f"GROUP BY c.id) AS comparisons {having} ORDER BY created_at DESC LIMIT :limit"
            ),
            params,
        )
    ).mappings().all()
    return {
        "items": [
            {
                "comparison_id": str(row["id"]), "url": row["url"], **describe(row["url"], row["original_url"]), "config": row["config"],
                "created_at": row["created_at"], "total": row["total"], "failed": row["failed"], "done": row["total"] - row["pending"],
                "status": "active" if row["pending"] else "failed" if row["failed"] else "done",
                "is_test": is_test_scan(row["url"]),
            }
            for row in rows
        ]
    }


async def _visit_data(session: AsyncSession, job_id: uuid.UUID) -> dict:
    """Filas de una visita que entran en la comparación."""
    params = {"job": job_id}
    requests = (await session.execute(
        text("SELECT method, host, path, request_headers FROM scan_requests WHERE job_id = :job"), params)).mappings().all()
    organizations = (await session.execute(
        text("SELECT DISTINCT entity FROM request_analysis WHERE job_id = :job AND entity <> 'no_disponible'"), params)).scalars().all()
    destinations = (await session.execute(text("SELECT DISTINCT host FROM scan_destinations WHERE job_id = :job"), params)).scalars().all()
    cookies = (await session.execute(
        text("SELECT name, value, domain, path, expires FROM scan_cookies WHERE job_id = :job"), params)).mappings().all()
    storage = (await session.execute(
        text("SELECT origin, storage_type, key, value FROM scan_storage WHERE job_id = :job"), params)).mappings().all()
    parameters = (await session.execute(
        text("SELECT p.source, p.name, p.value, p.identifier_like, r.host, r.path FROM parameters p "
             "JOIN scan_requests r ON r.id = p.request_id WHERE p.job_id = :job"), params)).mappings().all()
    return {
        "requests": [dict(row) for row in requests], "organizations": list(organizations), "destinations": list(destinations),
        "cookies": [dict(row) for row in cookies], "storage": [dict(row) for row in storage], "parameters": [dict(row) for row in parameters],
    }


def _finished(row) -> bool:
    return row["status"] == "failed" or (row["status"] == "completed" and row["analysis_status"] in ("completed", "failed"))


@router.get("/{comparison_id}")
async def get_comparison(comparison_id: uuid.UUID, reveal: bool = False, session: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    row = (await session.execute(
        text("SELECT id, url, original_url, config, state, created_at FROM visit_comparisons WHERE id = :id"), {"id": comparison_id},
    )).mappings().one_or_none()
    if row is None:
        raise AppError("COMPARISON_NOT_FOUND", "Esa comparación no existe.", stage="comparison", status_code=404)
    jobs = (await session.execute(
        text("SELECT id, status, analysis_status, options, result, error, progress, not_before, started_at, finished_at "
             "FROM jobs WHERE comparison_id = :id ORDER BY created_at, id"), {"id": comparison_id},
    )).mappings().all()
    state_visits = (row["state"] or {}).get("visits") or {}
    by_visit: dict[int, dict] = {}
    for job in jobs:
        visit = ((job["options"] or {}).get("comparison") or {}).get("visit")
        if visit in PROFILES:
            by_visit[visit] = {**dict(job), "pending": not _finished(job)}
    analysis = {}
    if by_visit:
        analysis = {
            str(item["job_id"]): item
            for item in (await session.execute(
                text("SELECT job_id, score, band FROM site_analysis WHERE job_id = ANY(:ids)"), {"ids": [job["id"] for job in by_visit.values()]},
            )).mappings().all()
        }
    visits = []
    for visit, profile in PROFILES.items():
        job = by_visit.get(visit)
        result = (job or {}).get("result") or {}
        scored = analysis.get(str(job["id"])) if job else None
        visits.append({
            "visit": visit, "profile": profile, "label": VISIT_LABELS[visit],
            "job_id": str(job["id"]) if job else None,
            "status": job["status"] if job else "no_disponible",
            "analysis_status": job["analysis_status"] if job else None,
            "error_code": (job["error"] or {}).get("error_code") if job else None,
            "error_message": str((job["error"] or {}).get("message") or "")[:300] if job else None,
            "progress": scan_progress(SimpleNamespace(**job)) if job else None,
            "waiting_until": job["not_before"] if job and job["status"] == "queued" and job["not_before"] and job["not_before"].year < 9999 else None,
            "requests": (result.get("capture") or {}).get("total_requests"),
            "cookies": (result.get("capture") or {}).get("cookies"),
            "storage_items": (result.get("capture") or {}).get("storage_items"),
            "site_exposure_score": scored["score"] if scored and job["status"] == "completed" else None,
            "band": scored["band"] if scored and job["status"] == "completed" else None,
            "partial_navigation": bool(result.get("partial")),
        })
    valid = comparison.validity(by_visit, state_visits)
    response = {
        "comparison_id": str(row["id"]), "url": row["url"], **describe(row["url"], row["original_url"]),
        "config": row["config"], "created_at": row["created_at"],
        "status": valid["status"], "validity": valid,
        "interval": comparison.interval(row["config"] or {}, state_visits),
        "visits": visits,
        "profiles": comparison.state_summary(state_visits),
        "condition_differences": comparison.condition_differences(state_visits),
        "warning": comparison.WARNING,
        "limits": comparison.LIMITS,
        "texts": {"absent": comparison.ABSENT_TEXT, "different": comparison.DIFFERENT_TEXT, "observed": comparison.OBSERVED_TEXT},
        "revealed": reveal,
        "result": None,
    }
    ready = len(by_visit) == len(PROFILES) and all(
        job["status"] == "completed" and job["analysis_status"] == "completed" for job in by_visit.values())
    if ready:
        observed = {visit: comparison.observations(await _visit_data(session, by_visit[visit]["id"])) for visit in PROFILES}
        response["result"] = comparison.classify(observed, comparison.load_constants(settings.data_dir), reveal=reveal)
        response["result"]["kinds"] = {kind: spec["label"] for kind, spec in comparison.KINDS.items()}
    return response
