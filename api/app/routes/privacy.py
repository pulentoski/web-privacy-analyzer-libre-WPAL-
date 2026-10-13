"""Privacy Test (F7): un grupo de scans (escenarios × perfiles × corridas) y su comparación."""

import pathlib
import re
import uuid
from types import SimpleNamespace
from typing import Literal

import yaml
from datetime import date

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field, StrictBool
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.models import Job
from app.privacy import REAL, build_result
from app.ratelimit import client_ip, scan_limiter
from app.routes.analysis import TRACKER_BANDS
from app.routes.scans import date_bounds, like_pattern, scan_progress
from app.testscans import is_test_scan
from app.url_cleaning import clean_url, describe
from app.security.url_validator import MAX_URL_LENGTH, UrlValidationError, validate_url

router = APIRouter(prefix="/api/privacy")
PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
Scenario = Literal["sin_interaccion", "aceptar", "rechazar"]
ID_SOURCES = ("query", "query_decoded", "post_form", "post_form_decoded", "post_body_decoded")


def available_profiles() -> list[dict]:
    """Perfiles de data/profiles/, más el navegador real del worker."""
    out = [{"name": REAL, "label": "Navegador real del worker (sin emulación)", "coherent": True}]
    directory = pathlib.Path(get_settings().profiles_dir)
    for path in sorted(directory.glob("*.yaml")) if directory.is_dir() else []:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict) and PROFILE_NAME.match(str(data.get("name", ""))) and data["name"] == path.stem:
            out.append({"name": data["name"], "label": str(data.get("label", data["name"])), "coherent": bool(data.get("coherent", True))})
    return out


class TestBody(BaseModel):
    model_config = {"extra": "forbid"}
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    scenarios: list[Scenario] = Field(default=["sin_interaccion"], min_length=1, max_length=3)
    profiles: list[str] = Field(default=[REAL], min_length=1, max_length=6)
    runs: int = Field(default=1, ge=1, le=5)
    # true (por defecto) = quitar los parámetros de seguimiento de la URL antes de escanear.
    clean_url: StrictBool = True


@router.get("/profiles")
async def list_profiles() -> dict:
    settings = get_settings()
    return {
        "profiles": available_profiles(),
        "scenarios": ["sin_interaccion", "aceptar", "rechazar"],
        "max_runs": 5,
        "max_group_jobs": settings.max_group_jobs,
        "note": "Un perfil cambia lo que el navegador dice ser. No cambia la dirección IP.",
    }


@router.post("/test", status_code=202)
async def create_test(body: TestBody, request: Request, session: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    original = body.url.strip()
    target = clean_url(original)[0] if body.clean_url else original
    try:
        validated = await validate_url(target, allow_fixtures=settings.allow_fixtures)
    except UrlValidationError as exc:
        raise AppError(exc.code, exc.message, stage="url_validation", status_code=400) from exc
    scenarios = list(dict.fromkeys(body.scenarios))
    profiles = list(dict.fromkeys(body.profiles))
    known = {profile["name"] for profile in available_profiles()}
    unknown = [name for name in profiles if name not in known]
    if unknown:
        raise AppError("UNKNOWN_PROFILE", "Perfil desconocido.", stage="privacy_test", status_code=400,
                       details={"unknown": [name[:64] for name in unknown], "available": sorted(known)})
    total = len(scenarios) * len(profiles) * body.runs
    if total > settings.max_group_jobs:
        raise AppError(
            "GROUP_TOO_LARGE", f"El test pide {total} scans; el máximo por grupo es {settings.max_group_jobs}.",
            stage="privacy_test", status_code=400, details={"requested": total, "max_group_jobs": settings.max_group_jobs},
        )
    # Cada corrida cuenta para el rate limit: o caben todas, o no se crea ninguna.
    retry_after = scan_limiter.check_many(client_ip(request), total, settings.scan_rate_limit, settings.scan_rate_window_s)
    if retry_after is not None:
        raise AppError(
            "RATE_LIMITED",
            f"Este test son {total} scans y el límite es de {settings.scan_rate_limit} cada {settings.scan_rate_window_s} segundos.",
            stage="rate_limit", status_code=429,
            details={"requested": total, "limit": settings.scan_rate_limit, "window_s": settings.scan_rate_window_s, "retry_after_s": round(retry_after, 1)},
        )
    queued = await session.scalar(select(func.count()).select_from(Job).where(Job.status == "queued"))
    if queued + total > settings.max_queued_jobs:
        raise AppError("QUEUE_FULL", "No hay espacio en la cola para este test. Intenta en unos minutos.", stage="queue",
                       status_code=429, details={"queued": queued, "requested": total, "max_queued_jobs": settings.max_queued_jobs})
    group_id = uuid.uuid4()
    config = {"scenarios": scenarios, "profiles": profiles, "runs": body.runs}
    await session.execute(
        text("INSERT INTO test_groups (id, url, original_url, config) VALUES (:id, :url, :original, CAST(:config AS jsonb))"),
        {"id": group_id, "url": validated.url, "original": original, "config": __import__("json").dumps(config)},
    )
    # Intercaladas por corrida: así los grupos se miden en momentos parecidos.
    for run in range(1, body.runs + 1):
        for scenario in scenarios:
            for profile in profiles:
                job = Job(url=validated.url, original_url=original, options={"scenario": scenario, "profile": profile, "run": run, "probe": True})
                session.add(job)
                await session.flush()
                await session.execute(text("UPDATE jobs SET group_id = :group WHERE id = :id"), {"group": group_id, "id": job.id})
    await session.commit()
    return {"group_id": str(group_id), "url": validated.url, **describe(validated.url, original), "config": config, "total": total, "status": "running"}


@router.get("/tests")
async def list_tests(
    limit: int = Query(50, ge=1, le=200),
    site: str | None = Query(None, max_length=200),
    status: Literal["done", "failed", "active"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Grupos de «Opciones avanzadas» (Historial), del más nuevo al más antiguo, con los mismos filtros que los scans.

    Estado de un grupo: active = le quedan scans por terminar; failed = terminó y todos sus scans
    fallaron; done = terminó con al menos un scan completado.
    """
    where, params = ["true"], {"limit": limit}
    if site and site.strip():
        where.append("g.url ILIKE :site ESCAPE '\\'")
        params["site"] = like_pattern(site.strip())
    start, end = date_bounds(date_from, date_to)
    if start:
        where.append("g.created_at >= :start")
        params["start"] = start
    if end:
        where.append("g.created_at < :end")
        params["end"] = end
    having = {
        None: "",
        "active": "WHERE pending > 0",
        "failed": "WHERE pending = 0 AND total > 0 AND failed = total",
        "done": "WHERE pending = 0 AND failed < total",
    }[status]
    rows = (
        await session.execute(
            text(
                "SELECT * FROM (SELECT g.id, g.url, g.original_url, g.config, g.created_at, count(j.id) AS total, "
                "count(j.id) FILTER (WHERE j.status = 'failed') AS failed, "
                "count(j.id) FILTER (WHERE j.status IN ('queued', 'running') OR (j.status = 'completed' AND j.analysis_status IN ('queued', 'running'))) AS pending "
                f"FROM test_groups g LEFT JOIN jobs j ON j.group_id = g.id WHERE {' AND '.join(where)} GROUP BY g.id) AS groups "
                f"{having} ORDER BY created_at DESC LIMIT :limit"
            ),
            params,
        )
    ).mappings().all()
    return {
        "items": [
            {
                "group_id": str(row["id"]), "url": row["url"], **describe(row["url"], row["original_url"]), "config": row["config"],
                "created_at": row["created_at"], "total": row["total"], "failed": row["failed"], "done": row["total"] - row["pending"],
                "status": "active" if row["pending"] else "failed" if row["total"] and row["failed"] == row["total"] else "done",
                "is_test": is_test_scan(row["url"]),
            }
            for row in rows
        ]
    }


@router.get("/test/{group_id}")
async def get_test(group_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    return await load_test(session, group_id)


async def load_test(session: AsyncSession, group_id: uuid.UUID) -> dict:
    """Estado del grupo y, cuando terminó, su comparación. También lo usa el reporte exportable (F8)."""
    group = (await session.execute(text("SELECT id, url, original_url, config, created_at FROM test_groups WHERE id = :id"), {"id": group_id})).mappings().one_or_none()
    if group is None:
        raise AppError("TEST_NOT_FOUND", "Ese test no existe.", stage="privacy_test", status_code=404)
    rows = (
        await session.execute(
            text("SELECT id, status, analysis_status, options, result, error, progress FROM jobs WHERE group_id = :id ORDER BY created_at, id"),
            {"id": group_id},
        )
    ).mappings().all()
    jobs = []
    for row in rows:
        options, result = row["options"] or {}, row["result"] or {}
        jobs.append({
            "job_id": str(row["id"]), "scenario": options.get("scenario"), "profile": options.get("profile") or REAL,
            "run": options.get("run"), "status": row["status"], "analysis_status": row["analysis_status"],
            "error_code": (row["error"] or {}).get("error_code"), "error_message": str((row["error"] or {}).get("message") or "")[:300], "consent": result.get("consent"), "profile_info": result.get("profile"),
            # Mismo progreso real que un scan suelto (F10).
            "progress": scan_progress(SimpleNamespace(**row)),
        })

    def finished(job: dict) -> bool:
        return job["status"] == "failed" or (job["status"] == "completed" and job["analysis_status"] in ("completed", "failed"))

    done = sum(1 for job in jobs if finished(job))
    failed = sum(1 for job in jobs if job["status"] == "failed")
    # Las corridas que se están midiendo ahora (el worker corre varias a la vez): las que ya
    # salieron de la cola y no terminaron; si todas esperan, la primera en cola. k = posición
    # de cada una entre las N del grupo.
    pending = [(index, job) for index, job in enumerate(jobs, start=1) if not finished(job)]
    running = [item for item in pending if item[1]["status"] != "queued"] or pending[:1]
    active = [
        {"index": index, "of": len(jobs), "job_id": job["job_id"], "scenario": job["scenario"], "profile": job["profile"],
         "run": job["run"], **job["progress"]}
        for index, job in running
    ]
    response = {
        "group_id": str(group_id), "url": group["url"], **describe(group["url"], group["original_url"]),
        "config": group["config"], "created_at": group["created_at"],
        "status": "completed" if done == len(jobs) else "running",
        "progress": {"done": done, "total": len(jobs), "failed": failed, "active": active},
        "jobs": [{key: job[key] for key in ("job_id", "scenario", "profile", "run", "status", "analysis_status", "error_code", "progress")} for job in jobs],
        "result": None,
    }
    if done < len(jobs):
        return response
    ids = [uuid.UUID(job["job_id"]) for job in jobs]
    counts = {
        str(row["job_id"]): {"requests": row["requests"], "third_party_domains": row["domains"]}
        for row in (
            await session.execute(
                text("SELECT r.job_id, count(*) AS requests, "
                     "count(DISTINCT r.registrable_domain) FILTER (WHERE COALESCE(a.party = 'third_party', r.third_party)) AS domains "
                     "FROM scan_requests r LEFT JOIN request_analysis a ON a.request_id = r.id WHERE r.job_id = ANY(:ids) GROUP BY r.job_id"),
                {"ids": ids},
            )
        ).mappings()
    }
    for job in jobs:
        counts.setdefault(job["job_id"], {"requests": 0, "third_party_domains": 0})
    trackers = [
        {**dict(row), "job_id": str(row["job_id"])}
        for row in (
            await session.execute(
                text("SELECT r.job_id, r.id AS request_id, r.seq, r.host, r.path, r.registrable_domain AS domain, a.entity "
                     "FROM scan_requests r JOIN request_analysis a ON a.request_id = r.id "
                     "WHERE r.job_id = ANY(:ids) AND a.band = ANY(:bands) AND COALESCE(a.party = 'third_party', r.third_party) ORDER BY r.job_id, r.seq"),
                {"ids": ids, "bands": list(TRACKER_BANDS)},
            )
        ).mappings()
    ]
    candidates = [
        {**dict(row), "job_id": str(row["job_id"])}
        for row in (
            await session.execute(
                text("SELECT p.job_id, p.request_id, r.registrable_domain AS domain, p.name, p.value, a.entity "
                     "FROM parameters p JOIN scan_requests r ON r.id = p.request_id LEFT JOIN request_analysis a ON a.request_id = r.id "
                     "WHERE p.job_id = ANY(:ids) AND COALESCE(a.party = 'third_party', r.third_party) AND p.identifier_like AND p.source = ANY(:sources) "
                     "AND p.length BETWEEN 12 AND 200 AND NOT p.value_truncated ORDER BY p.id LIMIT 30000"),
                {"ids": ids, "sources": list(ID_SOURCES)},
            )
        ).mappings()
    ]
    account_ids = {
        str(row["job_id"]): [item for item in (row["items"] or []) if isinstance(item, dict) and item.get("value")]
        for row in (
            await session.execute(
                text("SELECT job_id, summary->'account_ids' AS items FROM site_analysis WHERE job_id = ANY(:ids)"), {"ids": ids}
            )
        ).mappings()
    }
    response["result"] = build_result(jobs, counts, trackers, candidates, account_ids)
    return response


@router.get("/artifacts/{job_id}/{kind}")
async def get_artifact(job_id: uuid.UUID, kind: Literal["consent_banner"], session: AsyncSession = Depends(get_session)) -> Response:
    """Captura del banner de consentimiento (imagen generada por el worker, no por el sitio)."""
    row = (
        await session.execute(text("SELECT mime, data FROM scan_artifacts WHERE job_id = :job AND kind = :kind"), {"job": job_id, "kind": kind})
    ).mappings().one_or_none()
    if row is None:
        raise AppError("ARTIFACT_NOT_FOUND", "No hay captura para ese scan.", stage="privacy_test", status_code=404)
    return Response(content=bytes(row["data"]), media_type=row["mime"], headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"})
