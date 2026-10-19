"""Resumen de un scan (v1.6.0, docs/adr/042): `GET /api/scans/{id}/overview`.

«Quién recibió más datos» y el scan anterior del mismo sitio con el mismo protocolo, calculados al leer sobre lo que
el análisis ya guardó (app/overview.py). No cambia el análisis, el puntaje ni el reporte.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import brands, overview
from app.bands import TRACKER_BANDS
from app.db import get_session
from app.errors import AppError
from app.measurement import protocol_version
from app.routes.panel import site_key
from app.routes.scans import _get_job

router = APIRouter(prefix="/api/scans")
MAX_PREVIOUS = 200


def _source(options: dict | None) -> str:
    value = (options or {}).get("source")
    return value if value in ("har_import", "interactive") else "scan"


@router.get("/{job_id}/overview")
async def get_overview(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    job = await _get_job(session, job_id)
    if job.analysis_status != "completed":
        raise AppError("ANALYSIS_NOT_READY", "El scan aún no tiene análisis.", stage="analysis", status_code=409)
    params = {"job": job_id}
    rows = (await session.execute(
        text("SELECT a.request_id, a.entity, a.party, a.band, r.registrable_domain FROM request_analysis a "
             "JOIN scan_requests r ON r.id = a.request_id WHERE a.job_id = :job"), params)).mappings().all()
    requests = {row["request_id"]: {"entity": row["entity"], "party": row["party"], "band": row["band"], "domain": row["registrable_domain"]}
                for row in rows}
    findings = (await session.execute(
        text("SELECT type, evidence_refs, details FROM findings WHERE job_id = :job"), params)).mappings().all()
    exfiltrations = (await session.execute(
        text("SELECT request_refs FROM fp_findings WHERE job_id = :job AND heuristic = 'exfiltration'"), params)).mappings().all()
    ranking = overview.recipients(
        requests,
        [{"type": row["type"], "evidence_refs": row["evidence_refs"]} for row in findings],
        [dict(row) for row in exfiltrations],
        [row["details"] for row in findings if row["type"] == "persistent_cookie"],
        tuple(TRACKER_BANDS),
        label=brands.group_label,
    )

    # Scan anterior del mismo sitio (host sin «www.», como el Panel), mismo origen, analizado y fuera de comparaciones.
    source = _source(job.options)
    key = site_key(job.url)
    candidates = []
    if key:
        earlier = (await session.execute(
            text("SELECT j.id, j.url, j.created_at, j.options, j.result, s.score, s.band FROM jobs j "
                 "JOIN site_analysis s ON s.job_id = j.id "
                 "WHERE j.status = 'completed' AND j.analysis_status = 'completed' AND j.comparison_id IS NULL "
                 "AND j.id <> :job AND j.created_at < :created ORDER BY j.created_at DESC LIMIT :limit"),
            {"job": job_id, "created": job.created_at, "limit": MAX_PREVIOUS})).mappings().all()
        candidates = [
            {"job_id": str(row["id"]), "created_at": row["created_at"], "score": row["score"], "band": row["band"],
             "protocol_version": protocol_version(row["result"])}
            for row in earlier if site_key(row["url"]) == key and _source(row["options"]) == source
        ]
    previous = overview.previous_scan(protocol_version(job.result) if source == "scan" else None, candidates)
    return {
        "job_id": str(job_id),
        "data_types": [{"id": data_type, "label": label} for data_type, label in overview.DATA_LABELS.items()],
        "recipients": ranking,
        "previous_scan": previous["previous"],
        "previous_reason": previous["reason"],
    }
