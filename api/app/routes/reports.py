"""Exportación de reportes (F8, docs/adr/018): JSON, HTML autocontenido y PDF.

Exportar congela una instantánea: el JSON del reporte, su sha256, el HTML generado a
partir de ese JSON y un PDF que el worker renderiza del mismo HTML. Los tres comparten
sha256, que además va impreso en el documento. Por defecto los identificadores van
enmascarados; mostrarlos es una opción explícita (`reveal`) y produce otra instantánea.
"""

import hashlib
import json
import pathlib
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Literal

from fastapi import APIRouter, Depends, Response
from jsonschema import Draft202012Validator
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.masking import mask_group_report, mask_report
from app.report_html import load_brand, render_group_report, render_scan_report
from app.routes.analysis import CMP_EXCLUDED, EVIDENCE_LEVELS, LEGAL_NOTICE, UNKNOWN, _manifest_version, attributions, build_report, license_profile_of
from app.routes.privacy import load_test

router = APIRouter()

GROUP_SCHEMA_VERSION = "group-1.0.0"
GROUP_SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "schemas" / "group-report-1.0.0.schema.json"
MEDIA_TYPES = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}
Kind = Literal["json", "html", "pdf"]

UPSERT_SQL = text(
    "INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) "
    "VALUES (:subject_type, :subject_id, :kind, :reveal, :sha256, :status, :data) "
    "ON CONFLICT ON CONSTRAINT uq_report_files DO UPDATE SET sha256 = EXCLUDED.sha256, status = EXCLUDED.status, "
    "data = EXCLUDED.data, render_info = NULL, created_at = now()"
)


class ExportBody(BaseModel):
    model_config = {"extra": "forbid"}
    # true = el reporte muestra los valores completos. Nunca es el valor por defecto.
    reveal: bool = False


@lru_cache
def group_validator() -> Draft202012Validator:
    schema = json.loads(GROUP_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def report_bytes(report: dict) -> bytes:
    """Serialización canónica: de estos bytes exactos se calcula el sha256 impreso en el documento."""
    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


async def build_group_report(session: AsyncSession, group_id: uuid.UUID) -> dict:
    test = await load_test(session, group_id)
    if test["status"] != "completed" or test["result"] is None:
        raise AppError("TEST_NOT_READY", "El test aún no termina.", stage="report", status_code=409, details={"progress": test["progress"]})
    ids = [uuid.UUID(job["job_id"]) for job in test["jobs"]]
    analyses = {
        str(row["job_id"]): row
        for row in (
            await session.execute(
                text("SELECT job_id, score, band, analyzer_version, lists_version, lists, summary FROM site_analysis WHERE job_id = ANY(:ids)"), {"ids": ids}
            )
        ).mappings()
    }
    lists = next((row["lists"] for row in analyses.values() if row["lists"]), [])
    profiles = sorted({license_profile_of(row["summary"]) for row in analyses.values()}) or ["no_comercial"]
    # Un grupo mezclado (scans analizados con perfiles distintos) se informa como el más restrictivo en atribuciones.
    profile = "no_comercial" if "no_comercial" in profiles else "comercial"
    report = {
        "schema_version": GROUP_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "group": {
            "group_id": test["group_id"], "url": test["url"], "config": test["config"],
            "created_at": test["created_at"].isoformat(), "progress": test["progress"],
        },
        "scans": [
            {
                "job_id": job["job_id"], "scenario": job["scenario"], "profile": job["profile"], "run": job["run"], "status": job["status"],
                "exposure_score": analyses[job["job_id"]]["score"] if job["job_id"] in analyses else UNKNOWN,
                "band": analyses[job["job_id"]]["band"] if job["job_id"] in analyses else UNKNOWN,
            }
            for job in test["jobs"]
        ],
        "result": test["result"],
        "versions": {
            "analyzer": ", ".join(sorted({row["analyzer_version"] for row in analyses.values()})) or UNKNOWN,
            "lists": ", ".join(sorted({row["lists_version"] for row in analyses.values()})) or UNKNOWN,
            "ip_database": f"DB-IP Lite {_manifest_version('ipdb', 'edition')}",
            "cmp_list": CMP_EXCLUDED if profile == "comercial" else _manifest_version("iab", "version"),
            "license_profile": ", ".join(profiles),
        },
        "attributions": attributions(lists, profile),
        "evidence_levels": EVIDENCE_LEVELS,
        "legal_notice": LEGAL_NOTICE,
        "masked": False,
        "limitations": test["result"]["limitations"],
    }
    # Pasa por JSON antes de validar: así se valida exactamente lo que se va a guardar.
    report = json.loads(report_bytes(report))
    errors = sorted(group_validator().iter_errors(report), key=lambda error: list(error.absolute_path))
    if errors:
        raise AppError("REPORT_INVALID", "El reporte generado no cumple el schema.", stage="report", status_code=500,
                       details={"schema_version": GROUP_SCHEMA_VERSION, "errors": [error.message[:200] for error in errors[:5]]})
    return report


async def _export(session: AsyncSession, subject_type: str, subject_id: uuid.UUID, reveal: bool) -> dict:
    settings = get_settings()
    if subject_type == "scan":
        report = await build_report(session, subject_id)
        report = report if reveal else mask_report(report)
        render = render_scan_report
    else:
        report = await build_group_report(session, subject_id)
        report = report if reveal else mask_group_report(report)
        render = render_group_report
    data = report_bytes(report)
    sha256 = hashlib.sha256(data).hexdigest()
    # El HTML se genera del JSON ya serializado: lo que se lee es lo que se firmó.
    html = render(json.loads(data), sha256, load_brand(settings.report_brand_name, settings.report_brand_dir)).encode("utf-8")
    for kind, status, payload in (("json", "ready", data), ("html", "ready", html), ("pdf", "pending", None)):
        await session.execute(UPSERT_SQL, {"subject_type": subject_type, "subject_id": subject_id, "kind": kind, "reveal": reveal,
                                           "sha256": sha256, "status": status, "data": payload})
    await session.commit()
    return await _status(session, subject_type, subject_id, reveal)


async def _status(session: AsyncSession, subject_type: str, subject_id: uuid.UUID, reveal: bool) -> dict:
    rows = (
        await session.execute(
            text("SELECT kind, status, sha256, octet_length(data) AS bytes, render_info, created_at FROM report_files "
                 "WHERE subject_type = :subject_type AND subject_id = :subject_id AND reveal = :reveal"),
            {"subject_type": subject_type, "subject_id": subject_id, "reveal": reveal},
        )
    ).mappings().all()
    if not rows:
        raise AppError("EXPORT_NOT_FOUND", "Este reporte aún no se ha exportado.", stage="report", status_code=404)
    files = {row["kind"]: {"status": row["status"], "bytes": row["bytes"], "render_info": row["render_info"]} for row in rows}
    return {"subject_type": subject_type, "subject_id": str(subject_id), "reveal": reveal, "masked": not reveal,
            "sha256": rows[0]["sha256"], "created_at": rows[0]["created_at"], "files": files}


async def _download(session: AsyncSession, subject_type: str, subject_id: uuid.UUID, kind: str, reveal: bool) -> Response:
    row = (
        await session.execute(
            text("SELECT status, sha256, data FROM report_files WHERE subject_type = :subject_type AND subject_id = :subject_id "
                 "AND kind = :kind AND reveal = :reveal"),
            {"subject_type": subject_type, "subject_id": subject_id, "kind": kind, "reveal": reveal},
        )
    ).mappings().one_or_none()
    if row is None:
        raise AppError("EXPORT_NOT_FOUND", "Este reporte aún no se ha exportado.", stage="report", status_code=404)
    if row["status"] == "failed":
        raise AppError("EXPORT_FAILED", "No se pudo generar el PDF. Vuelva a exportar.", stage="report", status_code=500)
    if row["status"] != "ready" or row["data"] is None:
        raise AppError("EXPORT_NOT_READY", "El PDF aún se está generando.", stage="report", status_code=409, details={"status": row["status"]})
    name = f"reporte-{'grupo-' if subject_type == 'group' else ''}{subject_id}{'-completo' if reveal else ''}.{kind}"
    headers = {
        "Content-Disposition": f'attachment; filename="{name}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Report-Sha256": row["sha256"],
    }
    if kind == "html":
        # Contiene texto capturado (escapado). Si alguien lo abre desde este origen, queda aislado y sin scripts.
        headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    return Response(content=bytes(row["data"]), media_type=MEDIA_TYPES[kind], headers=headers)


# --- Scans ---


@router.post("/api/scans/{job_id}/export", status_code=202)
async def export_scan(job_id: uuid.UUID, body: ExportBody | None = None, session: AsyncSession = Depends(get_session)) -> dict:
    return await _export(session, "scan", job_id, bool(body and body.reveal))


@router.get("/api/scans/{job_id}/export")
async def export_scan_status(job_id: uuid.UUID, reveal: bool = False, session: AsyncSession = Depends(get_session)) -> dict:
    return await _status(session, "scan", job_id, reveal)


@router.get("/api/scans/{job_id}/export/{kind}")
async def export_scan_file(job_id: uuid.UUID, kind: Kind, reveal: bool = False, session: AsyncSession = Depends(get_session)) -> Response:
    return await _download(session, "scan", job_id, kind, reveal)


# --- Grupos de Privacy Test ---


@router.post("/api/privacy/test/{group_id}/export", status_code=202)
async def export_group(group_id: uuid.UUID, body: ExportBody | None = None, session: AsyncSession = Depends(get_session)) -> dict:
    return await _export(session, "group", group_id, bool(body and body.reveal))


@router.get("/api/privacy/test/{group_id}/export")
async def export_group_status(group_id: uuid.UUID, reveal: bool = False, session: AsyncSession = Depends(get_session)) -> dict:
    return await _status(session, "group", group_id, reveal)


@router.get("/api/privacy/test/{group_id}/export/{kind}")
async def export_group_file(group_id: uuid.UUID, kind: Kind, reveal: bool = False, session: AsyncSession = Depends(get_session)) -> Response:
    return await _download(session, "group", group_id, kind, reveal)
