"""Historial (F10): cuánto hay guardado y cómo borrarlo (un scan o todo).

Deshabilitado en modo demo (403): con público en la red, nadie debe poder borrar los datos
de la demostración. El borrado es definitivo; los respaldos de backups/ no se tocan.
"""

import logging
import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app import history
from app.bands import BAND_LIMITS, TRACKER_BANDS
from app.config import get_settings
from app.db import get_session
from app.errors import AppError
from app.explain import glossary

router = APIRouter()
logger = logging.getLogger("app.history")

CONFIRMATION = "BORRAR"
FREED_NOTE = (
    "Tamaño de los datos borrados (filas de la base, sin índices). La base reutiliza ese espacio para scans nuevos; "
    "los respaldos de backups/ no se tocan."
)


class DeleteAllBody(BaseModel):
    model_config = {"extra": "forbid"}
    # Confirmación explícita: hay que escribir la palabra exacta.
    confirm: str = ""


def _require_enabled() -> None:
    if get_settings().demo:
        raise AppError(
            "HISTORY_DELETE_DISABLED", "En modo demo no se puede borrar el historial.", stage="history", status_code=403,
        )


@router.get("/api/bands")
async def get_bands() -> dict:
    """Bandas del tracking_score y del índice, de menor a mayor (v1.4.9). Única fuente: data/scoring.yaml."""
    return {"bands": [{"name": band["name"], "max": band["max"]} for band in BAND_LIMITS], "tracker_min_band": TRACKER_BANDS[0]}


@router.get("/api/glossary")
async def get_glossary() -> dict:
    """Glosario y paneles «¿Qué es esto?» (data/glossary.yaml). Texto fijo: no depende de ningún scan."""
    return glossary().as_dict()


@router.get("/api/history")
async def get_history(session: AsyncSession = Depends(get_session)) -> dict:
    return {**await history.stats(session), "delete_enabled": not get_settings().demo, "confirmation": CONFIRMATION}


@router.delete("/api/scans/{job_id}")
async def delete_scan(job_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    _require_enabled()
    result = await history.delete_scan(session, job_id)
    if result is None:
        raise AppError("JOB_NOT_FOUND", "El job no existe.", stage="queue", status_code=404)
    await session.commit()
    logger.info("history_scan_deleted", extra={"job_id": str(job_id), **result})
    return {"deleted": result, "note": FREED_NOTE}


@router.delete("/api/scans")
async def delete_all(body: DeleteAllBody | None = None, session: AsyncSession = Depends(get_session)) -> dict:
    _require_enabled()
    if body is None or body.confirm != CONFIRMATION:
        raise AppError(
            "CONFIRMATION_REQUIRED", f"Para borrar todo el historial hay que confirmar escribiendo {CONFIRMATION}.",
            stage="history", status_code=400, details={"confirm": CONFIRMATION},
        )
    result = await history.delete_all(session)
    await session.commit()
    logger.info("history_deleted", extra=result)
    return {"deleted": result, "note": FREED_NOTE}
