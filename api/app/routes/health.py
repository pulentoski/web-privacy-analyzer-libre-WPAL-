import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import get_settings
from app.db import SessionLocal

router = APIRouter()
logger = logging.getLogger(__name__)


async def _check() -> tuple[bool, bool]:
    async with SessionLocal() as session:
        await session.execute(text("SELECT 1"))
        fresh = await session.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM worker_heartbeats "
                "WHERE last_seen > now() - make_interval(secs => :max_age))"
            ),
            {"max_age": get_settings().worker_heartbeat_max_age_s},
        )
    return True, bool(fresh)


@router.get("/health")
async def health() -> JSONResponse:
    try:
        database, worker = await asyncio.wait_for(_check(), timeout=3)
    except Exception as exc:
        logger.warning("health_database_unreachable", extra={"error_type": type(exc).__name__})
        database, worker = False, False
    status = "ok" if database and worker else "degraded"
    # 503 solo si falta la base de datos: sin ella la API no puede operar.
    return JSONResponse(
        {"status": status, "database": database, "worker": worker},
        status_code=200 if database else 503,
    )
