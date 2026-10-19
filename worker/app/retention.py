"""Retención de datos (F9): borra los scans terminados más antiguos que SCAN_RETENTION_DAYS.

Borrar un scan arrastra su captura, su análisis y sus reportes exportados (claves foráneas
ON DELETE CASCADE y el trigger de report_files, migración 0008). Los scans en cola o en
curso no se tocan, tengan la edad que tengan.

Purga manual (scripts/purge.sh):  python -m app.retention --days 30 [--dry-run]
"""

import argparse
import asyncio
import logging

import asyncpg

from app.config import settings
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)

EXPIRED_JOBS = "status IN ('completed', 'failed') AND analysis_status IS DISTINCT FROM 'running' AND created_at < now() - make_interval(days => $1)"
# Un grupo de Privacy Test se borra cuando ya no le queda ningún scan y también es antiguo.
EXPIRED_GROUPS = "created_at < now() - make_interval(days => $1) AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.group_id = test_groups.id)"
# Igual una comparación de visitas (v1.5.2).
EXPIRED_COMPARISONS = "created_at < now() - make_interval(days => $1) AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.comparison_id = visit_comparisons.id)"


async def purge(conn, days: int, *, dry_run: bool = False) -> dict:
    """Borra lo vencido y devuelve cuánto borró (o cuánto borraría). `days` debe ser >= 1."""
    if days < 1:
        raise ValueError("days debe ser >= 1 (0 desactiva la retención automática, no borra todo)")
    if dry_run:
        return {
            "dry_run": True, "days": days,
            "scans": await conn.fetchval(f"SELECT count(*) FROM jobs WHERE {EXPIRED_JOBS}", days),
            "reports": await conn.fetchval(
                f"SELECT count(*) FROM report_files f WHERE f.subject_type = 'scan' AND f.subject_id IN (SELECT id FROM jobs WHERE {EXPIRED_JOBS})", days),
            "groups": None,
        }
    async with conn.transaction():
        reports_before = await conn.fetchval("SELECT count(*) FROM report_files")
        scans = await conn.fetchval(f"WITH gone AS (DELETE FROM jobs WHERE {EXPIRED_JOBS} RETURNING 1) SELECT count(*) FROM gone", days)
        groups = await conn.fetchval(f"WITH gone AS (DELETE FROM test_groups WHERE {EXPIRED_GROUPS} RETURNING 1) SELECT count(*) FROM gone", days)
        await conn.execute(f"DELETE FROM visit_comparisons WHERE {EXPIRED_COMPARISONS}", days)
        reports = reports_before - await conn.fetchval("SELECT count(*) FROM report_files")
    return {"dry_run": False, "days": days, "scans": scans, "reports": reports, "groups": groups}


async def retention_loop(pool) -> None:
    if settings.scan_retention_days < 1:
        logger.info("retention_disabled")
        return
    while True:
        try:
            async with pool.acquire() as conn:
                result = await purge(conn, settings.scan_retention_days)
            if result["scans"] or result["groups"]:
                logger.info("retention_purged", extra=result)
        except Exception as exc:
            logger.error("retention_failed", extra={"error_type": type(exc).__name__})
        await asyncio.sleep(settings.retention_interval_s)


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Purga manual de scans y reportes antiguos.")
    parser.add_argument("--days", type=int, default=settings.scan_retention_days or 30, help="borra lo anterior a esta cantidad de días (>= 1)")
    parser.add_argument("--dry-run", action="store_true", help="solo cuenta; no borra")
    args = parser.parse_args()
    configure_logging(settings.log_level)
    conn = await asyncpg.connect(host=settings.postgres_host, user=settings.postgres_user,
                                 password=settings.postgres_password.get_secret_value(), database=settings.postgres_db)
    try:
        result = await purge(conn, args.days, dry_run=args.dry_run)
    finally:
        await conn.close()
    logger.info("retention_manual", extra=result)


if __name__ == "__main__":
    asyncio.run(_main())
