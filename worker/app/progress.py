"""Progreso real de un scan (F10): la etapa y los contadores que publica el worker.

Etapas que ve la interfaz: en cola → abriendo el sitio → capturando → analizando →
generando resultado → listo / falló. Aquí se publican las que dependen del worker; "en
cola", "listo" y "falló" salen del estado del job. Todo lo que se publica es un hecho
medido (requests capturadas, cuándo empezó la captura, el máximo configurado): no hay
porcentajes estimados.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

PUBLISH_INTERVAL_S = 0.5

PUBLISH_SQL = """
UPDATE jobs SET progress = $2::jsonb
 WHERE id = $1 AND status = 'running' AND locked_by = $3 AND attempts = $4
"""

STAGE_SQL = "UPDATE jobs SET progress = coalesce(progress, '{}'::jsonb) || jsonb_build_object('stage', $2::text) WHERE id = $1"


async def _write(pool, sql: str, *args) -> None:
    """Escribe el progreso sin esperar a que el WAL llegue al disco.

    Con el disco ocupado por el navegador, ese fsync llegó a tardar más de 3 s (medido): el
    contador aparecía cuando la captura ya había terminado. El progreso es efímero: si se
    perdiera en una caída no pasa nada, así que solo ESTA transacción usa
    synchronous_commit = off. El resultado del scan se sigue guardando con commit síncrono.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SET LOCAL synchronous_commit TO OFF")
            await conn.execute(sql, *args)


class ScanProgress:
    """Estado que run_scan actualiza y publish_loop escribe en jobs.progress."""

    def __init__(self, max_s: float) -> None:
        self.stage = "opening"
        self.max_s = max_s
        self.capture_started_at: datetime | None = None
        self._counter = None
        self._frozen: int | None = None

    def navigating(self, counter) -> None:
        """Empieza la navegación: desde aquí corre SCAN_TIMEOUT_S y `counter()` cuenta requests."""
        self.capture_started_at = datetime.now(timezone.utc)
        self._counter = counter

    def capturing(self) -> None:
        """El sitio respondió: la página está cargando y se captura su tráfico."""
        self.stage = "capturing"

    def freeze(self, requests: int) -> None:
        """Fin de la captura: el contador queda en su valor final."""
        self._frozen = requests

    @property
    def requests(self) -> int | None:
        if self._frozen is not None:
            return self._frozen
        if self._counter is None:
            return None
        try:
            return int(self._counter())
        except Exception:  # el contador mira objetos del navegador, que puede haberse cerrado
            return None

    def snapshot(self) -> dict:
        return {
            "stage": self.stage,
            "requests": self.requests,
            "max_s": self.max_s,
            "capture_started_at": self.capture_started_at.isoformat() if self.capture_started_at else None,
        }


async def publish_loop(pool, job, worker_id: str, state: ScanProgress) -> None:
    """Escribe el progreso mientras el scan corre. Solo cuando cambia; nunca tumba el scan."""
    last = None
    while True:
        snapshot = state.snapshot()
        if snapshot != last:
            try:
                await _write(pool, PUBLISH_SQL, job["id"], json.dumps(snapshot), worker_id, job["attempts"])
                last = snapshot
            except Exception as exc:
                logger.warning("progress_publish_failed", extra={"job_id": str(job["id"]), "error_type": type(exc).__name__})
        await asyncio.sleep(PUBLISH_INTERVAL_S)


async def set_stage(pool, job_id, stage: str) -> None:
    """Cambia solo la etapa (la usa el análisis: "analyzing", "building")."""
    try:
        await _write(pool, STAGE_SQL, job_id, stage)
    except Exception as exc:
        logger.warning("progress_stage_failed", extra={"job_id": str(job_id), "error_type": type(exc).__name__})
