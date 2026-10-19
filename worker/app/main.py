import asyncio
import logging
import pathlib
import signal

import asyncpg

from app import comparison, jobs
from app.progress import ScanProgress, publish_loop
from app.analysis import analysis_loop
from app import har_capture, interactive
from app.resources import resources_loop
from app.browser.capture import run_scan
from app.render import render_loop
from app.retention import retention_loop
from app.browser.profiles import UnknownProfile
from app.config import settings
from app.logging_setup import configure_logging

logger = logging.getLogger("worker")


async def heartbeat_loop(pool) -> None:
    heartbeat_file = pathlib.Path(settings.heartbeat_file)
    while True:
        try:
            await jobs.heartbeat(pool, settings.worker_id)
            heartbeat_file.touch()  # lo lee el healthcheck del contenedor
        except (asyncpg.PostgresError, OSError) as exc:
            logger.error("heartbeat_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
        await asyncio.sleep(settings.heartbeat_interval_s)


async def reaper_loop(pool) -> None:
    while True:
        try:
            await jobs.reap(pool)
        except (asyncpg.PostgresError, OSError) as exc:
            logger.error("reaper_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
        try:
            # Perfiles de comparaciones terminadas, fallidas o borradas (v1.5.2): no se conservan.
            await comparison.purge_orphans(pool)
        except (asyncpg.PostgresError, OSError) as exc:
            logger.error("comparison_purge_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
        await asyncio.sleep(settings.reaper_interval_s)


async def run_job(pool, job) -> None:
    job_id = str(job["id"])
    logger.info("job_started", extra={"job_id": job_id, "attempt": job["attempts"]})
    result, error, capture = None, None, None
    # Etapa y contadores reales, publicados mientras el scan corre (F10).
    source = jobs.job_source(job)
    # Visita de una comparación (v1.5.2): perfil en disco; el resto del scan es el de siempre.
    visit = comparison.job_visit(job) if source == "scan" else None
    session, interval_s = None, 0
    state = ScanProgress(settings.interactive_max_s if source == interactive.SOURCE else settings.scan_timeout_s)
    publisher = asyncio.create_task(publish_loop(pool, job, settings.worker_id, state))
    try:
        # run_scan corta la captura a los SCAN_TIMEOUT_S; el margen extra es para volcarla.
        if source == interactive.SOURCE:
            # Captura interactiva (v1.4): dura lo que navegue el usuario, dentro de sus propios límites.
            outcome = await interactive.run(pool, job, settings.worker_id, state)
            result, error, capture = outcome.result, outcome.error, outcome.capture
        elif source == har_capture.SOURCE:
            # Captura importada (HAR): no se navega; las entradas ya depuradas se convierten en captura.
            result, capture = har_capture.build_capture(
                await jobs.load_har_import(pool, job["id"]),
                max_requests=settings.max_requests, max_body_bytes=settings.max_body_capture_bytes,
            )
        else:
            if visit is not None:
                saved = await jobs.load_comparison(pool, visit["id"])
                if saved is None:
                    raise comparison.ProfileError("COMPARISON_NOT_FOUND", "La comparación ya no existe.")
                interval_s = int(saved["config"].get("interval_s") or 0)
                session = comparison.ProfileSession(visit, saved["state"].get("visits", {}).get("1") if visit["visit"] == 2 else None)
                await asyncio.to_thread(session.prepare)
            outcome = await asyncio.wait_for(
                run_scan(job["url"], proxy_user=f"scan-{job['id']}", progress=state, profile_session=session, **jobs.job_options(job)),
                timeout=settings.scan_timeout_s + settings.finalize_grace_s,
            )
            result, error, capture = outcome.result, outcome.error, outcome.capture
            if session is not None:
                await asyncio.to_thread(session.record_disk)
    except asyncio.CancelledError:
        publisher.cancel()
        if visit is not None:
            # Una visita a medias ya cambió el perfil en disco: no se repite, y la comparación queda sin validez.
            interrupted = {"error_code": "COMPARISON_INTERRUPTED", "message": "El worker se detuvo durante una visita de la comparación.", "stage": "comparison"}
            update = comparison_update(job, visit, session, None, interrupted, interval_s)
            await asyncio.shield(jobs.finish(pool, job, settings.worker_id, error=interrupted, progress={"stage": "failed"}, comparison=update))
            comparison.remove(visit["id"])
            raise
        if source == interactive.SOURCE:
            # Una sesión interactiva no se repite sola: lo que navegó el usuario se perdió con el navegador.
            interrupted = {"error_code": "INTERACTIVE_INTERRUPTED", "message": "El worker se detuvo durante la captura interactiva.", "stage": "interactive"}
            await asyncio.shield(jobs.finish(pool, job, settings.worker_id, error=interrupted, progress={"stage": "failed"}))
            raise
        # Apagado ordenado: devolver el job a la cola en vez de esperar al reaper.
        await asyncio.shield(jobs.release(pool, job, settings.worker_id))
        logger.warning("job_released_on_shutdown", extra={"job_id": job_id})
        raise
    except har_capture.InvalidImport:
        error = {"error_code": "HAR_INVALID", "message": "La captura importada no se pudo convertir.", "stage": "har_import"}
    except comparison.ProfileError as exc:
        error = {"error_code": exc.code, "message": exc.message, "stage": "comparison"}
    except UnknownProfile:
        error = {"error_code": "UNKNOWN_PROFILE", "message": "El perfil pedido no existe.", "stage": "worker"}
    except asyncio.TimeoutError:
        error = {"error_code": "SCAN_TIMEOUT", "message": "El scan superó SCAN_TIMEOUT_S.", "stage": "navigation"}
    except Exception as exc:
        logger.exception("job_crashed", extra={"job_id": job_id})
        error = {"error_code": "WORKER_ERROR", "message": type(exc).__name__, "stage": "worker"}
    finally:
        publisher.cancel()
        await asyncio.gather(publisher, return_exceptions=True)

    if capture is not None:
        state.freeze(len(capture["requests"]))
    final = {**state.snapshot(), "stage": "analyzing" if capture is not None else "failed"}
    if result is not None:
        result["capture"] = jobs.capture_summary(capture)
    update = comparison_update(job, visit, session, result, error, interval_s) if visit is not None else None
    try:
        saved = await jobs.finish(pool, job, settings.worker_id, result=result, error=error, capture=capture, progress=final, comparison=update)
    except Exception as exc:
        # La captura no se pudo guardar: el job no puede quedar "completed" sin sus datos.
        logger.exception("capture_persist_failed", extra={"job_id": job_id})
        result = None
        error = {"error_code": "PERSIST_FAILED", "message": type(exc).__name__, "stage": "worker"}
        if update is not None:
            update = comparison_update(job, visit, session, None, error, interval_s)
        saved = await jobs.finish(pool, job, settings.worker_id, result=None, error=error, capture=None, progress={**final, "stage": "failed"}, comparison=update)
    if visit is not None and (visit["visit"] == 3 or error is not None):
        # Comparación terminada (o sin validez): los perfiles guardan datos de sitios reales y no se conservan.
        await asyncio.to_thread(comparison.remove, visit["id"])
    logger.info(
        "job_finished",
        extra={
            "job_id": job_id,
            "status": "completed" if error is None else "failed",
            "error_code": error["error_code"] if error else None,
            "saved": saved,  # False = el lease venció y el job ya no es de este worker
            "requests": len(capture["requests"]) if capture else 0,
            "capture_truncated": capture["truncated"] if capture else None,
            "end_reason": capture["end_reason"] if capture else None,
        },
    )


def comparison_update(job, visit: dict, session, result: dict | None, error: dict | None, interval_s: int) -> dict:
    """Lo que la visita deja en visit_comparisons.state y la hora desde la que se puede tomar la siguiente."""
    state = dict(session.state) if session is not None else {"profile": visit["profile"]}
    state.update({
        "job_id": str(job["id"]),
        "conditions": comparison.conditions(job, result),
        "error_code": error["error_code"] if error else None,
        "interval_s": interval_s if visit["visit"] == 1 else None,
    })
    return {
        "id": visit["id"], "visit": visit["visit"], "state": state,
        "next_not_before": comparison.next_not_before(visit["visit"], state.get("closed_at"), interval_s),
    }


async def claim_loop(pool, stop: asyncio.Event) -> None:
    running: set[asyncio.Task] = set()
    stopped = asyncio.create_task(stop.wait())
    try:
        while not stop.is_set():
            if len(running) >= settings.max_concurrent_scans:
                await asyncio.wait({stopped, *running}, return_when=asyncio.FIRST_COMPLETED)
                continue
            try:
                job = await jobs.claim(pool, settings.worker_id, settings.lease_s)
            except (asyncpg.PostgresError, OSError) as exc:
                logger.error("claim_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
                job = None
            if job is None:
                await asyncio.wait({stopped}, timeout=settings.poll_interval_s)
                continue
            task = asyncio.create_task(run_job(pool, job))
            running.add(task)
            task.add_done_callback(running.discard)
    finally:
        stopped.cancel()
        for task in list(running):
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)


async def interactive_loop(pool, stop: asyncio.Event) -> None:
    """Capturas interactivas: una a la vez, en su propio turno (no ocupan MAX_CONCURRENT_SCANS)."""
    stopped = asyncio.create_task(stop.wait())
    try:
        while not stop.is_set():
            try:
                job = await jobs.claim(pool, settings.worker_id, settings.lease_s, interactive=True)
            except (asyncpg.PostgresError, OSError) as exc:
                logger.error("claim_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
                job = None
            if job is None:
                await asyncio.wait({stopped}, timeout=settings.poll_interval_s)
                continue
            await run_job(pool, job)
    finally:
        stopped.cancel()


async def start_display():
    """Xvfb: display virtual donde Chromium abre su ventana (docs/adr/008). Sin puertos TCP."""
    number = settings.display.lstrip(":")
    for stale in (f"/tmp/.X{number}-lock", f"/tmp/.X11-unix/X{number}"):
        pathlib.Path(stale).unlink(missing_ok=True)  # restos de un arranque anterior del contenedor
    process = await asyncio.create_subprocess_exec(
        "Xvfb", settings.display, "-screen", "0", "1920x1080x24", "-nolisten", "tcp",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    for _ in range(50):
        if pathlib.Path(f"/tmp/.X11-unix/X{number}").exists():
            return process
        if process.returncode is not None:
            break
        await asyncio.sleep(0.1)
    raise RuntimeError(f"Xvfb no arrancó en {settings.display}")


async def display_watchdog(process, stop: asyncio.Event) -> None:
    await process.wait()
    if not stop.is_set():
        # Sin display no se puede navegar: mejor reiniciar el contenedor que fallar cada scan.
        logger.error("display_exited", extra={"returncode": process.returncode})
        stop.set()


async def main() -> None:
    configure_logging(settings.log_level)
    display = None if settings.headless else await start_display()
    pool = await asyncpg.create_pool(
        host=settings.postgres_host,
        user=settings.postgres_user,
        password=settings.postgres_password.get_secret_value(),
        database=settings.postgres_db,
        min_size=1,
        max_size=settings.max_concurrent_scans + 5,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)

    logger.info(
        "worker_started",
        extra={
            "worker_id": settings.worker_id,
            "max_concurrent_scans": settings.max_concurrent_scans,
            "lease_s": settings.lease_s,
            "chromium_sandbox": settings.chromium_sandbox,
            "headless": settings.headless,
            "license_profile": settings.license_profile,
            "scan_retention_days": settings.scan_retention_days,
        },
    )
    try:
        # Perfiles que quedaron de un arranque anterior sin visitas pendientes (v1.5.2).
        await comparison.purge_orphans(pool)
    except (asyncpg.PostgresError, OSError) as exc:
        logger.error("comparison_purge_failed", extra={"error_type": type(exc).__name__, "error": str(exc)})
    background = [
        asyncio.create_task(heartbeat_loop(pool)),
        asyncio.create_task(reaper_loop(pool)),
        asyncio.create_task(analysis_loop(pool)),
        asyncio.create_task(render_loop(pool)),
        asyncio.create_task(retention_loop(pool)),
        asyncio.create_task(resources_loop(pool)),
        asyncio.create_task(interactive_loop(pool, stop)),
    ]
    if display is not None:
        background.append(asyncio.create_task(display_watchdog(display, stop)))
    try:
        await claim_loop(pool, stop)
    finally:
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        await pool.close()
        if display is not None and display.returncode is None:
            display.terminate()
        logger.info("worker_stopped", extra={"worker_id": settings.worker_id})
