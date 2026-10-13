"""F10: el worker publica la etapa y los contadores reales del scan."""

import asyncio
import json
import uuid

import asyncpg

from app import jobs, progress
from app.browser.capture import run_scan
from app.config import settings
from app.progress import ScanProgress
from tests.helpers import run_async


def test_snapshot_only_contains_measured_values():
    state = ScanProgress(60)
    assert state.snapshot() == {"stage": "opening", "requests": None, "max_s": 60, "capture_started_at": None}
    seen = [3]
    state.navigating(lambda: seen[0])
    assert state.stage == "opening" and state.requests == 3 and state.snapshot()["capture_started_at"] is not None
    state.capturing()
    seen[0] = 9
    assert state.snapshot()["stage"] == "capturing" and state.requests == 9
    state.freeze(11)
    seen[0] = 50
    assert state.requests == 11  # tras el fin de la captura el contador ya no cambia

    def broken():
        raise RuntimeError("navegador cerrado")

    other = ScanProgress(60)
    other.navigating(broken)
    assert other.requests is None  # si no se puede contar, no se inventa


def test_run_scan_reports_opening_then_capturing_with_live_request_count(manifest):
    state = ScanProgress(settings.scan_timeout_s)
    samples = []

    async def scan():
        async def sample():
            while True:
                samples.append((state.stage, state.requests))
                await asyncio.sleep(0.05)

        sampler = asyncio.create_task(sample())
        try:
            return await run_scan(manifest["page"], progress=state)
        finally:
            sampler.cancel()

    outcome = run_async(scan())
    assert outcome.error is None
    stages = [stage for stage, _ in samples]
    assert stages[0] == "opening" and stages[-1] == "capturing" and set(stages) == {"opening", "capturing"}
    counts = [count for _, count in samples if count is not None]
    # El contador es el del monitor de red: crece y termina en el total capturado.
    assert counts == sorted(counts) and counts[-1] == len(outcome.capture["requests"]) >= 21
    assert len(set(counts)) >= 2, "no se vio crecer el contador durante la captura"
    assert state.capture_started_at is not None


def test_progress_is_published_while_the_job_runs_and_kept_when_it_finishes():
    """Cola real: claim → publicación periódica → finish. Lo que queda en jobs.progress es lo medido."""

    async def flow():
        pool = await asyncpg.create_pool(host=settings.postgres_host, user=settings.postgres_user,
                                         password=settings.postgres_password.get_secret_value(), database=settings.postgres_db, min_size=1, max_size=2)
        job_id = uuid.uuid4()
        await pool.execute(
            "INSERT INTO jobs (id, url, status, attempts, locked_by, locked_until, progress) "
            "VALUES ($1, 'http://progreso.example/', 'running', 1, 'test-f10', now() + interval '1 minute', '{\"stage\": \"opening\"}')", job_id)
        job = {"id": job_id, "attempts": 1}
        try:
            state = ScanProgress(60)
            publisher = asyncio.create_task(progress.publish_loop(pool, job, "test-f10", state))
            await asyncio.sleep(0.2)
            first = json.loads(await pool.fetchval("SELECT progress FROM jobs WHERE id = $1", job_id))
            count = [0]
            state.navigating(lambda: count[0])
            state.capturing()
            count[0] = 7
            await asyncio.sleep(progress.PUBLISH_INTERVAL_S + 0.4)
            second = json.loads(await pool.fetchval("SELECT progress FROM jobs WHERE id = $1", job_id))
            # Otro worker no puede pisar el progreso de un job que no es suyo.
            await progress._write(pool, progress.PUBLISH_SQL, job_id, json.dumps({"stage": "capturing", "requests": 999}), "otro-worker", 1)
            untouched = json.loads(await pool.fetchval("SELECT progress FROM jobs WHERE id = $1", job_id))
            publisher.cancel()
            state.freeze(8)
            saved = await jobs.finish(pool, job, "test-f10", result=None, error={"error_code": "X", "message": "x", "stage": "worker"}, capture=None,
                                      progress={**state.snapshot(), "stage": "failed"})
            final = json.loads(await pool.fetchval("SELECT progress FROM jobs WHERE id = $1", job_id))
            await progress.set_stage(pool, job_id, "building")
            staged = json.loads(await pool.fetchval("SELECT progress FROM jobs WHERE id = $1", job_id))
            return first, second, untouched, saved, final, staged
        finally:
            await pool.execute("DELETE FROM jobs WHERE id = $1", job_id)
            await pool.close()

    first, second, untouched, saved, final, staged = run_async(flow())
    assert first == {"stage": "opening", "requests": None, "max_s": 60, "capture_started_at": None}
    assert second["stage"] == "capturing" and second["requests"] == 7 and second["max_s"] == 60 and second["capture_started_at"]
    assert untouched == second
    assert saved is True and final["stage"] == "failed" and final["requests"] == 8
    assert staged == {**final, "stage": "building"}
