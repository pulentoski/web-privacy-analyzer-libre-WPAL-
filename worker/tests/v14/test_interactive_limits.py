"""v1.4: límites de la captura interactiva contra la base real: inactividad, duración máxima y botón."""

import dataclasses
import json
import pathlib
import uuid

import asyncpg
import pytest

from app import interactive
from app.config import settings
from tests.helpers import SITE, run_async


def _alive(needle: str) -> int:
    count = 0
    for entry in pathlib.Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                count += needle in (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
    return count


async def _session(limits: dict, *, stop_after_ready: bool = False, touch_input: bool = False) -> dict:
    pool = await asyncpg.create_pool(host=settings.postgres_host, user=settings.postgres_user,
                                     password=settings.postgres_password.get_secret_value(), database=settings.postgres_db, min_size=1, max_size=3)
    job_id = uuid.uuid4()
    original = interactive.settings
    interactive.settings = dataclasses.replace(original, **limits)
    try:
        # running + locked_by: el worker real de este stack no lo toma.
        await pool.execute(
            "INSERT INTO jobs (id, url, status, attempts, max_attempts, locked_by, locked_until, options) "
            "VALUES ($1, $2, 'running', 1, 1, 'test', now() + interval '10 minutes', $3::jsonb)", job_id, SITE + "/", json.dumps({"source": "interactive"}))
        await pool.execute("INSERT INTO interactive_sessions (job_id, token_hash, vnc_password) VALUES ($1, $2, 'abc12345')", job_id, "0" * 64)
        if stop_after_ready or touch_input:
            import asyncio

            async def act():
                for _ in range(120):
                    await asyncio.sleep(0.5)
                    if await pool.fetchval("SELECT state FROM interactive_sessions WHERE job_id = $1", job_id) == "ready":
                        break
                if stop_after_ready:
                    await pool.execute("UPDATE interactive_sessions SET stop_requested = true WHERE job_id = $1", job_id)
                while touch_input:
                    # Entrada del usuario (la anota el relé de la api): la sesión no está inactiva.
                    await pool.execute("UPDATE interactive_sessions SET last_input_at = now() WHERE job_id = $1", job_id)
                    await asyncio.sleep(1)

            actor = asyncio.ensure_future(act())
        else:
            actor = None
        loop_time = __import__("time").monotonic()
        outcome = await interactive.run(pool, {"id": job_id, "url": SITE + "/", "attempts": 1}, "test")
        elapsed = __import__("time").monotonic() - loop_time
        if actor is not None:
            actor.cancel()
        row = await pool.fetchrow("SELECT state, end_reason, vnc_password, vnc_host, ended_at IS NOT NULL AS ended, idle_s, max_s FROM interactive_sessions WHERE job_id = $1", job_id)
        return {"outcome": outcome, "row": dict(row), "elapsed": elapsed, "x11vnc": _alive("x11vnc -display"), "xvfb": _alive(f"Xvfb {settings.interactive_display} ")}
    finally:
        interactive.settings = original
        await pool.execute("DELETE FROM jobs WHERE id = $1", job_id)
        await pool.close()


@pytest.mark.parametrize("limits, kwargs, reason", [
    ({"interactive_idle_s": 3, "interactive_max_s": 600}, {}, "idle_timeout"),
    ({"interactive_idle_s": 600, "interactive_max_s": 4}, {}, "max_duration"),
    # Con actividad continua no hay cierre por inactividad: manda la duración máxima.
    ({"interactive_idle_s": 3, "interactive_max_s": 8}, {"touch_input": True}, "max_duration"),
    ({"interactive_idle_s": 600, "interactive_max_s": 600}, {"stop_after_ready": True}, "user_stop"),
])
def test_session_ends_by_its_limits_and_releases_everything(limits, kwargs, reason):
    done = run_async(_session(limits, **kwargs))
    outcome, row = done["outcome"], done["row"]
    assert outcome.error is None and outcome.result["interactive"]["end_reason"] == reason and outcome.capture["end_reason"] == reason
    assert outcome.result["source"] == "interactive" and len(outcome.capture["requests"]) > 5
    assert row == {"state": "ended", "end_reason": reason, "vnc_password": None, "vnc_host": None, "ended": True,
                   "idle_s": limits["interactive_idle_s"], "max_s": limits["interactive_max_s"]}
    assert done["x11vnc"] == 0 and done["xvfb"] == 0
    assert done["elapsed"] < 45


def test_session_without_valid_row_does_not_open_a_browser():
    async def scenario():
        pool = await asyncpg.create_pool(host=settings.postgres_host, user=settings.postgres_user,
                                         password=settings.postgres_password.get_secret_value(), database=settings.postgres_db, min_size=1, max_size=2)
        try:
            return await interactive.run(pool, {"id": uuid.uuid4(), "url": SITE + "/", "attempts": 1}, "test")
        finally:
            await pool.close()

    outcome = run_async(scenario())
    assert outcome.capture is None and outcome.error["error_code"] == "INTERACTIVE_INVALID"
    assert _alive("x11vnc -display") == 0
