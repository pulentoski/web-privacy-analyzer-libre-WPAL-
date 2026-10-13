"""Retención (F9, criterio 8): lo antiguo se purga con todo lo suyo; lo reciente y lo activo no."""

import asyncio
import uuid

import asyncpg
import pytest

from app.config import settings
from app.retention import purge


async def connect():
    return await asyncpg.connect(host=settings.postgres_host, user=settings.postgres_user,
                                 password=settings.postgres_password.get_secret_value(), database=settings.postgres_db)


async def scenario():
    conn = await connect()
    ids = {name: uuid.uuid4() for name in ("old", "old_failed", "recent", "edge", "old_analyzing", "old_group_job")}
    groups = {name: uuid.uuid4() for name in ("old_group", "old_empty_group", "recent_group")}
    try:
        for name, age_days in (("old_group", 45), ("old_empty_group", 45), ("recent_group", 2)):
            await conn.execute("INSERT INTO test_groups (id, url, config, created_at) VALUES ($1, 'http://site.example/', '{}', now() - make_interval(days => $2))", groups[name], age_days)
        rows = [
            ("old", "completed", "completed", 45, None), ("old_failed", "failed", None, 31, None), ("recent", "completed", "completed", 3, None),
            ("edge", "completed", "completed", 29, None),
            # En análisis: no se toca aunque sea antiguo. (No se usa 'queued'/'running': el worker de este stack lo tomaría.)
            ("old_analyzing", "completed", "running", 45, None), ("old_group_job", "completed", "completed", 45, groups["old_group"]),
        ]
        for name, status, analysis_status, age_days, group in rows:
            await conn.execute(
                "INSERT INTO jobs (id, url, status, analysis_status, created_at, updated_at, group_id) "
                "VALUES ($1, 'http://site.example/', $2, $3, now() - make_interval(days => $4), now(), $5)",
                ids[name], status, analysis_status, age_days, group,
            )
            await conn.execute(
                "INSERT INTO scan_requests (job_id, seq, ts, method, url, url_truncated, scheme, host, path, query_params, resource_type, is_navigation, "
                "request_headers, blocked_by_proxy) VALUES ($1, 0, now(), 'GET', 'http://site.example/', false, 'http', 'site.example', '/', '[]', 'document', true, '[]', false)",
                ids[name],
            )
            for kind in ("json", "html", "pdf"):
                await conn.execute("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES ('scan', $1, $2, false, 'x', 'ready', 'x')", ids[name], kind)
        await conn.execute("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES ('group', $1, 'pdf', false, 'x', 'ready', 'x')", groups["old_group"])

        async def state():
            return {
                "jobs": {name for name, job_id in ids.items() if await conn.fetchval("SELECT 1 FROM jobs WHERE id = $1", job_id)},
                "requests": {name for name, job_id in ids.items() if await conn.fetchval("SELECT 1 FROM scan_requests WHERE job_id = $1", job_id)},
                "reports": {name for name, job_id in ids.items() if await conn.fetchval("SELECT 1 FROM report_files WHERE subject_id = $1", job_id)},
                "groups": {name for name, group_id in groups.items() if await conn.fetchval("SELECT 1 FROM test_groups WHERE id = $1", group_id)},
                "group_reports": await conn.fetchval("SELECT count(*) FROM report_files WHERE subject_id = $1", groups["old_group"]),
            }

        before = await state()
        dry = await purge(conn, 30, dry_run=True)
        after_dry = await state()
        result = await purge(conn, 30)
        after = await state()
        again = await purge(conn, 30)
        return before, dry, after_dry, result, after, again
    finally:
        await conn.execute("DELETE FROM jobs WHERE id = ANY($1::uuid[])", list(ids.values()))
        await conn.execute("DELETE FROM test_groups WHERE id = ANY($1::uuid[])", list(groups.values()))
        await conn.close()


@pytest.fixture(scope="module")
def outcome():
    return asyncio.run(scenario())


def test_dry_run_counts_but_deletes_nothing(outcome):
    before, dry, after_dry, _, _, _ = outcome
    assert dry["dry_run"] is True and dry["scans"] >= 3 and dry["reports"] >= 9
    assert after_dry == before and len(before["jobs"]) == 6


def test_old_finished_scans_are_purged_with_their_capture_and_reports(outcome):
    _, _, _, result, after, _ = outcome
    gone = {"old", "old_failed", "old_group_job"}
    assert result["dry_run"] is False and result["scans"] >= 3 and result["reports"] >= 10
    for table in ("jobs", "requests", "reports"):
        assert not gone & after[table], table


def test_recent_and_active_scans_are_kept(outcome):
    _, _, _, _, after, _ = outcome
    kept = {"recent", "edge", "old_analyzing"}
    for table in ("jobs", "requests", "reports"):
        assert after[table] == kept, table


def test_old_groups_go_once_they_are_empty_and_recent_ones_stay(outcome):
    _, _, _, result, after, _ = outcome
    assert after["groups"] == {"recent_group"} and after["group_reports"] == 0 and result["groups"] >= 2


def test_purge_is_idempotent_and_refuses_zero_days(outcome):
    again = outcome[5]
    assert again["scans"] == 0 and again["groups"] == 0 and again["reports"] == 0

    async def zero():
        conn = await connect()
        try:
            await purge(conn, 0)
        finally:
            await conn.close()

    with pytest.raises(ValueError):
        asyncio.run(zero())
