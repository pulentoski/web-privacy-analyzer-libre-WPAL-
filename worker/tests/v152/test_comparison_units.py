"""v1.5.2: comparación de visitas, piezas sin navegador (perfiles en disco, huellas, cola)."""

import dataclasses
import hashlib
import json
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import comparison, jobs
from app.browser import launcher
from app.config import settings
from tests.helpers import run_async

CID = str(uuid.uuid4())


@pytest.fixture
def profiles_root(tmp_path, monkeypatch):
    monkeypatch.setattr(comparison, "settings", dataclasses.replace(settings, comparison_profiles_dir=str(tmp_path)))
    return tmp_path


def job(options):
    return {"options": json.dumps(options), "url": "http://site.fixtures.test/v152/", "id": uuid.uuid4()}


def test_job_visit_only_for_valid_comparison_options():
    assert comparison.job_visit(job({"comparison": {"id": CID, "visit": 2}})) == {"id": CID, "visit": 2, "profile": "A"}
    assert comparison.job_visit(job({"comparison": {"id": CID, "visit": 3}}))["profile"] == "B"
    for bad in ({}, {"comparison": {"id": CID, "visit": 4}}, {"comparison": {"id": "../etc", "visit": 1}}, {"comparison": "x"}, {"scenario": "aceptar"}):
        assert comparison.job_visit(job(bad)) is None
    # El resto de opciones del scan no cambia: la comparación no es una opción de run_scan.
    assert jobs.job_options(job({"comparison": {"id": CID, "visit": 1}})) == {}


def test_profile_dir_only_from_uuid_and_known_profile(profiles_root):
    assert comparison.profile_dir(CID, "A") == profiles_root / CID / "A"
    assert comparison.profile_dir(CID, "B") != comparison.profile_dir(CID, "A")
    with pytest.raises(ValueError):
        comparison.profile_dir("../../x", "A")
    with pytest.raises(ValueError):
        comparison.profile_dir(CID, "C")


def test_cookie_fingerprints_keep_hashes_never_values():
    cookies = [
        {"name": "uid", "value": "secreto-123", "domain": "a.test", "path": "/", "expires": 2_000_000_000},
        {"name": "sess", "value": "s", "domain": "a.test", "path": "/", "expires": -1},
    ]
    result = comparison.cookie_fingerprints(cookies)
    assert result["session"] == 1
    assert result["persistent"] == [{"domain": "a.test", "path": "/", "name": "uid", "sha256": hashlib.sha256(b"secreto-123").hexdigest(), "expires": 2e9}]
    assert "secreto-123" not in json.dumps(result)


def test_missing_cookies_ignores_expired_and_detects_changed_values():
    def fp(name, value, expires):
        return comparison.cookie_fingerprints([{"name": name, "value": value, "domain": "a.test", "path": "/", "expires": expires}])["persistent"][0]
    expected = [fp("uid", "1", 2e9), fp("old", "1", 100), fp("other", "x", 2e9)]
    loaded = [fp("uid", "1", 2e9), fp("other", "y", 2e9)]
    assert comparison.missing_cookies(expected, loaded, at_epoch=1e9) == [{"domain": "a.test", "path": "/", "name": "other"}]


def test_manifest_changes_with_content_and_inventory_reads_stores(tmp_path):
    (tmp_path / "Default" / "IndexedDB" / "http_site.fixtures.test_0.indexeddb.leveldb").mkdir(parents=True)
    (tmp_path / "Default" / "Local Storage" / "leveldb").mkdir(parents=True)
    (tmp_path / "Default" / "Local Storage" / "leveldb" / "000003.log").write_bytes(b"x" * 10)
    (tmp_path / "Default" / "Cookies").write_bytes(b"db")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "data_1").write_bytes(b"y" * 5)
    first = comparison.manifest(tmp_path)
    assert first == comparison.manifest(tmp_path)
    assert comparison.inventory(tmp_path) == {
        "cookies_db": True, "local_storage_bytes": 10, "indexeddb_origins": ["http_site.fixtures.test_0"],
        "indexeddb_bytes": 0, "cache_bytes": 5,
    }
    (tmp_path / "Default" / "Cookies").write_bytes(b"otro")
    assert comparison.manifest(tmp_path)["digest"] != first["digest"]


def test_clean_profiles_are_new_empty_private_dirs(profiles_root):
    a = comparison.ProfileSession({"id": CID, "visit": 1, "profile": "A"}, None)
    a.prepare()
    assert a.state["start"] == {"dir_existed": False, "files_before_launch": 0}
    assert stat.S_IMODE(os.stat(a.path).st_mode) == 0o700 and stat.S_IMODE(os.stat(a.path.parent).st_mode) == 0o700
    # Un perfil «limpio» que ya existía no lo sería: la visita falla en vez de reutilizarlo.
    with pytest.raises(comparison.ProfileError) as error:
        comparison.ProfileSession({"id": CID, "visit": 1, "profile": "A"}, None).prepare()
    assert error.value.code == "COMPARISON_PROFILE_NOT_CLEAN"
    (a.path / "Default").mkdir()
    (a.path / "Default" / "Cookies").write_bytes(b"estado de A")
    b = comparison.ProfileSession({"id": CID, "visit": 3, "profile": "B"}, None)
    b.prepare()
    assert b.state["start"] == {"dir_existed": False, "files_before_launch": 0, "separate_from_a": True}
    assert list(b.path.iterdir()) == []


def visit1_state(path):
    session = comparison.ProfileSession({"id": CID, "visit": 1, "profile": "A"}, None)
    session.record_disk()
    return session.state


def test_profile_a_state_checked_before_visit_2(profiles_root):
    path = profiles_root / CID / "A"
    (path / "Default").mkdir(parents=True)
    (path / "Default" / "Cookies").write_bytes(b"cookies de la visita 1")
    previous = visit1_state(path)
    intact = comparison.ProfileSession({"id": CID, "visit": 2, "profile": "A"}, previous)
    intact.prepare()
    assert intact.state["start"]["manifest_matches"] is True and intact.state["start"]["manifest_changed_count"] == 0
    (path / "Default" / "Cookies").write_bytes(b"cambiado")
    changed = comparison.ProfileSession({"id": CID, "visit": 2, "profile": "A"}, previous)
    changed.prepare()
    assert changed.state["start"]["manifest_matches"] is False
    assert changed.state["start"]["manifest_changed_files"] == ["Default/Cookies"]
    comparison.remove(CID)
    lost = comparison.ProfileSession({"id": CID, "visit": 2, "profile": "A"}, previous)
    with pytest.raises(comparison.ProfileError) as error:
        lost.prepare()
    assert error.value.code == "COMPARISON_STATE_LOST"


class FakeContext:
    def __init__(self, cookies):
        self._cookies = cookies

    async def cookies(self):
        return self._cookies


def test_visit_2_compares_loaded_cookies_with_visit_1(profiles_root):
    future = datetime.now(timezone.utc).timestamp() + 3600
    uid = {"name": "uid", "value": "abc", "domain": "a.test", "path": "/", "expires": future}
    previous = {"end": {"cookies": comparison.cookie_fingerprints([uid, {**uid, "name": "gone"}])}}
    session = comparison.ProfileSession({"id": CID, "visit": 2, "profile": "A"}, previous)
    run_async(session.before_navigation(FakeContext([uid])))
    start = session.state["start"]
    assert start["cookies_read"] and start["cookies_at_start"] == 1
    assert start["persistent_cookies_expected"] == 2 and start["persistent_cookies_missing"] == 1
    assert start["missing_examples"] == [{"domain": "a.test", "path": "/", "name": "gone"}]


def test_interval_starts_when_visit_1_closes():
    closed = "2026-10-18T10:00:00.000+00:00"
    assert comparison.next_not_before(1, closed, 300) == datetime(2026, 10, 18, 10, 5, tzinfo=timezone.utc)
    assert comparison.next_not_before(2, closed, 300) == datetime(2026, 10, 18, 10, 0, tzinfo=timezone.utc)
    assert comparison.next_not_before(1, None, 0) - datetime.now(timezone.utc) < timedelta(seconds=5)


def test_persistent_context_options_match_the_ephemeral_ones():
    options = launcher.persistent_kwargs("/var/lib/wpa/profiles/x/A", "scan-1")
    base = {**launcher.launch_kwargs("scan-1"), **launcher.context_kwargs()}
    assert options["args"] == [*base["args"], "--disk-cache-dir=/var/lib/wpa/profiles/x/A/cache"]
    assert {key: value for key, value in options.items() if key != "args"} == {key: value for key, value in base.items() if key != "args"}


def test_comparison_rejects_scenario_profile_and_probe():
    from app.browser.capture import _run_scan

    for kwargs in ({"scenario": "aceptar"}, {"profile_name": "android"}, {"probe": True}):
        args = {"scenario": None, "profile_name": None, "probe": False, **kwargs}
        with pytest.raises(ValueError):
            run_async(_run_scan("http://x.test/", 1, None, None, None, None, args["scenario"], args["profile_name"], args["probe"],
                                "scan-1", None, None, object()))


def test_claim_waits_for_not_before_and_comparison_sql_is_scoped():
    assert "not_before IS NULL OR not_before <= now()" in jobs.CLAIM_SQL
    assert "comparison_id = $1" in jobs.COMPARISON_RELEASE_SQL and "status = 'queued'" in jobs.COMPARISON_RELEASE_SQL
    assert "q.comparison_id IS NOT NULL" in jobs.COMPARISON_ABORT_SQL and "f.status = 'failed'" in jobs.COMPARISON_ABORT_SQL
