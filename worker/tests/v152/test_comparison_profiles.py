"""v1.5.2: perfiles A y B con Chromium real contra el sitio de fixtures.

Comprueba lo que la comparación da por hecho: el estado de A se conserva en disco entre las visitas 1 y 2, y B no
comparte nada con A (cookies, localStorage, IndexedDB ni caché HTTP). También que un scan normal sigue usando el
contexto efímero de siempre.
"""

import dataclasses
import json
import os
import pathlib
import shutil
import stat
import time
import urllib.parse
import urllib.request
import uuid

import pytest

from app import comparison
from app.browser import capture as capture_module
from app.browser.capture import run_scan
from app.config import settings
from tests.helpers import fixtures_call, run_async

PAGE = "http://site.fixtures.test/v152/"
API = "http://api:8000"


@pytest.fixture
def profiles_root(tmp_path, monkeypatch):
    monkeypatch.setattr(comparison, "settings", dataclasses.replace(settings, comparison_profiles_dir=str(tmp_path)))
    return tmp_path


def visit(cid, number, previous=None):
    session = comparison.ProfileSession({"id": cid, "visit": number, "profile": comparison.PROFILE_BY_VISIT[number]}, previous)
    session.prepare()
    outcome = run_async(run_scan(PAGE, proxy_user=f"scan-{uuid.uuid4()}", profile_session=session))
    session.record_disk()
    assert outcome.error is None, outcome.error
    return outcome.capture, session.state


def cookie(capture, name):
    values = [c["value"] for c in capture["cookies"] if c["name"] == name]
    return values[0] if values else None


def storage(capture, key):
    values = [s["value"] for s in capture["storage"] if s["key"] == key and s["storage_type"] == "local"]
    return values[0] if values else None


def pixel(capture):
    found = [r for r in capture["requests"] if r["host"] == "tracker-a.fixtures.test" and r["path"] == "/v152/px"]
    assert len(found) == 1
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(found[0]["url"]).query, keep_blank_values=True))


def server_hits(path):
    return sum(1 for r in fixtures_call("/__received")["requests"] if r["path"] == path)


def paths(capture):
    return {r["path"] for r in capture["requests"]}


@pytest.fixture
def three_visits(fixtures_site, profiles_root):
    fixtures_call("/__reset", method="POST")
    cid = str(uuid.uuid4())
    v1, s1 = visit(cid, 1)
    cache_after_1 = server_hits("/v152/cached.js")
    v2, s2 = visit(cid, 2, s1)
    cache_after_2 = server_hits("/v152/cached.js")
    v3, s3 = visit(cid, 3)
    cache_after_3 = server_hits("/v152/cached.js")
    return {"cid": cid, "captures": (v1, v2, v3), "states": (s1, s2, s3), "cache": (cache_after_1, cache_after_2, cache_after_3),
            "root": profiles_root}


def test_profile_a_state_is_kept_on_disk_between_visits_1_and_2(three_visits):
    (v1, v2, _), (s1, s2, _) = three_visits["captures"], three_visits["states"]
    # Lo que quedó en disco al cerrar la visita 1 es lo que encontró la visita 2 antes de abrir el navegador.
    assert s2["start"]["manifest_matches"] is True, s2["start"]
    assert s1["end"]["inventory"]["cookies_db"] and s1["end"]["inventory"]["local_storage_bytes"] > 0
    assert any("site.fixtures.test" in origin for origin in s1["end"]["inventory"]["indexeddb_origins"])
    assert s1["end"]["inventory"]["cache_bytes"] > 0
    # Al abrir, el perfil cargó la cookie persistente de la visita 1 con el mismo valor; la de sesión no sobrevivió.
    assert s2["start"]["cookies_read"] and s2["start"]["persistent_cookies_missing"] == 0
    assert s2["start"]["persistent_cookies_expected"] >= 1
    assert s2["start"]["cookies_at_start"] == s2["start"]["persistent_cookies_expected"]
    assert cookie(v1, "v152_uid") == cookie(v2, "v152_uid")
    assert cookie(v1, "v152_sess") != cookie(v2, "v152_sess")
    # localStorage e IndexedDB: los mismos valores (la página los lee de vuelta y los envía en la URL del píxel).
    assert storage(v1, "v152_ls") == storage(v2, "v152_ls") == pixel(v2)["ls"]
    assert pixel(v1)["idb"] and pixel(v1)["idb"] == pixel(v2)["idb"]
    # Solo el perfil que volvió con estado pidió el recurso de bienvenida.
    assert "/v152/welcome-back.gif" not in paths(v1) and "/v152/welcome-back.gif" in paths(v2)


def test_profile_b_shares_nothing_with_profile_a(three_visits):
    (v1, v2, v3), (_, _, s3) = three_visits["captures"], three_visits["states"]
    assert s3["start"] == {"dir_existed": False, "files_before_launch": 0, "separate_from_a": True,
                           "cookies_read": True, "cookies_at_start": 0}
    assert cookie(v3, "v152_uid") not in (None, cookie(v1, "v152_uid"))
    assert storage(v3, "v152_ls") not in (None, storage(v1, "v152_ls"))
    assert pixel(v3)["idb"] and pixel(v3)["idb"] != pixel(v1)["idb"]
    assert "/v152/welcome-back.gif" not in paths(v3)
    # Caché HTTP: Playwright la desactiva en todos los scans al autenticar el proxy (Network.setCacheDisabled; las
    # requests salen con Cache-Control: no-cache). No interviene en la comparación: cada visita pide el recurso al servidor.
    assert three_visits["cache"] == (1, 2, 3)
    for capture in (v1, v2, v3):
        cached = [r for r in capture["requests"] if r["path"] == "/v152/cached.js"]
        assert len(cached) == 1
        assert {"name": "Cache-Control", "value": "no-cache"} in cached[0]["request_headers"]
    root = three_visits["root"] / three_visits["cid"]
    assert sorted(item.name for item in root.iterdir()) == ["A", "B"]
    assert (root / "B" / "cache").is_dir() and (root / "A" / "cache").is_dir()


def test_visit_1_starts_clean(three_visits):
    s1 = three_visits["states"][0]
    assert s1["start"] == {"dir_existed": False, "files_before_launch": 0, "cookies_read": True, "cookies_at_start": 0}
    assert s1["launched_at"] < s1["closed_at"]


def test_lost_or_changed_state_of_a_is_detected(fixtures_site, profiles_root):
    fixtures_call("/__reset", method="POST")
    cid = str(uuid.uuid4())
    _, s1 = visit(cid, 1)
    cookies = profiles_root / cid / "A" / "Default" / "Cookies"
    original = cookies.read_bytes()
    cookies.write_bytes(b"")
    changed = comparison.ProfileSession({"id": cid, "visit": 2, "profile": "A"}, s1)
    changed.prepare()
    assert changed.state["start"]["manifest_matches"] is False and "Default/Cookies" in changed.state["start"]["manifest_changed_files"]
    cookies.write_bytes(original)
    shutil.rmtree(profiles_root / cid / "A")
    with pytest.raises(comparison.ProfileError) as error:
        comparison.ProfileSession({"id": cid, "visit": 2, "profile": "A"}, s1).prepare()
    assert error.value.code == "COMPARISON_STATE_LOST"


def test_normal_scan_keeps_the_ephemeral_context(fixtures_site, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("un scan normal no debe usar un contexto persistente")

    monkeypatch.setattr(capture_module, "launch_persistent_context", forbidden)
    fixtures_call("/__reset", method="POST")
    first = run_async(run_scan(PAGE, proxy_user=f"scan-{uuid.uuid4()}"))
    second = run_async(run_scan(PAGE, proxy_user=f"scan-{uuid.uuid4()}"))
    assert first.error is None and second.error is None
    # Sin estado entre scans: cada uno recibe su propio identificador y pide otra vez el recurso cacheable.
    assert cookie(first.capture, "v152_uid") != cookie(second.capture, "v152_uid")
    assert "/v152/welcome-back.gif" not in paths(second.capture)
    assert server_hits("/v152/cached.js") == 2


@pytest.mark.needs_stack
def test_profiles_volume_is_private_to_the_worker_user():
    root = pathlib.Path(settings.comparison_profiles_dir)
    info = os.stat(root)
    assert info.st_uid == os.getuid() == 1001 and stat.S_IMODE(info.st_mode) == 0o700
    assert os.path.ismount(root), "los perfiles deben estar en el volumen `profiles` (disco), no en la raíz del contenedor"


def api(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(API + path, data=data, headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def wait(cid, predicate, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        body = api(f"/api/comparisons/{cid}")
        if predicate(body):
            return body
        time.sleep(1)
    raise AssertionError(f"la comparación {cid} no llegó al estado esperado: {body['status']} {[v['status'] for v in body['visits']]}")


@pytest.mark.needs_stack
def test_worker_runs_the_three_visits_and_removes_the_profiles(fixtures_site):
    """Con el worker real: la visita 2 espera el intervalo, la 3 va después, y los perfiles se borran al terminar."""
    fixtures_call("/__reset", method="POST")
    cid = api("/api/comparisons", {"url": PAGE, "interval_s": 5})["comparison_id"]
    root = pathlib.Path(settings.comparison_profiles_dir) / cid
    waiting = wait(cid, lambda body: body["visits"][0]["status"] in ("completed", "failed") and body["visits"][1]["status"] == "queued")
    assert waiting["visits"][0]["status"] == "completed"
    assert (root / "A").is_dir() and not (root / "B").exists()
    assert stat.S_IMODE(os.stat(root / "A").st_mode) == 0o700
    done = wait(cid, lambda body: body["status"] != "en_curso")
    assert done["status"] == "valida", done["validity"]
    assert done["interval"]["configured_s"] == 5 and done["interval"]["real_s"] >= 5
    assert not root.exists()


@pytest.mark.needs_stack
def test_lost_state_of_a_invalidates_the_comparison(fixtures_site):
    fixtures_call("/__reset", method="POST")
    cid = api("/api/comparisons", {"url": PAGE, "interval_s": 30})["comparison_id"]
    root = pathlib.Path(settings.comparison_profiles_dir) / cid
    wait(cid, lambda body: body["visits"][0]["status"] in ("completed", "failed") and body["visits"][1]["status"] == "queued")
    shutil.rmtree(root / "A")
    done = wait(cid, lambda body: body["status"] != "en_curso", timeout_s=180)
    assert done["status"] == "no_valida" and done["validity"]["valid"] is False
    assert [visit["error_code"] for visit in done["visits"]] == [None, "COMPARISON_STATE_LOST", "COMPARISON_ABORTED"]
    assert any("Se perdió el estado del perfil A" in reason for reason in done["validity"]["reasons"])
    assert done["result"] is None
    assert not root.exists()
