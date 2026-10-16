"""v1.4: captura interactiva (sesión, relé VNC, marca en el reporte) e indicador de recursos."""

import json
import time
import uuid

import pytest
from sqlalchemy import delete, text
from starlette.websockets import WebSocketDisconnect

from app.config import Settings
from app.db import SessionLocal
from app.masking import mask_report
from app.models import Job
from app.report_html import render_scan_report
from app.routes import panel as panel_routes
from app.routes import interactive, resources
from app.routes.analysis import interactive_section, report_validator

FIXTURE = "http://site.fixtures.test/"
ORIGIN = {"origin": "http://testserver", "host": "testserver"}


def wait_for(probe, timeout_s, what):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.5)
    raise AssertionError(f"tiempo agotado esperando: {what}")


def sample(ts, usage, memory, limit=1000, inactive=0):
    return {"ts": ts, "cpu_usage_usec": usage, "memory_current": memory, "memory_inactive_file": inactive, "memory_max": limit,
            "cpu_quota_usec": 200000, "cpu_period_usec": 100000, "pids_current": 3, "pids_max": 100}


# --- indicador de recursos ---


@pytest.mark.needs_stack  # lee los contadores de cgroup de los servicios en marcha; se omite en CI.
def test_resources_reports_every_service_from_its_own_cgroup(client):
    client.get("/api/resources")
    time.sleep(1.2)  # la respuesta se reutiliza 1 s; la segunda muestra permite calcular la CPU
    body = wait_for(lambda: (lambda b: b if b["totals"]["services_reporting"] == 5 else None)(client.get("/api/resources").json()), 30, "5 servicios")
    assert [item["service"] for item in body["services"]] == ["frontend", "api", "worker", "db", "egress-proxy"]
    for item in body["services"]:
        assert item["status"] == "ok" and item["memory_bytes"] > 0 and item["memory_limit_bytes"] > item["memory_bytes"], item
        assert 0 < item["memory_percent"] < 100 and item["pids"] >= 1 and item["cpu_limit_percent"] > 0, item
    api = next(item for item in body["services"] if item["service"] == "api")
    assert api["cpu_percent"] is not None and 0 <= api["cpu_percent"] <= api["cpu_limit_percent"] * 1.5
    totals = body["totals"]
    assert totals["memory_bytes"] == sum(item["memory_bytes"] for item in body["services"])
    assert totals["memory_limit_bytes"] == sum(item["memory_limit_bytes"] for item in body["services"])
    assert isinstance(body["scans"]["running"], int) and isinstance(body["scans"]["queued"], int)
    assert body["interactive"]["active"] in (True, False) and body["memory_alert_percent"] == 85.0 and body["refresh_s"] == 5


def test_cpu_is_a_delta_and_missing_data_is_never_invented():
    aggregator = resources.Aggregator()
    aggregator.add("api", sample(100.0, 1_000_000, 500))
    first = aggregator.describe("api", True, 85)
    # Una sola muestra: hay memoria, pero el uso de CPU aún no se puede calcular.
    assert first["status"] == "ok" and first["cpu_percent"] is None and first["memory_percent"] == 50.0
    aggregator.add("api", sample(105.0, 3_500_000, 500))
    second = aggregator.describe("api", True, 85)
    assert second["cpu_percent"] == 50.0 and second["cpu_limit_percent"] == 200.0  # 2,5 s de CPU en 5 s = medio núcleo
    aggregator.add("api", sample(105.0, 9_999_999, 500))  # misma marca de tiempo: no es una muestra nueva
    assert aggregator.describe("api", True, 85)["cpu_percent"] == 50.0
    stale = aggregator.describe("api", False, 85)
    assert stale["status"] == "no_disponible" and stale["memory_bytes"] is None and stale["cpu_percent"] is None and stale["alert"] is False
    assert aggregator.describe("worker", True, 85)["status"] == "no_disponible"


def test_memory_alert_above_85_percent_of_the_limit():
    aggregator = resources.Aggregator()
    aggregator.add("worker", sample(1.0, 0, 850))
    assert aggregator.describe("worker", True, 85)["alert"] is False  # 85 % justo no es "superar"
    aggregator.add("worker", sample(2.0, 0, 860))
    described = aggregator.describe("worker", True, 85)
    assert described["alert"] is True and described["memory_percent"] == 86.0
    # La caché de archivos inactiva no cuenta como memoria en uso.
    aggregator.add("worker", sample(3.0, 0, 960, inactive=200))
    assert aggregator.describe("worker", True, 85)["alert"] is False
    # Sin límite (memory.max = "max") no hay porcentaje ni aviso.
    aggregator.add("worker", {**sample(4.0, 0, 999), "memory_max": None})
    unlimited = aggregator.describe("worker", True, 85)
    assert unlimited["memory_percent"] is None and unlimited["alert"] is False


def test_cgroup_parsing_and_untrusted_samples():
    files = {"cpu_stat": "usage_usec 42\nuser_usec 1\n", "memory_current": "1000\n", "memory_stat": "anon 5\ninactive_file 300\n",
             "memory_max": "max\n", "cpu_max": "max 100000\n", "pids_current": "7\n", "pids_max": "200\n"}
    parsed = resources.parse_sample(files, 1.5)
    assert parsed == {"ts": 1.5, "cpu_usage_usec": 42, "memory_current": 1000, "memory_inactive_file": 300, "memory_max": None,
                      "cpu_quota_usec": None, "cpu_period_usec": 100000, "pids_current": 7, "pids_max": 200}
    assert resources.clean_sample({**parsed, "extra": "<img src=x onerror=alert(1)>"}) == parsed
    for hostile in ("texto", None, [], {**parsed, "memory_current": "<script>"}, {**parsed, "pids_current": -1}, {**parsed, "ts": None}, {**parsed, "ts": True}):
        assert resources.clean_sample(hostile) is None


@pytest.mark.needs_stack  # lee el estado de los servicios en marcha; se omite en CI.
def test_resources_survives_an_unreachable_frontend(client, monkeypatch):
    def unreachable(url):
        raise OSError("sin ruta")

    monkeypatch.setattr(resources, "_fetch_frontend", unreachable)
    monkeypatch.setitem(resources._cache, "body", None)
    body = client.get("/api/resources").json()
    frontend = next(item for item in body["services"] if item["service"] == "frontend")
    assert frontend["status"] == "no_disponible" and frontend["memory_bytes"] is None
    assert body["totals"]["services_reporting"] == 4 and body["totals"]["memory_bytes"] > 0
    monkeypatch.setitem(resources._cache, "body", None)


# --- captura interactiva ---


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://db:5432/", "http://worker:5900/", "file:///etc/passwd", "http://10.0.0.1/"])
def test_interactive_start_rejects_internal_targets(client, url):
    response = client.post("/api/interactive", json={"url": url})
    assert response.status_code == 400 and response.json()["stage"] == "url_validation"
    assert client.get("/api/interactive").json()["session"] is None


def test_interactive_is_disabled_in_demo_mode(client, monkeypatch):
    demo = Settings(postgres_user="u", postgres_password="p", postgres_db="d", demo_mode="1")
    monkeypatch.setattr(interactive, "get_settings", lambda: demo)
    assert client.get("/api/interactive").json() == {"enabled": False, "session": None, "warning": interactive.WARNING}
    for response in (client.post("/api/interactive", json={"url": FIXTURE}), client.post(f"/api/interactive/{uuid.uuid4()}/stop")):
        assert response.status_code == 403 and response.json()["error_code"] == "INTERACTIVE_DISABLED"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/interactive/{uuid.uuid4()}/ws?token={'t' * 40}", headers=ORIGIN):
            pass


@pytest.mark.needs_stack  # necesita el worker en marcha para la sesión interactiva; se omite en CI.
def test_interactive_session_end_to_end(client):
    """Sesión real contra el worker: una a la vez, relé con token y origen, detener, analizar y reporte marcado."""
    created = client.post("/api/interactive", json={"url": FIXTURE})
    assert created.status_code == 201, created.text
    body = created.json()
    job_id, token = body["job_id"], body["token"]
    try:
        assert body["state"] == "starting" and len(token) >= 32 and len(body["vnc_password"]) == 8 and "cuentas reales" in body["warning"]
        # Una sesión a la vez.
        busy = client.post("/api/interactive", json={"url": FIXTURE})
        assert busy.status_code == 409 and busy.json()["error_code"] == "INTERACTIVE_BUSY"

        session = wait_for(lambda: (lambda s: s if s and s["state"] == "ready" else None)(client.get("/api/interactive").json()["session"]), 60, "sesión lista")
        assert session["job_id"] == job_id and session["idle_limit_s"] == 600 and session["max_duration_s"] == 1800
        assert 0 < session["idle_remaining_s"] <= 600 and 0 < session["remaining_s"] <= 1800
        # El estado público no entrega ni el token ni la contraseña del visor, y la base solo guarda el hash.
        assert token not in client.get("/api/interactive").text and body["vnc_password"] not in client.get("/api/interactive").text
        assert token not in client.get(f"/api/scans/{job_id}").text

        async def stored():
            async with SessionLocal() as db:
                return (await db.execute(text("SELECT token_hash, vnc_host FROM interactive_sessions WHERE job_id = :id"), {"id": job_id})).one()

        token_hash, vnc_host = client.portal.call(stored)
        assert token not in token_hash and len(token_hash) == 64 and vnc_host.startswith("172.30.2.")  # red `internal`
        resources._cache["body"] = None
        assert client.get("/api/resources").json()["interactive"] == {"active": True, "job_id": job_id}

        # Relé VNC: sin token válido, con otro origen o para otra sesión no hay pantalla.
        for path, headers in (
            (f"/api/interactive/{job_id}/ws?token={'x' * 43}", ORIGIN),
            (f"/api/interactive/{job_id}/ws", ORIGIN),
            (f"/api/interactive/{job_id}/ws?token={token}", {"origin": "http://evil.example", "host": "testserver"}),
            (f"/api/interactive/{uuid.uuid4()}/ws?token={token}", ORIGIN),
        ):
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(path, headers=headers):
                    pass
        with client.websocket_connect(f"/api/interactive/{job_id}/ws?token={token}", headers=ORIGIN) as socket:
            assert socket.receive_bytes().startswith(b"RFB 003.")  # saludo del servidor VNC del worker

        stopped = client.post(f"/api/interactive/{job_id}/stop")
        assert stopped.status_code == 200 and stopped.json()["state"] == "stopping"
        wait_for(lambda: client.get("/api/interactive").json()["session"] is None, 60, "sesión cerrada")
        # Al terminar se borran la contraseña y la dirección del VNC, y el relé deja de aceptar el token.
        async def after():
            async with SessionLocal() as db:
                return (await db.execute(text("SELECT state, end_reason, vnc_password, vnc_host FROM interactive_sessions WHERE job_id = :id"), {"id": job_id})).one()

        assert tuple(client.portal.call(after)) == ("ended", "user_stop", None, None)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/api/interactive/{job_id}/ws?token={token}", headers=ORIGIN):
                pass
        assert client.post(f"/api/interactive/{job_id}/stop").json()["state"] == "ended"

        scan = wait_for(lambda: (lambda s: s if s["analysis_status"] in ("completed", "failed") else None)(client.get(f"/api/scans/{job_id}").json()), 120, "análisis")
        assert scan["status"] == "completed" and scan["analysis_status"] == "completed" and scan["source"] == "interactive"
        assert scan["result"]["capture"]["total_requests"] > 5 and scan["result"]["capture"]["end_reason"] == "user_stop"
        report = client.get(f"/api/scans/{job_id}/report").json()
        assert report["schema_version"] == "1.8.0" and not list(report_validator().iter_errors(report))
        assert report["scan"]["source"] == "interactive" and report["scan"]["import"] is None
        assert report["scan"]["interactive"]["masked_fields"] == []  # nada que enmascarar en esta sesión
        timeline = report["scan"]["interactive"]["timeline"]
        assert report["scan"]["interactive"]["end_reason"] == "user_stop" and timeline[0]["url"] == FIXTURE and timeline[0]["title"] == "Fixture Site"
        # Misma instrumentación que un scan: el reporte trae fingerprinting instrumentado y cookies.
        assert report["fingerprinting"]["instrumented"] is True
        listed = client.get("/api/scans?limit=50").json()["items"]
        assert next(item for item in listed if item["job_id"] == job_id)["source"] == "interactive"
        html = render_scan_report(report, "0" * 64)
        assert "Captura interactiva: una persona navegó" in html and "Captura interactiva: páginas visitadas" in html
    finally:
        async def cleanup():
            async with SessionLocal() as db:
                await db.execute(text("UPDATE interactive_sessions SET stop_requested = true WHERE job_id = :id"), {"id": job_id})
                await db.commit()

        client.portal.call(cleanup)
        wait_for(lambda: client.get("/api/interactive").json()["session"] is None, 60, "limpieza de la sesión")

        async def remove():
            async with SessionLocal() as db:
                await db.execute(delete(Job).where(Job.id == uuid.UUID(job_id)))
                await db.commit()

        client.portal.call(remove)


def test_stale_session_frees_the_slot(client):
    """Si el job de la sesión ya terminó (worker caído, lease vencido), la sesión se cierra sola."""
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as db:
            db.add(Job(id=job_id, url=FIXTURE, status="failed", options={"source": "interactive"}))
            await db.flush()
            db.add(interactive.InteractiveSession(job_id=job_id, token_hash="0" * 64, vnc_password="12345678", state="ready"))
            await db.commit()

    async def remove():
        async with SessionLocal() as db:
            await db.execute(delete(Job).where(Job.id == job_id))
            await db.commit()

    client.portal.call(insert)
    try:
        assert client.get("/api/interactive").json()["session"] is None

        async def row():
            async with SessionLocal() as db:
                return (await db.execute(text("SELECT state, end_reason, vnc_password FROM interactive_sessions WHERE job_id = :id"), {"id": job_id})).one()

        assert tuple(client.portal.call(row)) == ("ended", "worker_lost", None)
    finally:
        client.portal.call(remove)


def test_timeline_from_the_visited_site_is_revalidated_and_masked():
    hostile = '<img src=x onerror="window.__XSS=1">'
    result = {"source": "interactive", "interactive": {
        "timeline": [{"seq": 9, "ts": "2026-10-12T10:00:00+00:00", "url": "https://shop.example/u/1234567890abcdef1234?token=secretosecreto123", "title": hostile, "tab": 1},
                     "basura", {"url": 5}, {"url": "https://shop.example/b", "title": 7, "tab": "x"}],
        "end_reason": "<script>", "tabs": "2", "idle_limit_s": 600, "max_duration_s": None}}
    section = interactive_section(result)
    assert [entry["seq"] for entry in section["timeline"]] == [0, 1] and section["end_reason"] == "user_stop" and section["tabs"] == 1
    assert section["timeline"][1] == {"seq": 1, "ts": "", "url": "https://shop.example/b", "title": None, "tab": 1}
    assert interactive_section({"source": "scan", "interactive": result["interactive"]}) is None
    report = {"scan": {"url": "https://shop.example/", "final_url": "https://shop.example/", "source": "interactive", "interactive": section}}
    masked = mask_report(report)
    assert "secretosecreto123" not in str(masked) and "secretosecreto123" in str(report)
    html = render_scan_report({**report, "site": {}, "capture": {}, "analysis": {}}, "0" * 64)
    assert hostile not in html and "&lt;img src=x onerror=" in html


# --- v1.4.1 ---


def test_panel_ranking_excludes_interactive_captures_and_lists_them_apart(client, monkeypatch):
    # Sin tope: las organizaciones de los scans reales de la instalación pueden ocupar los 10 primeros puestos.
    monkeypatch.setattr(panel_routes, "TOP_ORGANIZATIONS", 10_000)
    monkeypatch.setattr(panel_routes, "TOP_SITES", 10_000)
    ids = {"scan": uuid.uuid4(), "interactive": uuid.uuid4()}

    async def insert():
        async with SessionLocal() as db:
            for source, job_id in ids.items():
                db.add(Job(id=job_id, url=f"https://v141-{source}.example/", status="completed", analysis_status="completed",
                           options={"source": source} if source != "scan" else None, result={"source": source}))
                await db.flush()
                await db.execute(
                    text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                         "VALUES (:job, '1.10.0', 'abc', '[]', :score, 'Alto', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 10)"),
                    {"job": job_id, "score": 70 if source == "scan" else 99,
                     "summary": json.dumps({"requests": 10, "trackers": 3, "source": source, "blocking": {"blocked": False},
                                            "entities": [{"entity": "Organización V141", "requests": 4}]})})
            await db.commit()

    async def remove():
        async with SessionLocal() as db:
            await db.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": list(ids.values())})
            await db.commit()

    client.portal.call(insert)
    try:
        panel = client.get("/api/panel?include_tests=true").json()
        ranked = {item["job_id"] for item in panel["ranking"]}
        assert str(ids["scan"]) in ranked and str(ids["interactive"]) not in ranked
        apart = [item for item in panel["partial_sites"] if item["job_id"] == str(ids["interactive"])]
        assert apart == [{"site": "v141-interactive.example", "job_id": str(ids["interactive"]), "site_exposure_score": 99, "band": "Alto", "source": "interactive"}]
        # Sigue contando para organizaciones y totales: solo sale del ranking por índice.
        organization = next(item for item in panel["organizations"] if item["entity"] == "Organización V141")
        assert organization["sites"] == 2 and panel["totals"]["partial_sites"] == len(panel["partial_sites"])
    finally:
        client.portal.call(remove)


def test_masked_fields_are_revalidated_and_reported_without_values():
    base = {"source": "interactive", "interactive": {"timeline": [], "end_reason": "user_stop"}}
    assert interactive_section(base)["masked_fields"] is None  # captura anterior a v1.4.1
    hostile = '<img src=x onerror="window.__XSS=1">'
    base["interactive"]["masked_fields"] = [{"name": "clave", "length": 12, "seq": 3, "value": "NO-DEBE-SALIR"}, {"name": hostile, "length": 4},
                                            "basura", {"name": 5, "length": 1}, {"name": "x", "length": "9"}]
    section = interactive_section(base)
    assert section["masked_fields"] == [{"name": "clave", "length": 12, "seq": 3}, {"name": hostile, "length": 4, "seq": None}]
    report = {"scan": {"url": "https://a.example/", "final_url": "https://a.example/", "source": "interactive", "interactive": section}, "site": {}, "capture": {}, "analysis": {}}
    html = render_scan_report(report, "0" * 64)
    assert "2 valores de credenciales fueron enmascarados antes de guardar" in html and "clave" in html
    assert hostile not in html and "NO-DEBE-SALIR" not in html
    old = render_scan_report({**report, "scan": {**report["scan"], "interactive": {**section, "masked_fields": None}}}, "0" * 64)
    assert "NO se enmascararon" in old
    none = render_scan_report({**report, "scan": {**report["scan"], "interactive": {**section, "masked_fields": []}}}, "0" * 64)
    assert "No se detectaron campos de contraseña" in none
