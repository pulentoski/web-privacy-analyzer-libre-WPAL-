import asyncio
import base64
import hashlib
import json
import uuid
from collections import Counter

import asyncpg
import pytest

from app import jobs
from app.config import settings

from tests.helpers import FIXTURE_HOSTS, find, run_async


def raw_query(request: dict) -> str:
    return "&".join(name if value is None else f"{name}={value}" for name, value in request["query_params"])


def captured_key(request: dict) -> tuple:
    return (request["method"], request["host"], request["path"], raw_query(request))


def received_key(entry: dict) -> tuple:
    return (entry["method"], entry["host"], entry["path"], entry["query"])


def websocket_key(websocket: dict) -> tuple:
    # ws://host/path -> el servidor lo recibe como GET con Upgrade.
    rest = websocket["url"].split("://", 1)[1]
    host, _, path = rest.partition("/")
    path, _, query = path.partition("?")
    return ("GET", host, "/" + path, query)


# --- Criterio 2 ---


def test_page_scan_completes(outcome, capture):
    assert outcome.error is None, outcome.error
    assert outcome.result["http_status"] == 200
    assert outcome.result["title"] == "Fixture Site"
    assert capture["end_reason"] == "network_idle"
    assert capture["truncated"] is False


# --- Criterios 3 y 4: recall y precisión contra /__received ---


def test_recall_every_received_request_was_captured(capture, received):
    assert received, "el servidor de fixtures no recibió nada"
    captured = Counter(captured_key(r) for r in capture["requests"])
    captured.update(websocket_key(w) for w in capture["websockets"])
    missing = Counter(received_key(entry) for entry in received) - captured
    assert not missing, f"recibidas por el servidor pero NO capturadas: {sorted(missing.elements())}"


def test_precision_every_captured_request_was_received(capture, received):
    captured = Counter(
        captured_key(r)
        for r in capture["requests"]
        if r["host"] in FIXTURE_HOSTS and not r["failure_text"] and not r["blocked_by_proxy"]
    )
    captured.update(websocket_key(w) for w in capture["websockets"] if not w["error"])
    assert captured, "no se capturó nada hacia el sitio de fixtures"
    extra = captured - Counter(received_key(entry) for entry in received)
    assert not extra, f"capturadas pero NO recibidas por el servidor: {sorted(extra.elements())}"


def test_manifest_requests_are_all_captured(capture, manifest):
    for expected in manifest["requests"]:
        request = find(capture, expected["host"], expected["path"], expected["method"])
        assert request["resource_type"] == expected["resource_type"], expected["name"]
        assert request["response_status"] == expected.get("status", request["response_status"]), expected["name"]
        if "query" in expected:
            assert request["query_params"] == expected["query"], expected["name"]
        if "query_keys" in expected:
            assert [name for name, _ in request["query_params"]] == expected["query_keys"], expected["name"]
        if expected.get("has_body"):
            assert request["post_data"] is not None, expected["name"]


def test_request_fields_are_complete(capture):
    document = find(capture, "site.fixtures.test", "/")
    assert document["is_navigation"] is True and document["scheme"] == "http"
    assert document["mime_type"] == "text/html"
    assert document["sizes"]["responseBodySize"] > 0
    assert document["timing"]["startTime"] > 0
    assert any(h["name"].lower() == "user-agent" for h in document["request_headers"])
    assert any(h["name"].lower() == "set-cookie" for h in document["response_headers"])
    image = find(capture, "site.fixtures.test", "/img/first.png")
    assert image["is_navigation"] is False and image["frame_url"] == "http://site.fixtures.test/"
    assert image["failure_text"] is None and image["blocked_by_proxy"] is False
    seqs = [r["seq"] for r in capture["requests"]]
    assert seqs == list(range(len(seqs)))


# --- Criterio 5: post_data ---


@pytest.mark.parametrize("path", ["/beacon", "/collect"])
def test_post_data_sha256_matches_server(capture, received, path):
    request = find(capture, "tracker-a.fixtures.test", path, "POST")
    server = [entry for entry in received if entry["path"] == path and entry["method"] == "POST"]
    assert len(server) == 1
    body = request["post_data"]
    assert body["sha256"] == server[0]["body_sha256"]
    assert body["size"] == server[0]["body_size"] > 0
    assert body["truncated"] is False and body["encoding"] == "utf8"
    # El sha256 guardado corresponde al dato guardado.
    assert hashlib.sha256(body["data"].encode()).hexdigest() == body["sha256"]


def test_post_data_content(capture, manifest):
    beacon = find(capture, "tracker-a.fixtures.test", "/beacon", "POST")
    assert json.loads(beacon["post_data"]["data"]) == {"event": "beacon", "uid": manifest["analysis"]["uid"]}
    collect = find(capture, "tracker-a.fixtures.test", "/collect", "POST")
    # Se guarda tal cual llegó (Base64), sin decodificar: eso es de F3.
    assert json.loads(base64.b64decode(collect["post_data"]["data"]))["event"] == "pageview"


# --- Criterio 6: redirects ---


def test_redirect_chain_is_recorded_in_order(capture, manifest):
    chains = [[hop["url"] for hop in chain] for chain in capture["redirects"]]
    assert manifest["redirect_chain"] in chains
    chain = capture["redirects"][chains.index(manifest["redirect_chain"])]
    assert [hop["status"] for hop in chain] == [302, 301, 200]
    by_seq = {r["seq"]: r for r in capture["requests"]}
    assert by_seq[chain[0]["request_seq"]]["redirected_from_seq"] is None
    assert by_seq[chain[1]["request_seq"]]["redirected_from_seq"] == chain[0]["request_seq"]
    assert by_seq[chain[2]["request_seq"]]["redirected_from_seq"] == chain[1]["request_seq"]


# --- Criterio 7: WebSocket ---


def test_websocket_frames(capture, manifest):
    sockets = [w for w in capture["websockets"] if w["url"] == manifest["websocket"]["url"]]
    assert len(sockets) == 1
    socket = sockets[0]
    assert (socket["frames_sent"], socket["frames_received"]) == (3, 3)
    assert socket["frames_truncated"] is False and socket["error"] is None
    sent = [f["data"] for f in socket["frames"] if f["direction"] == "sent"]
    got = [f["data"] for f in socket["frames"] if f["direction"] == "received"]
    assert sent == manifest["websocket"]["sent"]
    assert got == manifest["websocket"]["received"]
    assert all(f["encoding"] == "utf8" and f["opcode"] == "text" for f in socket["frames"])


# --- Criterio 8: initiator ---


def test_initiator_attributes_requests_to_their_script(capture, manifest):
    for expected in manifest["requests"]:
        if "initiator_script" not in expected:
            continue
        request = find(capture, expected["host"], expected["path"], expected["method"])
        initiator = request["initiator"]
        assert initiator is not None, f"{expected['name']}: sin initiator"
        assert initiator["type"] == "script", f"{expected['name']}: {initiator}"
        assert initiator["script_url"] == expected["initiator_script"], f"{expected['name']}: {initiator}"
        assert initiator["stack"] and initiator["stack"][0]["url"] == expected["initiator_script"]


def test_initiator_of_parser_inserted_resource(capture):
    image = find(capture, "site.fixtures.test", "/img/first.png")
    assert image["initiator"]["type"] == "parser"
    assert image["initiator"]["url"] == "http://site.fixtures.test/"


# --- Criterio 9: Service Worker ---


def test_service_worker_is_not_registered(capture, received, manifest):
    workers = capture["service_workers"]
    assert workers["blocked_attempts"] >= 1, "no quedó evidencia del intento de registro"
    assert workers["registrations"] == 0
    assert workers["active_workers"] == 0
    for forbidden in manifest["must_not_be_requested"]:
        assert not [e for e in received if e["host"] == forbidden["host"] and e["path"] == forbidden["path"]]
        assert not [r for r in capture["requests"] if r["host"] == forbidden["host"] and r["path"] == forbidden["path"]]


# --- Criterio 10: /flood ---


def test_flood_is_truncated_at_max_requests(flood_scan, manifest):
    outcome, received = flood_scan
    assert outcome.error is None, outcome.error
    assert manifest["flood"]["requests"] > settings.max_requests
    assert outcome.capture["truncated"] is True
    assert len(outcome.capture["requests"]) == settings.max_requests
    assert outcome.capture["end_reason"] == "max_requests"
    # Lo registrado antes del corte sí es real: todo está entre lo que recibió el servidor.
    extra = Counter(captured_key(r) for r in outcome.capture["requests"] if not r["failure_text"]) - Counter(
        received_key(entry) for entry in received
    )
    assert not extra, sorted(extra.elements())[:5]


# --- Criterio 11: first / third party ---


def test_first_and_third_party(capture, manifest):
    assert capture["first_party_domains"] == ["site.fixtures.test"]
    for expected in manifest["requests"]:
        request = find(capture, expected["host"], expected["path"], expected["method"])
        assert request["third_party"] is expected["third_party"], expected["name"]
    by_host = {r["host"]: r["third_party"] for r in capture["requests"]}
    assert by_host == {"site.fixtures.test": False, "tracker-a.fixtures.test": True, "cdn-b.fixtures.test": True}
    assert {r["registrable_domain"] for r in capture["requests"]} == {
        "site.fixtures.test",
        "tracker-a.fixtures.test",
        "cdn-b.fixtures.test",
    }


# --- Criterio 12: snapshot ---


def test_snapshot_has_cookies_and_storage(capture, manifest):
    for expected in manifest["cookies"]:
        cookies = [c for c in capture["cookies"] if c["name"] == expected["name"]]
        assert len(cookies) == 1
        assert cookies[0]["value"] == expected["value"] and cookies[0]["domain"] == expected["domain"]
        assert cookies[0]["http_only"] is True and cookies[0]["third_party"] is False
    for storage_type, key in (("local", "local_storage"), ("session", "session_storage")):
        expected = manifest[key]
        items = [
            s
            for s in capture["storage"]
            if s["storage_type"] == storage_type and s["origin"] == expected["origin"] and s["key"] == expected["key"]
        ]
        assert len(items) == 1, f"{storage_type}: {capture['storage']}"
        assert items[0]["value"] == expected["value"] and items[0]["value_truncated"] is False


# --- Persistencia: lo capturado llega íntegro a las tablas scan_* ---


def test_capture_is_persisted(outcome, capture):
    async def scenario():
        conn = await asyncpg.connect(
            host=settings.postgres_host,
            user=settings.postgres_user,
            password=settings.postgres_password.get_secret_value(),
            database=settings.postgres_db,
        )
        job_id = uuid.uuid4()
        worker_id = f"test-{job_id}"
        job = {"id": job_id, "attempts": 1, "options": None}
        try:
            # running y ya tomado: el worker real no lo toca.
            await conn.execute(
                "INSERT INTO jobs (id, url, status, attempts, locked_by, locked_until) "
                "VALUES ($1, $2, 'running', 1, $3, now() + interval '5 minutes')",
                job_id, "http://site.fixtures.test/", worker_id,
            )

            class OneConnection:
                def acquire(self):
                    return self

                async def __aenter__(self):
                    return conn

                async def __aexit__(self, *exc):
                    return False

            result = {**outcome.result, "capture": jobs.capture_summary(capture)}
            assert await jobs.finish(OneConnection(), job, worker_id, result=result, capture=capture) is True
            # Segundo cierre del mismo job: ya no es running, no debe duplicar nada.
            assert await jobs.finish(OneConnection(), job, worker_id, result=result, capture=capture) is False

            counts = await conn.fetchrow(
                "SELECT (SELECT count(*) FROM scan_requests WHERE job_id = $1) AS requests,"
                " (SELECT count(*) FROM scan_redirects WHERE job_id = $1) AS redirects,"
                " (SELECT count(*) FROM scan_websockets WHERE job_id = $1) AS websockets,"
                " (SELECT count(*) FROM scan_ws_frames WHERE job_id = $1) AS frames,"
                " (SELECT count(*) FROM scan_cookies WHERE job_id = $1) AS cookies,"
                " (SELECT count(*) FROM scan_storage WHERE job_id = $1) AS storage,"
                " (SELECT status FROM jobs WHERE id = $1) AS status",
                job_id,
            )
            beacon = await conn.fetchrow(
                "SELECT post_data_sha256, initiator->>'script_url' AS script, third_party FROM scan_requests "
                "WHERE job_id = $1 AND path = '/beacon'",
                job_id,
            )
            return dict(counts), dict(beacon)
        finally:
            await conn.execute("DELETE FROM jobs WHERE id = $1", job_id)
            await conn.close()

    counts, beacon = run_async(scenario())
    assert counts == {
        "requests": len(capture["requests"]),
        "redirects": sum(len(chain) for chain in capture["redirects"]),
        "websockets": len(capture["websockets"]),
        "frames": sum(len(w["frames"]) for w in capture["websockets"]),
        "cookies": len(capture["cookies"]),
        "storage": len(capture["storage"]),
        "status": "completed",
    }
    expected = next(r for r in capture["requests"] if r["path"] == "/beacon")
    assert beacon == {
        "post_data_sha256": expected["post_data"]["sha256"],
        "script": "http://tracker-a.fixtures.test/tracker.js",
        "third_party": True,
    }
