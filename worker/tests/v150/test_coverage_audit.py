"""v1.5.0 (docs/adr/038): auditoría de cobertura por contexto, reproducible, con el Chromium y la configuración de un scan.

Contextos: frame principal, iframe del mismo origen, iframe de tercero, dedicated worker y service worker. Por cada uno
se miden por separado tres columnas: instrumentación instalada, APIs observadas y tráfico capturado. El servidor de
fixtures dice qué contextos corrieron de verdad (sus marcadores llegaron). El resultado tiene que coincidir con
data/coverage.yaml, que es lo que el reporte declara en «Límites de la medición».
"""

import pathlib

import pytest
import yaml

from app.browser.capture import run_scan
from app.config import settings
from tests.helpers import SITE, fixtures_call, run_async

PAGE = SITE + "/v150/coverage/"
CLOSE_PAGE = SITE + "/v150/close/"
TRACKER = "http://tracker-a.fixtures.test"
# Frame de cada contexto con documento propio; los workers no tienen frame.
FRAMES = {
    "main_frame": PAGE,
    "same_origin_iframe": SITE + "/v150/coverage/frame?ctx=same_origin_iframe",
    "third_party_iframe": TRACKER + "/v150/coverage/frame?ctx=third_party_iframe",
}
# Script de cada contexto: las llamadas se atribuyen por stack.
SCRIPTS = {
    "main_frame": SITE + "/static/v150/coverage.js",
    "same_origin_iframe": SITE + "/static/v150/frame.js",
    "third_party_iframe": TRACKER + "/static/v150/frame.js",
    "dedicated_worker": SITE + "/static/v150/worker.js",
    "service_worker": SITE + "/static/v150/sw.js",
}


def declared() -> dict:
    return yaml.safe_load((pathlib.Path(settings.data_dir) / "coverage.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def audit(fixtures_site):
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(PAGE))
    received = fixtures_call("/__received")["requests"]
    return outcome, received


def measure(outcome, probe_apis) -> dict:
    fingerprinting = outcome.capture["fingerprinting"]
    reporting = set(fingerprinting["frames_reporting"])
    captured = {param[1] for request in outcome.capture["requests"] if request["path"] == "/v150/mark"
                for param in request["query_params"] if param[0] == "ctx"}
    table = {}
    for context, script in SCRIPTS.items():
        calls = [call for call in fingerprinting["calls"] if call["script_url"] == script and call["api"] in probe_apis]
        if context in FRAMES:
            calls = [call for call in calls if call["frame_url"] == FRAMES[context]]
        table[context] = {
            "instrumentation": FRAMES.get(context) in reporting,
            "apis_observed": sorted({call["api"] for call in calls}),
            "traffic_captured": context in captured,
        }
    return table


def test_contexts_really_ran(audit):
    """Verdad de terreno: el servidor recibió el marcador de cada contexto que se ejecuta en un scan."""
    _, received = audit
    got = {request["query"] for request in received if request["path"] == "/v150/mark"}
    assert got == {"ctx=main_frame", "ctx=same_origin_iframe", "ctx=third_party_iframe", "ctx=dedicated_worker"}
    # El service worker nunca se registró: su script no se pidió y la página recibió una promesa resuelta.
    assert not [request for request in received if request["path"] == "/static/v150/sw.js"]
    assert [request["query"] for request in received if request["path"] == "/v150/sw-registration"] == ["result=ok"]


def test_coverage_matches_declared_table(audit):
    outcome, _ = audit
    data = declared()
    measured = measure(outcome, set(data["probe_apis"]))
    expected = {row["id"]: {key: row[key] for key in ("instrumentation", "apis_observed", "traffic_captured")}
                for row in data["contexts"]}
    assert measured == expected
    assert outcome.capture["service_workers"]["blocked_attempts"] == 1 and outcome.capture["service_workers"]["registrations"] == 0


def test_uncovered_contexts_declare_their_limit():
    for row in declared()["contexts"]:
        covered = row["instrumentation"] and row["traffic_captured"] and len(row["apis_observed"]) == len(declared()["probe_apis"])
        assert covered or len(row.get("limitation") or "") > 40, row["id"]
        assert covered != ("limitation" in row), row["id"]


def test_worker_traffic_is_attributed_to_the_page(audit):
    outcome, _ = audit
    worker_mark = [request for request in outcome.capture["requests"]
                   if request["path"] == "/v150/mark" and ["ctx", "dedicated_worker"] in request["query_params"]]
    assert len(worker_mark) == 1 and worker_mark[0]["frame_url"] == PAGE


@pytest.fixture(scope="module")
def closing(fixtures_site, audit):
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(CLOSE_PAGE))
    received = fixtures_call("/__received")["requests"]
    return outcome, received


def test_closing_events_match_declared_table(closing):
    outcome, received = closing
    stage = outcome.result["measurement"]["visit_protocol"]["stages"][4]
    assert stage["name"] == "cierre" and stage["completed"] is True and stage["reason"] == "tab_closed"
    by_seq = {request["seq"]: request for request in outcome.capture["requests"]}
    in_stage = {param[1] for seq in stage["request_seqs"] for param in by_seq[seq]["query_params"] if param[0] == "event"}
    expected = {row["event"]: row["captured"] for row in declared()["closing_events"]}
    assert set(expected.values()) <= {True, False, "variable"} and in_stage <= set(expected)
    # «variable» = carrera con el cierre: cualquiera de los dos resultados coincide con lo declarado.
    assert {event: event in in_stage for event, value in expected.items() if value != "variable"} == {
        event: value for event, value in expected.items() if value != "variable"}
    # Solo envíos observados en el cierre: todo lo de la etapa son los beacons de salida de la página.
    assert stage["requests"] == len(stage["request_seqs"]) == len(in_stage)
    assert all(by_seq[seq]["path"] == "/v150/bye" for seq in stage["request_seqs"])
    # Lo que no se capturó sí salió: el servidor recibió el beacon de visibilitychange.
    sent = {request["query"] for request in received if request["path"] == "/v150/bye"}
    assert {"event=beforeunload", "event=visibilitychange"} <= sent
