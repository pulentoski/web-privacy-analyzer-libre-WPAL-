"""v1.5.0 (docs/adr/038): protocolo de visita con el Chromium del worker (scroll, cortes por tiempo y por MAX_REQUESTS)
y país de la IP de salida a través del egress-proxy. Requiere el stack de test (scripts/test.sh apunta
EGRESS_IP_SERVICE_URL a la ruta de control /__egress-ip del sitio de fixtures, que responde 8.8.8.8 y no queda en
/__received: no es tráfico del sitio)."""

import json
import logging
from datetime import datetime

import pytest

from app import egress
from app.browser.capture import run_scan
from app.config import settings
from tests.helpers import SITE, fixtures_call, run_async

EGRESS_TEST_IP = "8.8.8.8"
NAMES = ["carga", "espera", "scroll", "espera", "cierre"]


def stages_of(outcome) -> list[dict]:
    return outcome.result["measurement"]["visit_protocol"]["stages"]


def by_path(outcome, path) -> list[dict]:
    return [request for request in outcome.capture["requests"] if request["path"] == path]


@pytest.fixture(scope="module")
def scroll_scan(fixtures_site):
    fixtures_call("/__reset", "POST")
    return run_async(run_scan(SITE + "/v150/scroll/"))


def test_full_protocol_in_order(scroll_scan):
    stages = stages_of(scroll_scan)
    assert [stage["name"] for stage in stages] == NAMES
    assert all(stage["completed"] for stage in stages)
    assert [stage["reason"] for stage in stages] == ["network_idle", "duration_elapsed", "document_end", "duration_elapsed", "tab_closed"]
    times = [(datetime.fromisoformat(stage["started_at"]), datetime.fromisoformat(stage["ended_at"])) for stage in stages]
    for (start, end), (next_start, _) in zip(times, times[1:]):
        assert start <= end <= next_start
    # Esperas de 3 s (la segunda incluye el volcado previo al cierre) y 3 s de observación tras cerrar.
    assert (times[1][1] - times[1][0]).total_seconds() == pytest.approx(3, abs=0.3)
    assert (times[3][1] - times[3][0]).total_seconds() >= 3 and stages[3]["includes"] == ["pre_close_dump"]
    assert (times[4][1] - times[4][0]).total_seconds() == pytest.approx(3, abs=0.5)
    assert scroll_scan.result["measurement"]["visit_protocol"]["protocol_version"] == 1
    # Las etapas reparten todas las requests capturadas, sin huecos ni solapes.
    seqs = [seq for stage in stages for seq in stage["request_seqs"]]
    assert seqs == list(range(len(scroll_scan.capture["requests"])))


def test_lazy_content_is_requested_during_scroll(scroll_scan):
    stage = stages_of(scroll_scan)[2]
    bottom = by_path(scroll_scan, "/v150/scroll-bottom")
    assert len(bottom) == 1 and bottom[0]["seq"] in stage["request_seqs"] and stage["reached_end"] is True


def test_capture_after_close_keeps_headers(scroll_scan):
    # Las requests se vuelcan antes de cerrar la pestaña: conservan sus cabeceras reales y su respuesta.
    document = by_path(scroll_scan, "/v150/scroll/")[0]
    assert document["response_status"] == 200 and any(h["name"].lower() == "content-type" for h in document["response_headers"])
    assert any(h["name"].lower() == "accept-language" for h in document["request_headers"])
    assert scroll_scan.capture["storage"] == [] and scroll_scan.capture["service_workers"]["registrations"] == 0


def test_infinite_scroll_stops_at_max_time(fixtures_site):
    outcome = run_async(run_scan(SITE + "/v150/scroll/?infinite=1"))
    stage = stages_of(outcome)[2]
    assert stage["completed"] is True and stage["reason"] == "max_time" and stage["reached_end"] is False
    seconds = (datetime.fromisoformat(stage["ended_at"]) - datetime.fromisoformat(stage["started_at"])).total_seconds()
    assert seconds == pytest.approx(8, abs=0.6)
    more = {request["seq"] for request in by_path(outcome, "/v150/scroll-more")}
    assert len(more) >= 2 and more <= set(stage["request_seqs"])
    assert stages_of(outcome)[4]["completed"] is True


def test_scan_timeout_cuts_the_protocol(fixtures_site):
    # Carga ~3,5 s + espera 3 s: el tope de 8 s corta el scroll infinito; lo que sigue no se ejecuta.
    outcome = run_async(run_scan(SITE + "/v150/scroll/?infinite=1", timeout_s=8))
    assert outcome.error is None
    stages = stages_of(outcome)
    assert [stage["completed"] for stage in stages] == [True, True, False, False, False]
    assert stages[2]["reason"] == "scan_timeout" and stages[2]["ended_at"]
    for stage in stages[3:]:
        assert stage["reason"] == "previous_stage_incomplete" and stage["started_at"] is None and stage["request_seqs"] == []
    # Sin cierre la página siguió abierta: el volcado es el de siempre.
    assert by_path(outcome, "/v150/scroll/")[0]["response_status"] == 200


def test_max_requests_cuts_the_load(manifest):
    outcome = run_async(run_scan(manifest["flood"]["page"], max_requests=50))
    stages = stages_of(outcome)
    assert outcome.capture["end_reason"] == "max_requests"
    assert stages[0]["completed"] is False and stages[0]["reason"] == "max_requests" and stages[0]["requests"] == 50
    assert [stage["reason"] for stage in stages[1:]] == ["previous_stage_incomplete"] * 4


def test_failed_navigation_has_no_measurement(fixtures_site):
    outcome = run_async(run_scan("http://no-existe.fixtures.test/"))
    assert outcome.error is not None and outcome.result is None


# --- País de la IP de salida ---


def test_egress_country_through_the_proxy(fixtures_site):
    assert settings.egress_ip_service_url == SITE + "/__egress-ip", "scripts/test.sh fija EGRESS_IP_SERVICE_URL"
    result = egress.lookup_country(SITE + "/__egress-ip")
    assert result == {"status": "ok", "country_code": "US", "country": result["country"], "source": result["source"], "reason": None}
    assert result["source"].startswith("DB-IP Lite ") and EGRESS_TEST_IP not in json.dumps(result)
    invalid = egress.lookup_country(SITE + "/__egress-ip-invalid")
    assert invalid["status"] == "desconocido" and invalid["reason"] == "El servicio de IP pública no devolvió una IP."
    unreachable = egress.lookup_country("http://no-existe.fixtures.test/ip")
    assert unreachable["status"] == "desconocido" and unreachable["reason"] == "La consulta de la IP de salida falló."


def test_scan_records_country_without_the_ip(scroll_scan, caplog):
    country = scroll_scan.result["measurement"]["egress_country"]
    assert country["status"] == "ok" and country["country_code"] == "US"
    # La IP se descarta: no está en el resultado, en la captura ni en los logs del scan.
    assert EGRESS_TEST_IP not in json.dumps(scroll_scan.result, default=str)
    assert EGRESS_TEST_IP not in json.dumps(scroll_scan.capture, default=str)
    with caplog.at_level(logging.DEBUG):
        outcome = run_async(run_scan(SITE + "/v150/close/"))
    assert outcome.result["measurement"]["egress_country"]["country_code"] == "US"
    assert EGRESS_TEST_IP not in caplog.text


def test_egress_query_is_outside_the_analyzed_traffic(scroll_scan):
    # La consulta no la hace el navegador: no está entre las requests capturadas del scan.
    assert not by_path(scroll_scan, "/__egress-ip")
