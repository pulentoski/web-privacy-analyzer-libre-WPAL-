"""v1.5.0 (docs/adr/038): protocolo de visita (YAML, registro de etapas), condiciones de la medición y país de la IP
de salida, sin navegador ni red."""

import copy
import pathlib

import pytest
import yaml

from app.browser import visit
from app.browser.capture import measurement
from app.config import settings
from app import egress
from tests.helpers import run_async

PROTOCOL_PATH = pathlib.Path(settings.data_dir) / visit.PROTOCOL_FILE

# Valores de cada versión del protocolo. Cambiar un tiempo sin subir protocol_version hace fallar este test.
VERSIONS = {
    1: {"wait_s": (3, 3), "scroll_max_s": 8, "scroll_step_ms": 400, "close_observe_s": 3},
}


def raw_protocol() -> dict:
    return yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))


def test_protocol_file_matches_its_version():
    protocol = visit.load_protocol()
    assert protocol.version in VERSIONS, "protocol_version nuevo: añadirlo a VERSIONS y al CHANGELOG"
    expected = VERSIONS[protocol.version]
    assert (protocol.wait_s, protocol.scroll_max_s, protocol.scroll_step_ms, protocol.close_observe_s) == (
        expected["wait_s"], expected["scroll_max_s"], expected["scroll_step_ms"], expected["close_observe_s"])
    assert [stage["name"] for stage in raw_protocol()["stages"]] == ["carga", "espera", "scroll", "espera", "cierre"]
    # Con SCAN_TIMEOUT_S por defecto (90 s) quedan al menos 60 s para la carga.
    assert protocol.fixed_s == 17 and settings.scan_timeout_s - protocol.fixed_s >= 60


@pytest.mark.parametrize("mutate", [
    lambda raw: raw.pop("protocol_version"),
    lambda raw: raw.update(protocol_version=0),
    lambda raw: raw.update(protocol_version="1"),
    lambda raw: raw["stages"].reverse(),
    lambda raw: raw["stages"].pop(),
    lambda raw: raw["stages"][1].update(duration_s=-1),
    lambda raw: raw["stages"][1].update(duration_s=True),
    lambda raw: raw["stages"][2].update(step_interval_ms=10),
    lambda raw: raw["stages"][4].update(extra=1),
    lambda raw: raw["stages"][0].update(duration_s=5),
])
def test_invalid_protocol_does_not_load(mutate):
    raw = copy.deepcopy(raw_protocol())
    mutate(raw)
    with pytest.raises(visit.InvalidProtocol):
        visit.parse_protocol(raw)


def test_stage_log_records_each_stage_with_its_requests():
    counter = {"n": 0}
    log = visit.StageLog(visit.load_protocol(), lambda: counter["n"])
    load = log.start()
    counter["n"] = 4
    log.end(load, True, "network_idle")
    wait = log.start()
    counter["n"] = 6
    log.end(wait, False, "scan_timeout")
    log.skip_rest("previous_stage_incomplete")
    result = log.result()
    assert result["protocol_version"] == 1 and result["applies"] is True
    stages = result["stages"]
    assert [stage["name"] for stage in stages] == ["carga", "espera", "scroll", "espera", "cierre"]
    assert [stage["order"] for stage in stages] == [1, 2, 3, 4, 5]
    assert stages[0]["completed"] is True and stages[0]["requests"] == 4 and stages[0]["request_seqs"] == [0, 1, 2, 3]
    assert stages[0]["started_at"] and stages[0]["ended_at"] >= stages[0]["started_at"]
    assert stages[1] | {"started_at": None, "ended_at": None} == {
        "name": "espera", "order": 2, "planned": {"duration_s": 3}, "completed": False, "started_at": None, "ended_at": None,
        "reason": "scan_timeout", "requests": 2, "request_seqs": [4, 5]}
    for stage in stages[2:]:
        assert stage["completed"] is False and stage["started_at"] is None and stage["reason"] == "previous_stage_incomplete"
        assert stage["requests"] == 0 and stage["request_seqs"] == []
    assert stages[2]["planned"] == {"max_s": 8, "step_interval_ms": 400} and stages[4]["planned"] == {"observe_s": 3}
    assert all("first_seq" not in stage for stage in stages)


def test_measurement_conditions():
    data = measurement("153.0.8010.12", "2026-10-18T12:00:00.000+00:00", {"protocol_version": 1}, headless=False)
    assert data == {"browser": {"name": "Chromium", "version": "153.0.8010.12"}, "browser_mode": "headful",
                    "started_at": "2026-10-18T12:00:00.000+00:00", "visit_protocol": {"protocol_version": 1}}
    assert measurement(None, "x", {}, headless=True)["browser_mode"] == "headless"
    assert measurement(None, "x", {})["browser"]["version"] is None


# --- País de la IP de salida ---


def test_empty_service_url_does_not_query(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("con EGRESS_IP_SERVICE_URL vacío no se consulta nada")

    monkeypatch.setattr(egress, "_fetch_ip", forbidden)
    result = egress.lookup_country("")
    assert result == {"status": "desconocido", "country_code": None, "country": "desconocido", "source": None,
                      "reason": "EGRESS_IP_SERVICE_URL está vacío: no se consultó la IP de salida."}


@pytest.mark.parametrize("body, reason", [
    ("hola", "El servicio de IP pública no devolvió una IP."),
    ("1" * 80, "El servicio de IP pública no devolvió una IP."),
    ("10.0.0.5", "El servicio de IP pública devolvió una IP no pública."),
    ("127.0.0.1", "El servicio de IP pública devolvió una IP no pública."),
])
def test_invalid_answers_are_unknown(monkeypatch, body, reason):
    monkeypatch.setattr(egress, "_fetch_ip", lambda *args: body)
    result = egress.lookup_country("https://ip.example/")
    assert result["status"] == "desconocido" and result["country"] == "desconocido" and result["reason"] == reason


def test_failed_query_is_unknown(monkeypatch, caplog):
    def fail(*args):
        raise OSError("connection refused 203.0.113.9")

    monkeypatch.setattr(egress, "_fetch_ip", fail)
    result = egress.lookup_country("https://ip.example/")
    assert result["status"] == "desconocido" and result["reason"] == "La consulta de la IP de salida falló."
    # Del error solo se registra el tipo: el mensaje podría traer la respuesta del servicio.
    assert "203.0.113.9" not in caplog.text


def test_non_http_url_is_unknown(monkeypatch):
    monkeypatch.setattr(egress, "_fetch_ip", lambda *args: "8.8.8.8")
    assert egress.lookup_country("file:///etc/passwd")["reason"] == "EGRESS_IP_SERVICE_URL no es una URL http(s)."


def test_missing_ip_database_is_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(egress, "_fetch_ip", lambda *args: "8.8.8.8\n")
    result = egress.lookup_country("https://ip.example/", ipdb_dir=tmp_path)
    assert result == {"status": "desconocido", "country_code": None, "country": "desconocido", "source": None,
                      "reason": "La base DB-IP de países no está disponible."}
    assert "8.8.8.8" not in repr(result)


def test_async_lookup_never_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("inesperado")

    monkeypatch.setattr(egress, "lookup_country", boom)
    assert run_async(egress.lookup_country_async("https://ip.example/"))["status"] == "desconocido"



def test_query_uses_its_own_proxy_user(monkeypatch):
    """La consulta sale por el egress-proxy con un usuario nuevo en cada llamada, nunca el del scan."""
    seen = []
    real = egress.urllib.request.build_opener

    def spy(*handlers):
        seen.extend(handler.proxies for handler in handlers if isinstance(handler, egress.urllib.request.ProxyHandler))
        return real(*handlers)

    monkeypatch.setattr(egress.urllib.request, "build_opener", spy)
    egress._opener("http://egress-proxy:3128", "secreto")
    egress._opener("http://egress-proxy:3128", "secreto")
    users = [proxies["https"].split("://", 1)[1].split(":", 1)[0] for proxies in seen]
    assert all(user.startswith("scan-") and len(user) == 41 for user in users) and users[0] != users[1]
    assert all(proxies["http"] == proxies["https"] and proxies["https"].endswith("@egress-proxy:3128") for proxies in seen)
