"""v1.4.8 (docs/adr/035): Chromium sin reinicio por ACCEPT_CH, scans fallidos sin medición, scans parciales y
alerta antibot solo con señal dura."""

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import POSSIBLE_VARIANT_TEXT, _blocking
from app.browser.capture import _error, net_error_code, partial_navigation, run_scan
from app.browser.launcher import CHROMIUM_ARGS, launch_kwargs
from app.config import settings
from tests.helpers import SITE, run_async
from tests.v121.test_party_blocking_service_consent import capture, req


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


# --- a) Chromium: el frame ACCEPT_CH no reinicia la navegación ---

def test_accept_ch_frame_is_disabled_for_scan_and_interactive():
    assert "--disable-features=AcceptCHFrame" in CHROMIUM_ARGS
    # La captura interactiva parte de launch_kwargs: mismo flag.
    assert "--disable-features=AcceptCHFrame" in launch_kwargs()["args"]
    # Un segundo --disable-features reemplazaría al primero en Chromium: debe haber uno solo.
    assert sum(arg.startswith("--disable-features=") for arg in CHROMIUM_ARGS) == 1


# --- b) código net::ERR_* real ---

def test_net_error_code_is_taken_from_the_browser_message():
    message = "Page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://example.test/"
    assert net_error_code(message) == "net::ERR_CERT_AUTHORITY_INVALID"
    assert net_error_code(None, "net::ERR_CONNECTION_RESET") == "net::ERR_CONNECTION_RESET"
    assert net_error_code("Timeout 30000ms exceeded.", None) is None
    assert _error("NAVIGATION_TIMEOUT", "x")["net_error"] is None


class FakeMonitor:
    count, responses = 12, 3

    def navigation_failure(self):
        return "net::ERR_TIMED_OUT"


def test_partial_navigation_summary():
    partial = partial_navigation(FakeMonitor(), 60)
    assert partial["reason"] == "navigation_timeout" and partial["net_error"] == "net::ERR_TIMED_OUT"
    assert (partial["requests"], partial["responses"]) == (12, 3)
    assert "60 s" in partial["message"] and "12 requests, 3 con respuesta" in partial["message"]


# --- b) alerta antibot: solo con señal dura; nunca en fallidos ni en capturas interactivas ---

def few(**extra):
    cap = capture([req(1, "https://www.muscache.com/a.png")], **extra)
    return cap, cap["requests"]


@pytest.mark.parametrize("flags", [{"navigation_failed": True}, {"source": "interactive"}, {"source": "har_import"}])
def test_no_blocking_verdict_without_an_automated_measurement(config, flags):
    cap, requests = few(title="Just a moment...", http_status=403)
    result = _blocking({**cap, **flags}, requests, config.blocking, trackers=0)
    assert result["blocked"] is False and result["signals"] == [] and result["possible_variant"] is None
    assert result["note"] is None and result["not_applicable"]


def test_hard_signal_blocks_and_soft_signals_go_along(config):
    cap, requests = few(http_status=429)
    result = _blocking(cap, requests, config.blocking, trackers=0)
    assert result["blocked"] is True and result["possible_variant"] is None
    assert [s["signal"] for s in result["signals"]] == ["http_status", "few_requests"]


def test_soft_signal_alone_is_a_possible_note(config):
    cap, requests = few(title="Airbnb", http_status=200)
    result = _blocking(cap, requests, config.blocking, trackers=0)
    assert result["blocked"] is False and result["signals"] == []
    assert result["possible_variant"]["level"] == "POSIBLE" and result["possible_variant"]["text"] == POSSIBLE_VARIANT_TEXT
    assert "compare con un HAR propio" in POSSIBLE_VARIANT_TEXT


def test_partial_scan_ignores_soft_signals_but_keeps_hard_ones(config):
    cap, requests = few(title="Airbnb", http_status=200)
    cap["partial_navigation"] = {"reason": "navigation_timeout"}
    quiet = _blocking(cap, requests, config.blocking, trackers=0)
    assert quiet["blocked"] is False and quiet["possible_variant"] is None
    cap["http_status"] = 403
    assert _blocking(cap, requests, config.blocking, trackers=0)["blocked"] is True


# --- c) goto agota el tiempo: con respuestas = scan parcial; sin respuestas = falla y conserva lo capturado ---

def test_timeout_after_a_response_is_a_partial_scan(fixtures_site):
    outcome = run_async(run_scan(f"{SITE}/v148/redirect-to-hang", timeout_s=5, fp_instrumentation=False))
    assert outcome.error is None, outcome.error
    partial = outcome.result["partial"]
    assert partial["reason"] == "navigation_timeout" and partial["responses"] >= 1
    assert outcome.capture["end_reason"] == "navigation_timeout_partial"
    paths = [r["path"] for r in outcome.capture["requests"]]
    assert "/v148/redirect-to-hang" in paths and "/v148/hang" in paths


def test_timeout_without_responses_fails_and_keeps_the_capture(fixtures_site):
    outcome = run_async(run_scan(f"{SITE}/v148/hang", timeout_s=4, fp_instrumentation=False))
    assert outcome.result is None
    assert outcome.error["error_code"] == "NAVIGATION_TIMEOUT" and "net_error" in outcome.error
    assert [r["path"] for r in outcome.capture["requests"]] == ["/v148/hang"]
