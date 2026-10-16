"""v1.3.1 — pantallas antibot que responden 200: firmas en documentos/frames y anomalía de rastreo."""

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import _blocking, _tracker_anomaly, analyze
from app.config import settings
from tests.v121.test_party_blocking_service_consent import ENTITIES, Lists, capture, req

SITE = "https://www.airbnb.cl"


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def page_requests(count=30):
    return [req(i, f"{SITE}/a{i}.png", third_party=False) for i in range(1, count + 1)]


def blocking(config, extra, **kwargs):
    return analyze(capture([*page_requests(), *extra], **kwargs), Lists(ENTITIES), config)["site"]["summary"]["blocking"]


@pytest.mark.parametrize("url", [
    "https://acs.airbnb.cl//h5/mtop.pdp.pc.query/1.0/_____tmd_____/punish?x5secdata=abc",
    "https://www.airbnb.cl/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1",
    "https://geo.captcha-delivery.com/captcha/?initialCid=1",
    "https://www.airbnb.cl/px-captcha",
    "https://www.airbnb.cl/baxia/check.html",
])
def test_challenge_document_with_status_200_marks_the_scan(config, url):
    result = blocking(config, [req(900, url, third_party=False, resource_type="document")])
    assert result["blocked"] is True
    signal = next(s for s in result["signals"] if s["signal"] == "challenge_url")
    assert "antibot" in signal["detail"]


def test_challenge_frame_url_marks_the_scan(config):
    inner = req(900, "https://g.alicdn.com/x.js", resource_type="script")
    inner["frame_url"] = "https://acs.airbnb.cl/_____tmd_____/punish?x5step=3"
    assert blocking(config, [inner])["blocked"] is True


def test_security_sdk_loaded_as_script_does_not_mark(config):
    # En visitas normales de AliExpress se carga o.alicdn.com/baxia/…: no es una pantalla de desafío.
    extra = [req(900, "https://o.alicdn.com/baxia/baxia-entry-gray/index.js", resource_type="script"),
             req(901, "https://www.google.com/recaptcha/enterprise.js", resource_type="script")]
    assert blocking(config, extra)["blocked"] is False


def test_embedded_captcha_widget_does_not_mark(config):
    extra = [req(900, "https://www.google.com/recaptcha/api2/anchor?ar=1&k=x", resource_type="document"),
             req(901, "https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html", resource_type="document")]
    assert blocking(config, extra)["blocked"] is False


def test_har_import_is_never_marked(config):
    extra = [req(900, "https://acs.airbnb.cl/_____tmd_____/punish", third_party=False, resource_type="document")]
    assert blocking(config, extra, source="har_import")["blocked"] is False


# --- Anomalía de rastreo ---

def rule(config):
    return config.blocking["tracker_anomaly"]


def test_anomaly_against_history(config):
    history = [{"requests": 330, "trackers": 67}, {"requests": 400, "trackers": 90}]
    signal = _tracker_anomaly(152, 2, history, rule(config))
    assert signal["signal"] == "tracker_anomaly_history" and "se esperaban cerca de" in signal["detail"]
    # Mismo sitio con rastreo en línea con su historial: sin señal.
    assert _tracker_anomaly(300, 55, history, rule(config)) is None


def test_no_history_uses_conservative_threshold(config):
    assert _tracker_anomaly(152, 2, [], rule(config))["signal"] == "tracker_anomaly"
    # Sitio que de verdad rastrea poco o nada (p. ej. wikipedia): no se marca.
    assert _tracker_anomaly(60, 0, [], rule(config)) is None
    assert _tracker_anomaly(400, 0, [], rule(config)) is None
    # Página chica con algo de rastreo, o proporción normal: no se marca.
    assert _tracker_anomaly(80, 1, [], rule(config)) is None
    assert _tracker_anomaly(150, 6, [], rule(config)) is None


def test_low_tracking_history_falls_back_to_conservative_threshold(config):
    # Historial de un sitio que rastrea poco: no sirve de referencia ni marca una visita normal.
    quiet = [{"requests": 60, "trackers": 0}, {"requests": 70, "trackers": 1}]
    assert _tracker_anomaly(65, 0, quiet, rule(config)) is None
    # Historial de visitas ya bloqueadas (2 de 150): la visita actual igual se marca.
    assert _tracker_anomaly(152, 2, [{"requests": 150, "trackers": 2}], rule(config))["signal"] == "tracker_anomaly"


def test_signals_come_from_yaml(config):
    assert "punish" in config.blocking["challenge_url_signatures"]
    assert _tracker_anomaly(152, 2, [], {}) is None


# --- v1.3.2: bloqueo parcial (firma en un componente, rastreo normal) ---

CHALLENGE = "https://acs.airbnb.cl/h5/mtop.recommend/1.0/_____tmd_____/punish?x5secdata=abc"


def verdict(config, trackers, *, total=120, challenge=True, page_url=None, **extra):
    """_blocking sobre una captura de `total` requests con `trackers` de rastreo (el conteo lo da analyze())."""
    requests = capture(page_requests(total - 2), **extra)["requests"]
    if challenge:
        requests.append(req(900, CHALLENGE, third_party=False, resource_type="document"))
    cap = capture([], **extra)
    if page_url:
        cap["page_url"] = page_url
    return _blocking(cap, requests, config.blocking, trackers=trackers)


def test_signature_with_normal_tracking_is_a_partial_block_not_a_blocked_visit(config):
    result = verdict(config, 40)
    assert result["blocked"] is False and result["partial"] is True
    assert [s["signal"] for s in result["signals"]] == ["challenge_component"]
    assert "El resto de la página cargó: 40 de 120 requests fueron de rastreo." in result["signals"][0]["detail"]


def test_signature_with_very_low_tracking_is_still_possibly_blocked(config):
    for trackers in (0, 2, 5):  # 5 de 120 no llega al mínimo de «rastreo normal»
        result = verdict(config, trackers)
        assert result["blocked"] is True and result["partial"] is False, trackers
        assert "challenge_url" in {s["signal"] for s in result["signals"]}


def test_only_anomalous_tracking_is_a_possible_note(config):
    # v1.4.8: sin señal dura, el rastreo anómalo no marca la visita.
    result = verdict(config, 1, challenge=False)
    assert result["blocked"] is False and result["signals"] == []
    assert [s["signal"] for s in result["possible_variant"]["signals"]] == ["tracker_anomaly"]


def test_signature_on_the_page_itself_is_blocked_even_with_tracking(config):
    result = verdict(config, 40, page_url=CHALLENGE)
    assert result["blocked"] is True and result["partial"] is False


def test_signature_plus_another_signal_is_blocked(config):
    result = verdict(config, 40, title="Just a moment...")
    assert result["blocked"] is True and result["partial"] is False
    assert {s["signal"] for s in result["signals"]} == {"challenge_text", "challenge_url"}


def test_clean_scan_has_no_partial_flag(config):
    result = verdict(config, 40, challenge=False)
    assert result["blocked"] is False and result["partial"] is False and result["signals"] == []
