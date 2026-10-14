"""v1.4.5: el perfil base del navegador del worker se presenta en español de Chile (configurable por .env) y eso es
coherente para el detector de inconsistencias. La parte con navegador real usa el sitio de fixtures."""

import pytest

from app import config as worker_config
from app.analyzer.consistency import check
from app.browser import launcher
from app.browser.capture import run_scan
from app.browser.profiles import consistency_rules
from app.config import accept_language, settings
from tests.helpers import SITE, fixtures_call, run_async


def test_defaults_are_chilean_spanish():
    assert settings.worker_locale == "es-CL" and settings.worker_timezone == "America/Santiago"
    kwargs = launcher.context_kwargs()
    assert kwargs["locale"] == "es-CL" and kwargs["timezone_id"] == "America/Santiago"
    assert kwargs["extra_http_headers"] == {"Accept-Language": "es-CL,es;q=0.9"}
    assert launcher.base_session_setup() == [("Emulation.setUserAgentOverride", {"userAgent": "", "acceptLanguage": "es-CL,es"})]
    # El resto del perfil base no cambia.
    assert kwargs["no_viewport"] is True and kwargs["service_workers"] == "block"


@pytest.mark.parametrize("locale, header", [("es-CL", "es-CL,es;q=0.9"), ("en-US", "en-US,en;q=0.9"), ("es", "es"), ("pt-BR", "pt-BR,pt;q=0.9")])
def test_accept_language_of_a_locale(locale, header):
    assert accept_language(locale) == header


def test_locale_and_timezone_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("WORKER_LOCALE", "pt-BR")
    monkeypatch.setenv("WORKER_TIMEZONE", "America/Sao_Paulo")
    custom = worker_config.Settings()
    assert (custom.worker_locale, custom.worker_timezone) == ("pt-BR", "America/Sao_Paulo")
    monkeypatch.setattr(launcher, "settings", custom)
    kwargs = launcher.context_kwargs()
    assert kwargs["locale"] == "pt-BR" and launcher.base_session_setup()[0][1]["acceptLanguage"] == "pt-BR,pt"


@pytest.mark.parametrize("name, value", [
    ("WORKER_LOCALE", "es_CL"), ("WORKER_LOCALE", "es-CL\r\nX-Injected: 1"), ("WORKER_LOCALE", "español"),
    ("WORKER_TIMEZONE", "Santiago de Chile"), ("WORKER_TIMEZONE", "../etc/passwd"), ("WORKER_TIMEZONE", "America/Santiago\nX: 1"),
])
def test_invalid_values_are_rejected_at_startup(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        worker_config.Settings()


def test_empty_values_fall_back_to_the_defaults(monkeypatch):
    monkeypatch.setenv("WORKER_LOCALE", "")
    monkeypatch.setenv("WORKER_TIMEZONE", " ")
    custom = worker_config.Settings()
    assert (custom.worker_locale, custom.worker_timezone) == ("es-CL", "America/Santiago")


def test_profiles_keep_their_own_locale():
    profile = {"user_agent": "UA", "locale": "en-US", "timezone": "America/New_York", "viewport": [1, 2], "screen": [3, 4],
               "device_scale_factor": 1, "mobile": False, "has_touch": False}
    kwargs = launcher.context_kwargs(profile)
    assert kwargs["locale"] == "en-US" and kwargs["timezone_id"] == "America/New_York" and "extra_http_headers" not in kwargs


def test_the_base_profile_is_coherent_for_the_consistency_checker():
    js = {"languages": ["es-CL", "es"], "timezone": "America/Santiago"}
    assert check(js, {"accept-language": accept_language("es-CL")}, consistency_rules()) == []
    # El perfil anterior (inglés, UTC implícito) con zona de Chile sí era incoherente.
    rules = [item["rule"] for item in check({"languages": ["en-US"], "timezone": "America/Santiago"}, {"accept-language": "en-US,en;q=0.9"}, consistency_rules())]
    assert rules == ["timezone_vs_locale"]


@pytest.fixture(scope="module")
def v145_scan(manifest, page_scan):
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(manifest["v145"]["page"], probe=True))
    return outcome, fixtures_call("/__received")["requests"]


def test_the_server_receives_chilean_spanish(v145_scan):
    _, received = v145_scan
    languages = {entry["accept_language"] for entry in received}
    assert languages == {"es-CL,es;q=0.9"}, languages


def test_scripts_read_the_same_language_and_timezone(v145_scan):
    outcome, _ = v145_scan
    probe = outcome.result["profile"]["js"]
    assert probe["languages"] == ["es-CL", "es"] and probe["timezone"] == "America/Santiago" and probe["locale"].startswith("es")
    headers = outcome.result["profile"]["headers"]
    assert headers["accept-language"] == "es-CL,es;q=0.9"
    assert [item["rule"] for item in check(probe, headers, consistency_rules()) if item["rule"] in ("language_js_vs_header", "timezone_vs_locale")] == []


def test_v145_fixture_end_to_end(v145_scan, manifest, analyzer_resources):
    from app.analyzer.engine import analyze, prepare_capture

    outcome, _ = v145_scan
    lists, config = analyzer_resources
    expected = manifest["v145"]
    result = analyze(prepare_capture(outcome.capture, start_url=expected["page"], page_url=outcome.result["final_url"]), lists, config)
    summary = result["site"]["summary"]
    rows = [item for item in summary["third_party_services"]["items"] if expected["third_party_service_host"] in item["hosts"]]
    assert len(rows) == 1 and rows[0]["requests"] == expected["third_party_service_requests"]
    assert rows[0]["organization"] == "no_disponible" and rows[0]["service_label"] is None
    # El recuadro que no cargó: su request (fallida) queda atribuida a la página de error y se cuenta aparte.
    assert summary["error_frames"]["observed"] is True and summary["error_frames"]["requests"] <= 1
    assert summary["error_frames"]["ignored_messages"] >= 1 and summary["error_frames"]["ignored_calls"] == 0
    (accounts,) = [item for item in result["findings"] if item["type"] == "analytics_accounts"]
    assert accounts["details"]["accounts"] == expected["analytics_accounts"]["accounts"] and accounts["level"] == "EVIDENCIA"
    (note,) = [item for item in result["findings"] if item["type"] == "discontinued_tag"]
    assert note["details"]["accounts"] == expected["analytics_accounts"]["discontinued"]
    # El recuadro que no cargó no deja scripts ni llamadas atribuidas a la página de error del navegador.
    assert "chrome-error" not in repr(result["fingerprinting"]) and "chrome-error" not in repr(result["findings"])
    assert all(not call["frame_url"].startswith("chrome-error://") for call in outcome.capture["fingerprinting"]["calls"])
