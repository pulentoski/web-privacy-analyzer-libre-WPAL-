"""v1.3.4 — telemetría propia: envíos de eventos al propio sitio o a la misma organización."""

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import _blocking, analyze
from app.config import settings
from tests.v121.test_party_blocking_service_consent import ENTITIES, Lists, capture, req

SITE = "https://www.airbnb.cl"      # Airbnb; muscache.com es de la misma organización (ENTITIES)


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def own(request_id, url, *, method="GET", resource_type="xhr", status=200, params=None):
    request = req(request_id, url, third_party=not url.startswith(SITE), resource_type=resource_type, status=status, params=params)
    request["method"] = method
    return request


def telemetry_of(config, requests):
    result = analyze(capture([*[own(100 + i, f"{SITE}/a{i}.png", resource_type="image") for i in range(25)], *requests]), Lists(ENTITIES), config)
    return result, result["site"]["summary"]["first_party_telemetry"]


@pytest.mark.parametrize("path", ["/count", "/metrics", "/collect", "/events", "/track", "/beacon", "/log", "/cdn/ping.gif", "/v1/metrics", "/api/tracks/prints"])
def test_event_paths_to_the_site_or_same_org_are_first_party_telemetry(config, path):
    for base in (SITE, "https://a0.muscache.com"):
        _, telemetry = telemetry_of(config, [own(1, f"{base}{path}", method="POST")])
        assert telemetry["requests"] == 1 and telemetry["endpoints"] == 1 and telemetry["by_kind"] == {"path": 1}, (base, path, telemetry)
        assert telemetry["endpoint_list"][0]["path"] == path


def test_204_with_data_counts_but_plain_204_documents_and_preflights_do_not(config):
    hits = [own(1, f"{SITE}/x/y", method="POST", status=204), own(2, f"{SITE}/x/z", status=204, params={"d": "1"})]
    misses = [own(3, f"{SITE}/x/w", status=204), own(4, f"{SITE}/metrics", method="OPTIONS", status=204),
              own(5, f"{SITE}/events", resource_type="document"), own(6, f"{SITE}/static/login.js", resource_type="script"),
              own(7, f"{SITE}/account/login"), own(8, f"{SITE}/catalog/discount")]
    _, telemetry = telemetry_of(config, [*hits, *misses])
    assert telemetry["requests"] == 2 and telemetry["by_kind"] == {"status_204": 2}, telemetry


def test_third_party_endpoints_are_not_first_party_telemetry(config):
    _, telemetry = telemetry_of(config, [own(1, "https://stats.g.doubleclick.net/collect?v=1", status=204, params={"v": "1"})])
    assert telemetry["requests"] == 0 and telemetry["endpoints"] == 0


def test_known_own_analytics_scripts_and_endpoints(config):
    requests = [own(1, "https://a0.muscache.com/storage/melidata-js-sdk/js/3/melidata.min.js", resource_type="script"),
                own(2, "https://a0.muscache.com/frontend-assets/frontend-viewability/viewability-script.2.2.js", resource_type="script"),
                own(3, "https://a0.muscache.com/melidata/prints", method="POST")]
    result, telemetry = telemetry_of(config, requests)
    assert telemetry["scripts"] == 2 and telemetry["requests"] == 1 and telemetry["by_kind"] == {"script": 2, "known": 1}
    assert {entry["name"] for entry in telemetry["script_list"]} == {"Melidata (Mercado Libre)", "Medición de visibilidad de anuncios propia"}
    findings = {item["type"]: item for item in result["findings"]}
    assert findings["first_party_telemetry"]["level"] == "INFERENCIA" and findings["first_party_telemetry"]["evidence_refs"] == [3]
    assert findings["first_party_analytics_script"]["level"] == "EVIDENCIA" and findings["first_party_analytics_script"]["evidence_refs"] == [1, 2]
    # Componente propio del índice; no cuentan como terceros ni como requests de rastreo.
    component = next(item for item in result["site"]["breakdown"] if item["component"] == "first_party_telemetry")
    assert component["count"] == 3 and 0 < component["points"] < component["cap"] == 4
    assert result["site"]["summary"]["third_party_domains"] == 0 and result["site"]["summary"]["trackers"] == 0


def test_index_caps_still_add_up_to_100(config):
    assert sum(spec["cap"] for spec in config.scoring["site_exposure"].values()) == 100


def test_no_telemetry_means_no_finding_and_zero_component(config):
    result, telemetry = telemetry_of(config, [])
    assert telemetry["requests"] == 0 and not [f for f in result["findings"] if f["type"].startswith("first_party_")]


# --- Regla de anomalía ---

def verdict(config, *, own_requests, title="Tienda", trackers=1, total=150, extra=()):
    requests = capture([own(100 + i, f"{SITE}/a{i}.png", resource_type="image") for i in range(total - 1 - len(extra))], title=title)["requests"] + list(extra)
    return _blocking(capture([], title=title), requests, config.blocking, trackers=trackers,
                     telemetry={"requests": own_requests}, telemetry_min=config.first_party_telemetry.min_requests_for_note)


def test_low_third_party_tracking_with_own_telemetry_is_a_note_not_a_block(config):
    result = verdict(config, own_requests=40)
    assert result["blocked"] is False and result["partial"] is False and result["signals"] == []
    assert result["note"]["signal"] == "low_third_party_tracking"
    assert result["note"]["detail"].startswith("Rastreo de terceros bajo; telemetría propia detectada")


def test_low_tracking_without_own_telemetry_is_still_possibly_blocked(config):
    for own_requests in (0, 2):
        result = verdict(config, own_requests=own_requests)
        assert result["blocked"] is True and result["note"] is None and [s["signal"] for s in result["signals"]] == ["tracker_anomaly"]


def test_note_needs_a_normal_title_and_no_antibot_signature(config):
    assert verdict(config, own_requests=40, title="")["blocked"] is True
    assert verdict(config, own_requests=40, title="Just a moment...")["blocked"] is True
    challenge = own(900, f"{SITE}/_____tmd_____/punish?x5secdata=a", resource_type="document")
    result = verdict(config, own_requests=40, extra=[challenge])
    assert result["blocked"] is True and result["note"] is None
    assert {s["signal"] for s in result["signals"]} == {"tracker_anomaly", "challenge_url"}
