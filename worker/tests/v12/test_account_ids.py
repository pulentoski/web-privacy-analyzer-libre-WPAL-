"""v1.2: los IDs de cuenta del sitio no son identificadores del visitante.

Un ID de medición, un contenedor o un pixel llegan iguales para cualquier persona. Se muestran
como "ID de cuenta del sitio" y quedan fuera de "identificadores que persisten" y de
"sincronización entre organizaciones".
"""

import pathlib

import pytest
import yaml

from app.analyzer.account_ids import AccountIds
from app.analyzer.config import load_config
from app.analyzer.engine import analyze, prepare_capture
from app.browser.capture import run_scan
from app.config import settings
from tests.helpers import fixtures_call, run_async

VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
SNAP = "0f8fad5b-d9cb-469f-a165-70867728950e"


class Lists:
    version, sources, license_profile = "test", [], "no_comercial"

    def entity(self, domain):
        return "no_disponible"

    def match(self, request, source_host):
        return []


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def request(request_id, url, params, third_party=True):
    host = url.split("/")[2]
    return {
        "request_id": request_id, "seq": request_id, "method": "GET", "url": url, "host": host, "resource_type": "image",
        "is_navigation": False, "query_params": [[name, value] for name, value in params.items()], "request_headers": [],
        "response_headers": [], "post_data": None, "sizes": None, "mime_type": "image/gif", "third_party": third_party,
        "registrable_domain": ".".join(host.split(".")[-2:]), "response_status": 200,
    }


def capture(requests, **extra):
    page = request(0, "https://www.site.example/", {}, third_party=False)
    page.update({"resource_type": "document", "is_navigation": True})
    return {"start_url": page["url"], "page_url": page["url"], "requests": [page, *requests], "cookies": [], "storage": [],
            "websockets": [], "fingerprinting": None, "tcf": None, "consent": None, **extra}


REAL = [
    ("https://www.google-analytics.com/g/collect", {"tid": "G-JV69QQQV19"}, "ga_measurement_id", "G-JV69QQQV19"),
    ("https://www.google-analytics.com/collect", {"tid": "UA-1234567-2"}, "ga_measurement_id", "UA-1234567-2"),
    ("https://www.googletagmanager.com/gtm.js", {"id": "GTM-AB12CD3"}, "gtm_container_id", "GTM-AB12CD3"),
    ("https://analytics.google.com/g/collect", {"gtm": "45je4a10v9"}, "gtm_container_version", "45je4a10v9"),
    ("https://www.googletagmanager.com/gtag/js", {"id": "AW-987654321"}, "google_ads_id", "AW-987654321"),
    ("https://www.googleadservices.com/pagead/conversion/987654321/", {"label": "AbC-D_efG1234567890"}, "google_ads_label", "AbC-D_efG1234567890"),
    ("https://www.google.cl/pagead/1p-user-list/987654321/", {}, "google_ads_id", "987654321"),
    ("https://www.facebook.com/tr", {"id": "123456789012345", "ev": "PageView"}, "meta_pixel_id", "123456789012345"),
    ("https://ct.pinterest.com/v3/", {"tid": "2612345678901"}, "pinterest_tag_id", "2612345678901"),
    ("https://tr.snapchat.com/p", {"pid": SNAP}, "snapchat_pixel_id", SNAP),
    ("https://analytics.tiktok.com/i18n/pixel/events.js", {"sdkid": "C4ABCDEFGHIJ12345678"}, "tiktok_pixel_id", "C4ABCDEFGHIJ12345678"),
    ("https://px.ads.linkedin.com/collect", {"pid": "1234567", "fmt": "gif"}, "linkedin_partner_id", "1234567"),
]


@pytest.mark.parametrize(("url", "params", "rule", "value"), REAL)
def test_each_vendor_pattern_is_recognised_on_its_real_host(config, url, params, rule, value):
    analysis = analyze(capture([request(1, url, params)]), Lists(), config)
    found = analysis["site"]["summary"]["account_ids"]
    # (La URL de conversión de Google Ads lleva además el ID de conversión en la ruta: son dos IDs.)
    assert (rule, value) in [(item["rule"], item["value"]) for item in found]
    assert {item["rule"] for item in found} <= {rule, "google_ads_id"}
    # Regla 1: nivel y evidencia en cada dato.
    assert all(item["level"] == "INFERENCIA" and item["evidence_refs"] == [1] and item["requests"] == 1 for item in found)


def test_the_same_parameter_on_another_host_is_not_an_account_id(config):
    """«id» o «pid» en un host cualquiera no es un ID de cuenta: la regla exige host, parámetro y forma."""
    analysis = analyze(capture([
        request(1, "https://px.other-ads.example/tr", {"id": "123456789012345"}),
        request(2, "https://www.facebook.com/tr", {"id": "no-es-un-pixel"}),
        request(3, "https://www.facebook.com/plugins/like.php", {"id": "123456789012345"}),
    ]), Lists(), config)
    assert analysis["site"]["summary"]["account_ids"] == []


def test_account_ids_are_excluded_from_sync_and_persistence_but_visitor_ids_are_not(config):
    cookies = [{"name": "_sc_site", "value": SNAP, "domain": "www.site.example", "expires": -1},
               {"name": "_vid", "value": VISITOR, "domain": "www.site.example", "expires": -1}]
    full = capture([
        request(1, "https://tr.snapchat.com/p", {"pid": SNAP, "u": VISITOR}),
        request(2, "https://px.beta-metrics.example/c.gif", {"pid": SNAP, "u": VISITOR}),
    ], cookies=cookies)
    analysis = analyze(full, Lists(), config)
    by_type = {}
    for finding in analysis["findings"]:
        by_type.setdefault(finding["type"], []).append(finding)
    # El identificador del visitante sigue contando en los dos cruces…
    assert len(by_type["id_sync"]) == 1 and by_type["id_sync"][0]["details"]["value_length"] == len(VISITOR)
    assert {finding["details"]["stored_in"] for finding in by_type["persistent_id"]} == {"la cookie «_vid»"}
    # …y el ID de cuenta, en ninguno: ni siquiera en la request al host que no es del proveedor.
    assert all(SNAP[:8] not in finding["claim"] for finding in by_type["id_sync"] + by_type["persistent_id"])
    assert [item["value"] for item in analysis["site"]["summary"]["account_ids"]] == [SNAP]

    # Control: sin las reglas, el mismo ID de cuenta sí aparecería en los dos cruces.
    import dataclasses
    control = analyze(full, Lists(), dataclasses.replace(config, account_ids=AccountIds()))
    assert len([f for f in control["findings"] if f["type"] == "id_sync"]) == 2
    assert "la cookie «_sc_site»" in {f["details"]["stored_in"] for f in control["findings"] if f["type"] == "persistent_id"}


def test_test_hosts_only_apply_with_fixtures_enabled():
    raw = yaml.safe_load((pathlib.Path(settings.data_dir) / "account_ids.yaml").read_text(encoding="utf-8"))
    item = request(1, "http://tracker-a.fixtures.test/tr", {"id": "123456789012345"})

    class P:
        name, value = "id", "123456789012345"

    assert AccountIds(raw, allow_fixtures=True).detect([item], {1: [P]})[1] == {"123456789012345"}
    assert AccountIds(raw, allow_fixtures=False).detect([item], {1: [P]}) == ([], set())


def test_a_rule_without_host_or_pattern_does_not_load():
    with pytest.raises(ValueError):
        AccountIds({"rules": [{"id": "x", "vendor": "X", "label": "x", "params": ["id"], "pattern": "^1$"}]})
    with pytest.raises(ValueError):
        AccountIds({"rules": [{"id": "x", "vendor": "X", "label": "x", "hosts": ["x.example"], "params": ["id"]}]})


# --- el fixture, con un navegador real ---


@pytest.fixture(scope="module")
def accounts_analysis(manifest, analyzer_resources):
    fixtures_call("/__reset", "POST")
    page = manifest["account_ids"]["page"]
    outcome = run_async(run_scan(page))
    lists, config = analyzer_resources
    return analyze(prepare_capture(outcome.capture, start_url=page, page_url=outcome.result["final_url"]), lists, config)


def test_fixture_account_ids_match_the_manifest(accounts_analysis, manifest):
    expected = {(item["rule"], item["value"]) for item in manifest["account_ids"]["expected"]}
    found = accounts_analysis["site"]["summary"]["account_ids"]
    assert {(item["rule"], item["value"]) for item in found} == expected
    assert all(item["level"] == "INFERENCIA" and item["evidence_refs"] for item in found)


def test_fixture_only_the_visitor_id_is_synced_and_persistent(accounts_analysis, manifest):
    expected = manifest["account_ids"]
    sync = [finding for finding in accounts_analysis["findings"] if finding["type"] == "id_sync"]
    assert len(sync) == 1 and sync[0]["details"]["domains"] == expected["sync_domains"] and sync[0]["details"]["value_length"] == 32
    persistent = [finding for finding in accounts_analysis["findings"] if finding["type"] == "persistent_id"]
    assert persistent and {finding["details"]["stored_in"] for finding in persistent} == {f"la cookie «{expected['visitor_cookie']}»"}
