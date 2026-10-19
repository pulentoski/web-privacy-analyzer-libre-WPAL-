"""v1.5.1: categoría por subdominio publicitario (px.ads.linkedin.com) y regla concreta de la lista. Sin red."""

import asyncio
import json

import pytest

from app.analyzer import ANALYZER_VERSION
from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.lists import FilterLists
from app.config import settings
from tests.v121.test_party_blocking_service_consent import Lists, capture, req

VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
ENTITIES = {"airbnb.cl": "Airbnb", "linkedin.com": "Microsoft", "licdn.com": "Microsoft"}
# Reglas que el motor optimizado de adblock-rust une en un solo filtro («/gtm.js <+> /gtm/gtm- <+> …»).
GTM_RULES = ["/min/gtm/*", ".js?id=GTM-", "/gtm.min.js", "/gtm.js", "/gtm/gtm-"]


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def categories(result):
    return {item["request_id"]: item["category"] for item in result["requests"]}


def test_analyzer_version():
    assert ANALYZER_VERSION == "1.18.0"


@pytest.mark.parametrize("host, domain, expected", [
    ("px.ads.linkedin.com", "linkedin.com", "advertising"),
    ("ads.linkedin.com", "linkedin.com", "advertising"),
    ("adservice.google.cl", "google.cl", "advertising"),
    # Solo etiquetas completas y a la izquierda del dominio registrable.
    ("www.linkedin.com", "linkedin.com", None),
    ("loads.example.com", "example.com", None),
    ("adsense.example.com", "example.com", None),
    ("ads.com", "ads.com", None),
    ("x.ads.com", "ads.com", None),
    ("PX.ADS.LINKEDIN.COM.", "linkedin.com", "advertising"),
    (None, "linkedin.com", None),
    ("px.ads.linkedin.com", None, None),
])
def test_host_category(config, host, domain, expected):
    assert config.host_category(host, domain) == expected


def test_advertising_subdomain_of_a_social_organization(config):
    cap = capture([
        req(1, f"https://px.ads.linkedin.com/collect?pid=123&uid={VISITOR}", params={"pid": "123", "uid": VISITOR}),
        req(2, "https://www.linkedin.com/li/track", params={"pid": "123"}),
        req(3, "https://static.licdn.com/sc/h/app.js", resource_type="script"),
    ])
    result = analyze(cap, Lists(ENTITIES), config)
    # linkedin.com es «social» (domain_categories.yaml); su subdominio publicitario, Publicidad.
    assert categories(result) == {0: "first-party", 1: "advertising", 2: "social", 3: "social"}
    by_id = {item["request_id"]: item for item in result["requests"]}
    assert by_id[1]["entity"] == by_id[2]["entity"] == "Microsoft", "la organización no cambia"
    advertising = next(item for item in result["site"]["data_categories"] if item["category"] == "ADVERTISING")
    assert advertising["evidence_refs"] == [1]


def test_category_does_not_change_the_score(config):
    """La categoría se decide después del puntaje: el subdominio publicitario no cambia score ni banda."""
    ads = analyze(capture([req(1, f"https://px.ads.linkedin.com/collect?uid={VISITOR}", params={"uid": VISITOR})]), Lists(ENTITIES), config)
    www = analyze(capture([req(1, f"https://px.www.linkedin.com/collect?uid={VISITOR}", params={"uid": VISITOR})]), Lists(ENTITIES), config)
    assert categories(ads)[1] == "advertising" and categories(www)[1] == "social"
    pick = lambda result: [(item["score"], item["band"], item["reasons"]) for item in result["requests"]]  # noqa: E731
    assert pick(ads) == pick(www)
    assert (ads["site"]["score"], ads["site"]["band"]) == (www["site"]["score"], www["site"]["band"])


def test_first_party_ads_subdomain_stays_first_party(config):
    cap = capture([req(1, "https://ads.airbnb.cl/banner.png", third_party=False)])
    assert categories(analyze(cap, Lists(ENTITIES), config))[1] == "first-party"


@pytest.fixture
def gtm_lists(tmp_path):
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "gtm.txt").write_text("[Adblock Plus 2.0]\n" + "\n".join(GTM_RULES) + "\n", encoding="utf-8")
    (lists_dir / "MANIFEST.json").write_text(json.dumps({"sources": [
        {"id": "easyprivacy", "file": "gtm.txt", "format": "adblock", "sha256": "x", "license": "GPL-3.0", "noncommercial": False}]}))
    return FilterLists(tmp_path)


@pytest.mark.parametrize("url, rules", [
    # Coincide con tres reglas de la lista: se informa UNA de ellas, tal como está escrita, no el bloque unido.
    ("https://www.airbnb.cl/gtg/gtm-46mk/gtm.js?id=GTM-46MK", {".js?id=GTM-", "/gtm.js", "/gtm/gtm-"}),
    ("https://www.airbnb.cl/static/gtm.min.js", {"/gtm.min.js"}),
])
def test_list_match_reports_the_concrete_rule(gtm_lists, url, rules):
    request = {"url": url, "host": "www.airbnb.cl", "resource_type": "script", "third_party": False, "seq": 3}
    matches = gtm_lists.match(request, "www.airbnb.cl")
    assert len(matches) == 1 and matches[0]["list"] == "easyprivacy"
    assert matches[0]["rule"] in rules and "<+>" not in matches[0]["rule"]


# --- Volcado con tráfico en curso (regresión de 1.5.0: KeyError 'built' al terminar una captura interactiva) ---

def test_requests_arriving_during_the_dump_do_not_break_it():
    from app.browser.network_monitor import NetworkMonitor
    from tests.helpers import run_async

    class Request:
        method, url = "GET", "http://site.example/a"

    def record(seq):
        return {"seq": seq, "request": Request(), "response": None, "finished": True, "failed": None}

    async def scenario():
        monitor = NetworkMonitor.__new__(NetworkMonitor)
        monitor._loop = asyncio.get_running_loop()
        monitor._tasks, monitor._cdp, monitor._matched, monitor._pre = set(), {}, 0, None
        monitor._records = [record(0), record(1)]

        async def build(rec, cdp, first_party, deadline):
            await asyncio.sleep(0)
            monitor._records.append(record(len(monitor._records)))  # la pestaña sigue generando tráfico
            return {"seq": rec["seq"]}

        monitor._build = build
        first = await monitor._build_pending({"site.example"}, monitor._loop.time() + 5)
        # Solo lo que había al empezar; lo que llegó durante el volcado entra en el siguiente.
        assert [rec["built"]["seq"] for rec in first] == [0, 1] and len(monitor._records) == 4
        second = await monitor._build_pending({"site.example"}, monitor._loop.time() + 5)
        assert [rec["built"]["seq"] for rec in second] == [0, 1, 2, 3]

    run_async(scenario())
