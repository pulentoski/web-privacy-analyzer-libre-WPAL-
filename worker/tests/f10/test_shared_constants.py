"""F10: un valor compartido entre organizaciones solo cuenta si puede ser un identificador.

Caso real: "153.0.8010.12" (la versión de Chrome) aparecía como "mismo valor enviado a
varias organizaciones" en 11 scans. Es igual para todo el que usa ese navegador.
"""

import pathlib

import pytest
import yaml

from app.analyzer.config import load_config
from app.analyzer.constants import SharedConstants
from app.analyzer.engine import analyze
from app.analyzer.fingerprinting import ATTRIBUTES
from app.analyzer.parameters import is_identifier_like, shannon_entropy, value_shapes
from app.config import settings

CHROME = "153.0.8010.12"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
REAL_ID = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"


class Lists:
    """Listas mínimas: sin reglas, y cada dominio con dueño propio salvo los de `owners`."""

    version, sources, license_profile = "test", [], "no_comercial"

    def __init__(self, owners=None):
        self.owners = owners or {}

    def entity(self, domain):
        return self.owners.get(domain, "no_disponible")

    def match(self, request, source_host):
        return []


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="module")
def constants():
    return SharedConstants(yaml.safe_load((pathlib.Path(settings.data_dir) / "shared_constants.yaml").read_text(encoding="utf-8")))


def request(request_id, host, params, **extra):
    domain = ".".join(host.split(".")[-2:])
    return {
        "request_id": request_id, "seq": request_id, "method": "GET", "url": f"https://{host}/collect", "host": host,
        "resource_type": "fetch", "is_navigation": False, "query_params": [[name, value] for name, value in params.items()],
        "request_headers": [{"name": "user-agent", "value": UA}, {"name": "sec-ch-ua", "value": '"Chromium";v="153", "Not.A/Brand";v="24"'},
                            {"name": "accept-language", "value": "es-CL,es;q=0.9"}],
        "response_headers": [], "post_data": None, "sizes": None, "mime_type": "application/json", "third_party": domain != "site.example",
        "registrable_domain": domain, "response_status": 200, **extra,
    }


def capture(requests, **extra):
    page = request(0, "www.site.example", {})
    page.update({"resource_type": "document", "is_navigation": True, "url": "https://www.site.example/"})
    return {"start_url": "https://www.site.example/", "page_url": "https://www.site.example/", "requests": [page, *requests],
            "cookies": [], "storage": [], "websockets": [], "fingerprinting": None, "tcf": None, "consent": None, **extra}


def sync_findings(analysis):
    return [finding for finding in analysis["findings"] if finding["type"] == "id_sync"]


# --- el caso reportado ---


def test_chrome_version_is_not_an_identifier():
    shapes = value_shapes(CHROME)
    assert "version" in shapes
    assert is_identifier_like(CHROME, shapes, shannon_entropy(CHROME)) is False
    # Un identificador de verdad lo sigue siendo, y un número largo con puntos que no es versión también.
    assert is_identifier_like(REAL_ID, value_shapes(REAL_ID), shannon_entropy(REAL_ID)) is True
    assert "version" not in value_shapes("GA1.2.1234567890.1700000000")
    for version in ("1.2.3", "v4.2.1", "10.0.19045.3803"):
        assert "version" in value_shapes(version), version
    for other in ("1.2", "153", "a.b.c.d", "1234567890123.45678"):
        assert "version" not in value_shapes(other), other


def test_browser_version_sent_to_two_organizations_is_not_id_sync(config):
    """El falso positivo: la versión de Chrome llega a dos empresas y NO es sincronización."""
    analysis = analyze(capture([
        request(1, "t.alpha-ads.example", {"cv": CHROME}),
        request(2, "px.beta-metrics.example", {"browser_version": CHROME}),
    ]), Lists(), config)
    assert sync_findings(analysis) == []
    assert not any(reason["signal"] == "id_sync" for item in analysis["requests"] for reason in item["reasons"])
    breakdown = {item["component"]: item["count"] for item in analysis["site"]["breakdown"]}
    assert breakdown["id_sync"] == 0


def test_a_real_identifier_sent_to_two_organizations_still_is_id_sync(config):
    analysis = analyze(capture([
        request(1, "t.alpha-ads.example", {"uid": REAL_ID, "cv": CHROME}),
        request(2, "px.beta-metrics.example", {"partner_uid": REAL_ID, "v": CHROME}),
    ]), Lists(), config)
    found = sync_findings(analysis)
    assert len(found) == 1 and found[0]["level"] == "EVIDENCIA" and sorted(found[0]["evidence_refs"]) == [1, 2]
    assert found[0]["details"]["domains"] == ["alpha-ads.example", "beta-metrics.example"]
    assert {item["component"]: item["count"] for item in analysis["site"]["breakdown"]}["id_sync"] == 1
    # La razón lleva los datos sueltos que usan las frases técnicas.
    reason = next(reason for reason in analysis["requests"][1]["reasons"] if reason["signal"] == "id_sync")
    assert reason["data"] == {"other_domains": ["beta-metrics.example"], "other_entities": []}


def test_same_organization_is_still_not_sync(config):
    lists = Lists({"alpha-ads.example": "Alpha", "alpha-cdn.example": "Alpha"})
    analysis = analyze(capture([request(1, "t.alpha-ads.example", {"uid": REAL_ID}), request(2, "s.alpha-cdn.example", {"uid": REAL_ID})]), lists, config)
    assert sync_findings(analysis) == []


def test_shared_constants_are_excluded_and_counted_with_their_reason(config):
    """Trozos del User-Agent, IDs de medición del sitio, tamaños de anuncios y dominios: fuera del cruce, pero contados."""
    shared = {
        "ua_piece": "AppleWebKit/537.36",            # está dentro del User-Agent enviado
        "tag": "G-JV69QQQV19",                       # ID de medición de Google: identifica al sitio
        "sizes": "970x90|728x90",                    # tamaños de anuncios
        "source": "id5-sync.example.com",            # un dominio
        "uid": REAL_ID,                              # este sí es un identificador
    }
    analysis = analyze(capture([request(1, "t.alpha-ads.example", shared), request(2, "px.beta-metrics.example", shared)]), Lists(), config)
    found = sync_findings(analysis)
    assert len(found) == 1 and found[0]["details"]["value_length"] == len(REAL_ID)
    excluded = analysis["site"]["summary"]["shared_values_excluded"]
    assert excluded["total"] == 4 and excluded["by_reason"] == {"user_agent": 1, "constant": 3}
    assert {item["reason"] for item in excluded["examples"]} == {"user_agent", "constant:google_tag_id", "constant:ad_sizes", "constant:hostname"}
    assert all(item["domains"] == 2 for item in excluded["examples"])


def test_values_read_from_the_browser_environment_are_excluded(config, constants):
    fingerprinting = {"calls": [{"call_id": 1, "api": "navigator.userAgentData.getHighEntropyValues", "script_url": "https://t.alpha-ads.example/a.js",
                                 "frame_url": "https://www.site.example/", "count": 1, "details": {"value": '{"uaFullVersion":"153.0.8010.12","platformVersion":"6.8.0-generic-x86"}'}}],
                      "available": [], "truncated": False}
    full = capture([request(1, "t.alpha-ads.example", {"pv": "6.8.0-generic-x86"}), request(2, "px.beta-metrics.example", {"pv": "6.8.0-generic-x86"})], fingerprinting=fingerprinting)
    environment = constants.environment(full)
    assert constants.classify("6.8.0-generic-x86", {"pv"}, environment) in ("version", "environment")
    assert sync_findings(analyze(full, Lists(), config)) == []


@pytest.mark.parametrize(("value", "names", "expected"), [
    (CHROME, {"cv"}, "version"),
    ("v4.2.1", {"sdk"}, "version"),
    ("5.10.0-beta.2", {"lib"}, "version"),
    ("AppleWebKit/537.36", {"x"}, "user_agent"),
    ("G-JV69QQQV19", {"tid"}, "constant:google_tag_id"),
    ("GTM-ABC1234", {"id"}, "constant:google_tag_id"),
    ("970x90|728x90", {"prev_iu_szs"}, "constant:ad_sizes"),
    ("gpt_m202610010101", {"li"}, "constant:gpt_build"),
    ("45je6a51v877838426z8849371110za20gzb849371110", {"gtm"}, "constant_param"),
    (REAL_ID, {"uid"}, None),
    (REAL_ID, {"gtm", "uid"}, None),                       # si algún parámetro NO es constante documentada, cuenta
    ("fb.1.1700000000000.1234567890", {"fbp"}, None),
    ("3af70a5f990f528bb62e22c8ef4e185ca02ce81f3578fe038f7e09e05b4129b3", {"eids[2].id"}, None),
])
def test_classify(constants, value, names, expected):
    environment = constants.environment(capture([request(1, "t.alpha-ads.example", {})]))
    assert constants.classify(value, names, environment) == expected


def test_classify_never_fails_on_hostile_input(constants):
    for value in ("", None, 12, "x" * 5000, "(" * 200, "\x00\x00"):
        assert constants.classify(value, {"a"}, {"headers": [UA.lower()], "apis": []}) in (None, "user_agent")


# --- cookies persistentes ---


def test_persistent_cookies_become_a_finding_with_evidence(config):
    visit = 1_790_000_000.0
    cookies = [
        {"name": "t_gid", "value": "abc", "domain": ".alpha-ads.example", "expires": visit + 390 * 86_400, "third_party": True},
        {"name": "t_s", "value": "abc", "domain": "t.alpha-ads.example", "expires": visit + 30 * 86_400 + 5, "third_party": True},
        {"name": "sess", "value": "abc", "domain": "www.site.example", "expires": -1, "third_party": False},          # de sesión
        {"name": "short", "value": "abc", "domain": "www.site.example", "expires": visit + 3600, "third_party": False},  # dura una hora
        {"name": "_site", "value": "abc", "domain": "www.site.example", "expires": visit + 2 * 86_400, "third_party": False},
    ]
    with_cookie = request(1, "t.alpha-ads.example", {}, response_headers=[{"name": "set-cookie", "value": "t_gid=abc; Max-Age=33696000"}])
    analysis = analyze(capture([with_cookie], cookies=cookies, visit_ts=visit), Lists({"alpha-ads.example": "Alpha"}), config)
    found = {finding["details"]["domain"]: finding for finding in analysis["findings"] if finding["type"] == "persistent_cookie"}
    assert set(found) == {"alpha-ads.example", "site.example"}
    alpha = found["alpha-ads.example"]
    assert alpha["level"] == "EVIDENCIA" and alpha["evidence_refs"] == [1]
    assert alpha["details"] == {"domain": "alpha-ads.example", "entity": "Alpha", "cookies": 2, "max_days": 390, "names": ["t_gid", "t_s"], "third_party": True}
    # La creó un script y nunca viajó: la evidencia es la primera request de la visita.
    site = found["site.example"]
    assert site["details"]["cookies"] == 1 and site["details"]["max_days"] == 2 and site["evidence_refs"] == [0]
    # Sin la hora de la visita no se puede saber cuánto le queda a una cookie: no se afirma nada.
    undated = analyze(capture([with_cookie], cookies=cookies), Lists(), config)
    assert not [finding for finding in undated["findings"] if finding["type"] == "persistent_cookie"]


def test_every_finding_has_level_and_evidence(config):
    analysis = analyze(capture([request(1, "t.alpha-ads.example", {"uid": REAL_ID}), request(2, "px.beta-metrics.example", {"uid": REAL_ID})],
                               cookies=[{"name": "a", "value": "b", "domain": "t.alpha-ads.example", "expires": 2_000_000_000.0, "third_party": True}], visit_ts=1_790_000_000.0),
                       Lists(), config)
    assert analysis["findings"]
    for finding in analysis["findings"]:
        assert finding["level"] in ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO") and finding["evidence_refs"]


# --- las frases técnicas nombran lo mismo que el analizador ---


def test_api_attribute_table_matches_the_analyzer():
    explanations = yaml.safe_load((pathlib.Path(settings.data_dir) / "explanations.yaml").read_text(encoding="utf-8"))
    expected = {api: attribute for attribute, apis in ATTRIBUTES.items() for api in apis}
    assert explanations["api_attributes"] == expected
    assert set(ATTRIBUTES) <= set(explanations["data_names"])
