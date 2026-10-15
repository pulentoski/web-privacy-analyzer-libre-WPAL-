"""v1.4.6 (docs/adr/033): librerías de CDN públicos, UserWay, sincronización solo con 2+ organizaciones, alias de
organización y propósito de las cookies por su nombre. Capturas en memoria con la forma de los casos reales
(laserena.cl, userena.cl), sin red."""

import pathlib

import pytest
import yaml

from app.analyzer.attribution import CookiePurposes, PublicCdns
from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.interaction import BenignLibraries
from app.analyzer.lists import OrganizationCatalog
from app.config import settings
from tests.v121.test_party_blocking_service_consent import capture, req
from tests.v145.test_rules import ENTITIES, CatalogLists, get, laserena, services

DATA = pathlib.Path(settings.data_dir)
VISITOR = "57cb35e2-4a1f-4c3b-9d7e-2f8a6b1c0d9e"
OTHER = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"


def read(name):
    return yaml.safe_load((DATA / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="module")
def catalog():
    return OrganizationCatalog(read("organizations.yaml"), read("org_aliases.yaml"))


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


def site_capture(page_url, requests, **extra):
    """capture() con la página del sitio indicado (la de v1.2.1 es airbnb.cl)."""
    cap = capture(requests, **extra)
    page = req(0, page_url, third_party=False, resource_type="document", is_navigation=True)
    cap.update(start_url=page_url, page_url=page_url, requests=[page, *cap["requests"][1:]])
    return cap


# --- 1. librerías en CDN público ---


@pytest.fixture(scope="module")
def cdns():
    return PublicCdns(read("organizations.yaml")["public_cdns"], BenignLibraries(read("benign_libraries.yaml")))


@pytest.mark.parametrize("url, library, cdn", [
    ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js", "bootstrap", "jsDelivr"),
    ("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js", "@popperjs/core", "jsDelivr"),
    ("https://cdn.jsdelivr.net/npm/slick-carousel@1.8.1/slick/slick.min.js", "slick-carousel", "jsDelivr"),
    ("https://fastly.jsdelivr.net/gh/kenwheeler/slick@1.8.1/slick/slick.js", "kenwheeler/slick", "jsDelivr"),
    ("https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js", "leaflet", "cdnjs"),
    ("https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.11.3/font/fonts/bootstrap-icons.woff2?dd67", "bootstrap-icons", "cdnjs"),
    ("https://unpkg.com/leaflet@1.9.4/dist/leaflet.js", "leaflet", "unpkg"),
    ("https://unpkg.com/@scope/pkg@1.0.0/index.js", "@scope/pkg", "unpkg"),
])
def test_library_is_read_from_the_path(cdns, url, library, cdn):
    host = url.split("/")[2]
    found = cdns.of(url, host)
    assert found["library"] == library and found["cdn"] == cdn
    assert found["label"] == f"librería {library} en CDN público ({cdn})"


@pytest.mark.parametrize("url", [
    "https://cdn.jsdelivr.net/combine/npm/a@1,npm/b@2", "https://cdnjs.cloudflare.com/cdn-cgi/x.js", "https://unpkg.com/",
    "https://cdn.jsdelivr.net/npm/%3Cimg%20src=x%3E/a.js",
])
def test_without_a_readable_package_the_cdn_is_named_not_its_company(cdns, url):
    found = cdns.of(url, url.split("/")[2])
    assert found["library"] is None and found["label"].startswith("librería en CDN público (")
    assert "Prospect One" not in found["label"] and "Cloudflare" not in found["label"]


def test_other_hosts_are_not_public_cdns(cdns):
    assert cdns.of("https://www.cloudflare.com/ajax/libs/x/1/x.js", "www.cloudflare.com") is None
    assert cdns.of("https://jsdelivr.net/npm/x", "jsdelivr.net") is None


def test_known_library_is_marked_benign(cdns):
    found = cdns.of("https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js", "cdn.jsdelivr.net")
    assert found["library"] == "chart.js" and found["benign"] is True and found["benign_label"] == "librería de gráficos"
    assert cdns.of("https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.min.js", "cdn.jsdelivr.net")["benign"] is False


def test_requests_and_services_are_attributed_to_the_library(config, catalog):
    extra = [get(10, "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js")]
    result = analyze(laserena(extra), CatalogLists(ENTITIES, catalog), config)
    by_id = {item["request_id"]: item for item in result["requests"]}
    assert by_id[1]["entity"] == "librería bootstrap en CDN público (jsDelivr)"
    assert by_id[2]["entity"] == "librería font-awesome en CDN público (cdnjs)"
    assert by_id[8]["entity"] == "librería leaflet en CDN público (unpkg)"
    # Lo que no es un CDN público sigue atribuido a su organización.
    assert by_id[3]["entity"] == "Google"
    dumped = repr(result["requests"]) + repr(result["site"]["summary"]["third_party_services"])
    assert "Prospect One" not in dumped and "'Cloudflare'" not in dumped
    assert "unpkg" not in {item["entity"] for item in result["requests"]}
    listed = services(result)
    chart = listed[("librería chart.js en CDN público (jsDelivr)", "library_cdn")]
    assert chart["library"] == {"library": "chart.js", "cdn": "jsDelivr", "benign": True, "benign_label": "librería de gráficos"}
    assert listed[("librería bootstrap en CDN público (jsDelivr)", "library_cdn")]["library"]["benign"] is False
    # Las librerías de un mismo CDN cuentan como una organización (la del CDN), como antes Prospect One.
    assert result["site"]["summary"]["third_party_services"]["organizations"] == 7
    # La clasificación por organización no cambia: el CDN sigue siendo un tercero.
    assert by_id[1]["party"] == "third_party"


# --- 2. UserWay ---


def test_userway_is_one_organization_with_an_accessibility_widget(config, catalog):
    for host in ("userway.org", "cdn.userway.org", "api.userway.org"):
        assert catalog.lookup(host) == (True, "UserWay")
    service = config.service_types.of(entity="UserWay", domain="userway.org")
    assert service == {"type": "accessibility_widget", "label": "widget de accesibilidad"}


# --- 3. sincronización solo con 2 o más organizaciones ---


def userena(extra=(), storage_value=VISITOR):
    cap = site_capture("https://userena.cl/", [
        {**get(1, "https://cdn.userway.org/widget.js"), "registrable_domain": "userway.org"},
        {**get(2, "https://api.userway.org/api/v1/settings", resource_type="xhr", params={"uid": VISITOR}), "registrable_domain": "userway.org"},
        {**get(3, "https://cdn.userway.org/widgetapp/bundle.js", params={"uid": VISITOR}), "registrable_domain": "userway.org"},
        *extra,
    ])
    cap["storage"] = [{"storage_type": "local", "key": "uw-uid", "value": storage_value, "origin": "https://userena.cl"}]
    return cap


def test_identifier_reaching_one_organization_goes_to_group_1(config, catalog):
    result = analyze(userena(), CatalogLists({}, catalog), config)
    assert not findings_of(result, "id_sync") and not findings_of(result, "persistent_id")
    [item] = findings_of(result, "persistent_id_org")
    assert item["level"] == "EVIDENCIA" and item["claim"].startswith("Identificador persistente enviado a UserWay:")
    assert item["details"]["organization"] == "UserWay" and item["details"]["stored_in"] == "el ítem «uw-uid» de localStorage"
    assert sorted(item["evidence_refs"]) == [2, 3]
    # El índice no cambia por la reclasificación: sigue siendo un tercero que recibió un identificador guardado.
    counts = {entry["component"]: entry["count"] for entry in result["site"]["breakdown"]}
    assert counts["persistent_id_recipients"] == 1 and counts["id_sync"] == 0


def test_the_site_itself_is_not_a_second_organization(config, catalog):
    own = {**get(4, "https://userena.cl/api/visit", resource_type="xhr", params={"vid": OTHER}), "third_party": False}
    tracker = get(5, "https://px.tracker-uno.example/p.gif", resource_type="image", params={"vid": OTHER})
    result = analyze(userena([own, tracker]), CatalogLists({}, catalog), config)
    assert not findings_of(result, "id_sync")
    single = [item for item in findings_of(result, "persistent_id_org") if item["details"]["domain"] == "tracker-uno.example"]
    assert len(single) == 1 and "al propio sitio y a tracker-uno.example" in single[0]["claim"]
    assert sorted(single[0]["evidence_refs"]) == [4, 5]


def test_two_organizations_are_still_sync_in_group_5(config, catalog):
    other = get(4, "https://px.tracker-uno.example/p.gif", resource_type="image", params={"vid": VISITOR})
    result = analyze(userena([other]), CatalogLists({}, catalog), config)
    [sync] = findings_of(result, "id_sync")
    assert sync["details"]["owners"] == 2 and "de 2 organizaciones distintas del sitio" in sync["claim"]
    assert {item["details"]["domain"] for item in findings_of(result, "persistent_id")} == {"userway.org", "tracker-uno.example"}
    assert not findings_of(result, "persistent_id_org")


# --- 4. alias de organización ---


def test_aliases_make_domains_of_one_owner_the_same_organization(config, catalog):
    for host in ("laserena.cl", "lineadirecta.laserena.cl", "munilaserena.cl", "apis.munilaserena.cl"):
        assert catalog.lookup(host) == (True, "Municipalidad de La Serena")
    cap = site_capture("https://laserena.cl/", [
        {**get(1, "https://apis.munilaserena.cl/v1/noticias", resource_type="xhr"), "registrable_domain": "munilaserena.cl"},
        {**get(2, "https://lineadirecta.laserena.cl/", resource_type="document"), "third_party": False, "registrable_domain": "laserena.cl"},
        get(3, "https://www.google.com/recaptcha/api.js", params={"render": "explicit"}),
    ])
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    parties = result["site"]["summary"]["parties"]
    assert parties["same_org_domains"] == ["munilaserena.cl"] and parties["third_party_domains"] == ["google.com"]
    assert {item["request_id"]: item["party"] for item in result["requests"]}[1] == "same_org"
    assert result["site"]["summary"]["third_party_domains"] == 1


def test_without_aliases_the_catalog_behaves_as_before():
    catalog = OrganizationCatalog(read("organizations.yaml"))
    assert catalog.lookup("munilaserena.cl") == (False, None) and catalog.lookup("googleapis.com") == (True, "Google")


@pytest.mark.needs_stack  # carga las listas reales de ./data (no versionadas); se omite en CI.
def test_real_lists_load_the_aliases(analyzer_resources):
    lists, _ = analyzer_resources
    assert lists.entity("munilaserena.cl") == lists.entity("laserena.cl") == "Municipalidad de La Serena"
    assert lists.entity("userway.org") == "UserWay" and lists.entity("jsdelivr.net") == "Prospect One"


# --- 5. propósito de las cookies por su nombre ---


@pytest.mark.parametrize("name, purpose", [
    ("session", "funcional"), ("PHPSESSID", "funcional"), ("cf_clearance", "funcional"), ("__cf_bm", "funcional"),
    ("lang", "funcional"), ("idioma", "funcional"), ("site_lang", "funcional"), ("cart", "funcional"), ("laravel_session", "funcional"), ("ci_session", "funcional"),
    ("_ga", "analitica"), ("_gid", "analitica"), ("_ga_VED1YSGNC7", "analitica"), ("_clck", "analitica"), ("_clsk", "analitica"),
    ("_hjSessionUser_123", "analitica"), ("_hjid", "analitica"),
    ("_fbp", "publicidad"), ("_fbc", "publicidad"), ("_gcl_au", "publicidad"), ("_ttp", "publicidad"), ("IDE", "publicidad"),
    ("test_cookie", "publicidad"),
    ("71ab4f43b039d574093f6811133b136b", "sin_clasificar"), ("taboola_session_id", "sin_clasificar"), ("appier_session", "sin_clasificar"), ("fx_session", "sin_clasificar"), ("_gac", "sin_clasificar"),
])
def test_cookie_purpose_by_known_name(name, purpose):
    assert CookiePurposes(read("cookie_purposes.yaml")).of(name) == purpose


def with_cookies(cookies):
    cap = site_capture("https://userena.cl/", [get(1, "https://www.google-analytics.com/g/collect", resource_type="xhr", params={"tid": "G-X"})])
    cap["cookies"] = [{"name": name, "value": "v", "domain": domain, "expires": -1, "third_party": third} for name, domain, third in cookies]
    return cap


COOKIES = [("PHPSESSID", "userena.cl", False), ("cf_clearance", ".userena.cl", False), ("_ga", ".userena.cl", False),
           ("_ga_ABC123", ".userena.cl", False), ("_fbp", ".userena.cl", False), ("IDE", ".doubleclick.net", True),
           ("71ab4f43b039d574093f6811133b136b", ".userena.cl", False)]


def test_cookie_purposes_in_summary_and_findings_including_first_party(config, catalog):
    result = analyze(with_cookies(COOKIES), CatalogLists({}, catalog), config)
    purposes = result["site"]["summary"]["cookie_purposes"]
    assert purposes["level"] == "INFERENCIA" and purposes["basis"] == "nombre"
    assert purposes["by_purpose"] == {"publicidad": 2, "analitica": 2, "funcional": 2, "sin_clasificar": 1}
    assert {row["name"]: row["domain"] for row in purposes["cookies"]}["_ga"] == "userena.cl"
    by_purpose = {item["details"]["purpose"]: item for item in findings_of(result, "cookie_purpose")}
    assert set(by_purpose) == {"analitica", "publicidad"} and all(item["level"] == "INFERENCIA" for item in by_purpose.values())
    assert by_purpose["publicidad"]["details"] == {"purpose": "publicidad", "label": "publicidad", "cookies": 2, "first_party": 1,
                                                   "third_party": 1, "names": ["IDE", "_fbp"]}
    assert "inferencia por el nombre" in by_purpose["analitica"]["claim"]
    [functional] = findings_of(result, "cookie_purpose_functional")
    assert functional["level"] == "INFERENCIA" and functional["details"]["names"] == ["PHPSESSID", "cf_clearance"]
    assert all(item["evidence_refs"] for item in findings_of(result, "cookie_purpose") + [functional])


def test_functional_cookies_do_not_add_to_the_index(config, catalog):
    lists = CatalogLists({}, catalog)
    functional_only = analyze(with_cookies(COOKIES[:2]), lists, config)
    counts = {entry["component"]: entry for entry in functional_only["site"]["breakdown"]}
    assert counts["stored_items"]["count"] == 0 and counts["stored_items"]["points"] == 0
    mixed = analyze(with_cookies(COOKIES), lists, config)
    assert {entry["component"]: entry["count"] for entry in mixed["site"]["breakdown"]}["stored_items"] == 5
    none = analyze(with_cookies([]), lists, config)
    assert none["site"]["summary"]["cookie_purposes"]["by_purpose"] == {"publicidad": 0, "analitica": 0, "funcional": 0, "sin_clasificar": 0}
    assert not findings_of(none, "cookie_purpose") and not findings_of(none, "cookie_purpose_functional")


def test_persistent_cookie_finding_counts_purposes(config, catalog):
    cap = with_cookies([])
    cap["visit_ts"] = 1_800_000_000.0
    cap["cookies"] = [{"name": name, "value": "v", "domain": ".userena.cl", "expires": 1_800_000_000.0 + 400 * 86_400, "third_party": False}
                      for name in ("_ga", "_ga_ABC", "lang")]
    [item] = findings_of(analyze(cap, CatalogLists({}, catalog), config), "persistent_cookie")
    assert item["details"]["purposes"] == {"analitica": 2, "funcional": 1}

