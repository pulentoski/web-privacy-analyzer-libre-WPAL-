"""v1.4.7 (docs/adr/034): las fugas hacia un CDN público siguen informándose y nombran al CDN (no a la librería), y
las cookies se clasifican en dos pasos: nombre conocido y, si no, tipo de servicio de la organización. Sin red."""

import pathlib

import pytest
import yaml

from app.analyzer.attribution import CookiePurposes
from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.lists import OrganizationCatalog
from app.config import settings
from tests.v145.test_rules import ENTITIES, CatalogLists, get
from tests.v146.test_v146 import site_capture

DATA = pathlib.Path(settings.data_dir)
PAGE = "https://laserena.cl/noticias/detalle?id=7"
REFERER = [{"name": "Referer", "value": PAGE}]


def read(name):
    return yaml.safe_load((DATA / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="module")
def lists():
    return CatalogLists({**ENTITIES, "criteo.com": "Criteo", "clarity.ms": "Microsoft Clarity"},
                        OrganizationCatalog(read("organizations.yaml"), read("org_aliases.yaml")))


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


# --- 1. la librería cambia la atribución del script, no oculta las fugas de la request ---


def with_referer(request):
    request["request_headers"] = REFERER
    return request


def test_referer_leak_to_a_public_cdn_is_kept_and_names_the_cdn(config, lists):
    cap = site_capture(PAGE, [
        with_referer(get(1, "https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.11.3/font/bootstrap-icons.min.css", resource_type="stylesheet")),
        get(2, "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"),
    ])
    result = analyze(cap, lists, config)
    by_id = {item["request_id"]: item for item in result["requests"]}
    assert by_id[1]["entity"] == "librería bootstrap-icons en CDN público (cdnjs)" and by_id[1]["referer"] == "full_url"
    [leak] = findings_of(result, "referer_leak")
    assert leak["evidence_refs"] == [1] and leak["details"]["domain"] == "cloudflare.com"
    assert leak["details"]["recipient"] == "CDN público cdnjs (Cloudflare)"
    reason = next(item for item in by_id[1]["reasons"] if item["signal"] == "referer_full_url")
    assert reason["data"]["recipient"] == "CDN público cdnjs (Cloudflare)"
    counts = {entry["component"]: entry["count"] for entry in result["site"]["breakdown"]}
    assert counts["url_leak_recipients"] == 1


def test_url_leak_to_a_public_cdn_names_the_cdn(config, lists):
    cap = site_capture(PAGE, [get(1, "https://cdn.jsdelivr.net/npm/x@1/x.js", params={"page": PAGE})])
    [leak] = findings_of(analyze(cap, lists, config), "url_leak")
    assert leak["details"]["recipient"] == "CDN público jsDelivr (Prospect One)"


def test_mixed_group_is_named_after_the_organization_not_a_library(config, lists):
    cap = site_capture(PAGE, [
        with_referer(get(1, "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js")),
        with_referer(get(2, "https://challenges.cloudflare.com/turnstile/v0/api.js")),
    ])
    [leak] = findings_of(analyze(cap, lists, config), "referer_leak")
    assert leak["details"]["recipient"] == "Cloudflare" and sorted(leak["evidence_refs"]) == [1, 2]


# --- 2 y 3. cookies en dos pasos ---


@pytest.mark.parametrize("name, purpose", [
    ("aep_usuc_f", "funcional"), ("intl_locale", "funcional"), ("xman_us_f", "funcional"), ("_m_h5_tk", "funcional"),
    ("JSESSIONID", "funcional"), ("isg", "funcional"), ("tfstk", "funcional"), ("l", "funcional"),
    ("cna", "analitica"), ("ali_apache_id", "analitica"),
    ("cto_bundle", "publicidad"), ("MUID", "publicidad"), ("_uetsid", "publicidad"), ("_uetvid", "publicidad"),
    ("IDE", "publicidad"), ("tuuid", "publicidad"), ("_ttp", "publicidad"), ("A3", "publicidad"),
    ("la", "sin_clasificar"), ("tuuid_lu", "sin_clasificar"),
])
def test_new_known_names(name, purpose):
    assert CookiePurposes(read("cookie_purposes.yaml")).of(name) == purpose


def test_service_type_of_the_organization_maps_to_a_purpose():
    purposes = CookiePurposes(read("cookie_purposes.yaml"))
    assert [purposes.of_service(kind) for kind in ("advertising", "dmp", "analytics", "session_recording", "cdn", "antifraud", "maps", None)] == \
        ["publicidad", "publicidad", "analitica", "analitica", "funcional", "funcional", None, None]


def cookies_capture(cookies):
    cap = site_capture("https://es.aliexpress.com/", [get(1, "https://www.google.com/recaptcha/api.js", params={"render": "x"})])
    cap["cookies"] = [{"name": name, "value": "v", "domain": domain, "expires": -1, "third_party": third} for name, domain, third in cookies]
    return cap


COOKIES = [("uid", ".criteo.com", True), ("_clid", ".clarity.ms", True), ("__cfruid", ".cloudflare.com", True),
           ("zz", ".desconocido.example", True), ("xman_t", ".aliexpress.com", False), ("cna", ".aliexpress.com", False)]


def test_second_step_classifies_by_organization_and_says_so(config, lists):
    result = analyze(cookies_capture(COOKIES), lists, config)
    purposes = result["site"]["summary"]["cookie_purposes"]
    rows = {row["name"]: row for row in purposes["cookies"]}
    assert (rows["uid"]["purpose"], rows["uid"]["basis"]) == ("publicidad", "organizacion")
    assert (rows["_clid"]["purpose"], rows["_clid"]["basis"]) == ("analitica", "organizacion")
    assert (rows["__cfruid"]["purpose"], rows["__cfruid"]["basis"]) == ("funcional", "organizacion")
    assert (rows["cna"]["purpose"], rows["cna"]["basis"]) == ("analitica", "nombre")
    # Sin nombre conocido ni tipo de servicio (dueño desconocido, o el propio sitio): no se inventa.
    assert (rows["zz"]["purpose"], rows["zz"]["basis"]) == ("sin_clasificar", None)
    assert (rows["xman_t"]["purpose"], rows["xman_t"]["basis"]) == ("sin_clasificar", None)
    assert purposes["by_purpose"] == {"publicidad": 1, "analitica": 2, "funcional": 1, "sin_clasificar": 2}
    assert purposes["by_basis"] == {"nombre": 1, "organizacion": 3}
    by_org = [item for item in findings_of(result, "cookie_purpose") + findings_of(result, "cookie_purpose_functional")
              if item["details"]["basis"] == "organizacion"]
    assert {item["details"]["purpose"] for item in by_org} == {"publicidad", "analitica", "funcional"}
    assert all(item["level"] == "INFERENCIA" and "inferencia por la organización" in item["claim"] for item in by_org)
    ads = next(item for item in by_org if item["details"]["purpose"] == "publicidad")
    assert ads["details"]["organizations"] == ["Criteo"] and "Criteo" in ads["claim"]
    # Las funcionales por la organización tampoco suman al índice: 6 cookies, 1 funcional.
    assert {entry["component"]: entry["count"] for entry in result["site"]["breakdown"]}["stored_items"] == 5
