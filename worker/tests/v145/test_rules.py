"""v1.4.5 (docs/adr/032): servicios de terceros sin señales de rastreo, envíos de la interacción solo con datos,
catálogo de organizaciones, nombres de persona, frames de error del navegador y varias cuentas de analítica.
Capturas en memoria con la forma de los casos reales (laserena.cl y municoquimbo.cl), sin red."""

import pathlib

import pytest
import yaml

from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.lists import UNKNOWN_ENTITY, OrganizationCatalog
from app.browser.fp_monitor import FingerprintMonitor
from app.config import settings
from tests.v121.test_party_blocking_service_consent import Lists, capture, req

T0 = 1_800_000_000.0
PERSON = "NIKITAS GEORGOPOULOS"


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="module")
def catalog():
    return OrganizationCatalog(yaml.safe_load((pathlib.Path(settings.data_dir) / "organizations.yaml").read_text(encoding="utf-8")))


class CatalogLists(Lists):
    """El mapa del test + el catálogo propio, con la misma regla que FilterLists.entity()."""

    def __init__(self, entities, catalog):
        super().__init__(entities)
        self.catalog = catalog
        self.persons = frozenset(name for name in set(entities.values()) if catalog.is_person(name, [d for d, n in entities.items() if n == name]))

    def entity(self, domain):
        known, name = self.catalog.lookup(domain or "")
        if known:
            return name or UNKNOWN_ENTITY
        name = super().entity(domain)
        return UNKNOWN_ENTITY if name in self.persons else name


ENTITIES = {"gstatic.com": "Google", "google.com": "Google", "jsdelivr.net": "Prospect One", "cloudflare.com": "Cloudflare",
            "openstreetmap.org": "OpenStreetMap Foundation", "openweathermap.org": "OpenWeather", "unpkg.com": "unpkg",
            "google-analytics.com": "Google", "googletagmanager.com": "Google", "e-mailit.com": PERSON,
            "bootstrapcdn.com": "StackPath", "facebook.com": "Facebook"}


def get(request_id, url, *, resource_type="script", params=None, ts=None, method="GET", registrable=None):
    request = req(request_id, url, params=params, resource_type=resource_type)
    request.update(method=method)
    if ts is not None:
        request["ts"] = ts
    if registrable:
        request["registrable_domain"] = registrable
    return request


def services(result):
    return {(item["organization"], item["service_type"]): item for item in result["site"]["summary"]["third_party_services"]["items"]}


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


# --- 1. servicios de terceros sin señales de rastreo ---


def laserena(extra=()):
    return capture([
        get(1, "https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.min.js"),
        get(2, "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css", resource_type="stylesheet"),
        get(3, "https://www.google.com/recaptcha/api.js", params={"render": "explicit"}),
        get(4, "https://www.gstatic.com/recaptcha/releases/abc/recaptcha__es.js"),
        get(5, "https://a.tile.openstreetmap.org/12/1/2.png", resource_type="image"),
        get(6, "https://b.tile.openstreetmap.org/12/1/3.png", resource_type="image"),
        get(7, "https://api.openweathermap.org/data/2.5/weather", resource_type="fetch", params={"q": "La Serena"}),
        get(8, "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"),
        get(9, "https://apis.munilaserena.cl/v1/noticias", resource_type="xhr"),
        *extra,
    ])


def test_third_parties_without_tracking_signals_are_listed_by_organization_and_service(config, catalog):
    result = analyze(laserena(), CatalogLists(ENTITIES, catalog), config)
    summary = result["site"]["summary"]
    assert summary["trackers"] == 0, "el caso es justamente un sitio sin rastreadores"
    listed = services(result)
    assert listed[("Prospect One", "library_cdn")]["requests"] == 1
    assert listed[("Cloudflare", "library_cdn")]["hosts"] == ["cdnjs.cloudflare.com"]
    assert listed[("Google", "antifraud")]["requests"] == 2 and listed[("Google", "antifraud")]["hosts"] == ["www.google.com", "www.gstatic.com"]
    assert listed[("OpenStreetMap Foundation", "maps")]["requests"] == 2
    assert listed[("OpenWeather", "weather")]["service_label"].startswith("clima")
    assert listed[("unpkg", "library_cdn")]["service_label"].startswith("CDN de librerías")
    # Dueño desconocido y giro desconocido: se informa igual, sin inventar ninguno de los dos.
    unknown = listed[(UNKNOWN_ENTITY, None)]
    assert unknown["domains"] == ["munilaserena.cl"] and unknown["service_label"] is None
    block = summary["third_party_services"]
    assert block["level"] == "EVIDENCIA" and block["service_level"] == "INFERENCIA"
    assert block["requests"] == 9 and block["organizations"] == 7 and block["truncated"] is False
    # Cada fila lleva evidencia (ids de request) y ninguna está también en Rastreadores.
    assert all(item["evidence_refs"] and item["in_trackers"] is False for item in block["items"])
    assert block["items"] == sorted(block["items"], key=lambda item: -item["requests"]) or block["items"][0]["requests"] == 2


def test_tracker_requests_stay_out_and_the_shared_organization_is_flagged(config, catalog):
    visitor = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
    extra = [get(20, "https://www.google-analytics.com/g/collect", resource_type="ping", method="POST",
                 params={"tid": "G-ABCD123456", "cid": visitor, "dl": "https://www.airbnb.cl/"})]
    cap = laserena(extra)
    cap["cookies"] = [{"name": "_ga", "value": visitor, "domain": "airbnb.cl"}]
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    assert result["site"]["summary"]["trackers"] == 1
    block = result["site"]["summary"]["third_party_services"]
    assert 20 not in [ref for item in block["items"] for ref in item["evidence_refs"]]
    assert services(result)[("Google", "antifraud")]["in_trackers"] is True
    assert services(result)[("OpenWeather", "weather")]["in_trackers"] is False


def test_two_unknown_owners_are_not_treated_as_the_same_organization(config, catalog):
    visitor = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
    cap = capture([
        get(1, "https://t.rastreador-desconocido.example/p.gif", resource_type="image", params={"uid": visitor, "dl": "https://www.airbnb.cl/"}),
        get(2, "https://static.otro-desconocido.example/lib.css", resource_type="stylesheet"),
        get(3, "https://t.rastreador-desconocido.example/logo.png", resource_type="image"),
    ])
    cap["cookies"] = [{"name": "_uid", "value": visitor, "domain": "airbnb.cl"}]
    result = analyze(cap, CatalogLists({}, catalog), config)
    assert result["site"]["summary"]["trackers"] == 1
    rows = {item["domains"][0]: item for item in result["site"]["summary"]["third_party_services"]["items"]}
    assert rows["otro-desconocido.example"]["in_trackers"] is False
    assert rows["rastreador-desconocido.example"]["in_trackers"] is True and rows["rastreador-desconocido.example"]["requests"] == 1


def test_no_third_parties_gives_an_empty_list_not_a_missing_one(config, catalog):
    result = analyze(capture([req(1, "https://www.airbnb.cl/app.js", third_party=False, resource_type="script")]), CatalogLists({}, catalog), config)
    assert result["site"]["summary"]["third_party_services"] == {
        "level": "EVIDENCIA", "service_level": "INFERENCIA", "organizations": 0, "requests": 0, "items": [], "truncated": False}


# --- 2. «Su interacción se envió a X»: solo envíos con datos ---


def clicks(*offsets):
    return [{"ts": T0 + offset, "kind": "click"} for offset in offsets]


def interactive(requests, interactions):
    cap = capture(requests)
    cap["interactions"] = interactions
    cap["requests"][0]["ts"] = T0 - 30
    return cap


def test_static_downloads_after_a_click_are_not_the_interaction_being_sent(config, catalog):
    """laserena.cl: tras dos clics el visor 3D bajó el decodificador draco (.js y .wasm) de gstatic.com."""
    cap = interactive([
        get(1, "https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_wasm_wrapper.js", resource_type="fetch", ts=T0 + 0.4),
        get(2, "https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_decoder.wasm", resource_type="fetch", ts=T0 + 0.6),
        get(3, "https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_wasm_wrapper.js", resource_type="fetch", ts=T0 + 10.3),
        get(4, "https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_decoder.wasm", resource_type="fetch", ts=T0 + 10.5),
    ], clicks(0, 10, 20))
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    assert findings_of(result, "interaction_sent") == []
    interaction = result["site"]["summary"]["interaction"]
    assert interaction["available"] is True and interaction["total"] == 3 and interaction["organizations"] == []


@pytest.mark.parametrize("url, resource_type, params, method, service, expected", [
    ("https://t.example/collect", "xhr", None, "POST", None, True),
    ("https://t.example/b", "ping", None, "POST", None, True),
    ("https://t.example/b", "beacon", None, "GET", None, True),
    ("https://t.example/pixel.gif", "image", {"e": "click"}, "GET", None, True),
    ("https://t.example/api/track", "fetch", {"e": "click"}, "GET", None, True),
    ("https://t.example/api/config", "fetch", None, "GET", None, False),
    ("https://t.example/pixel.gif", "image", None, "GET", None, False),
    ("https://t.example/lib.js", "script", {"v": "3"}, "GET", None, False),
    ("https://t.example/decoder.wasm", "fetch", None, "GET", None, False),
    ("https://t.example/module.mjs", "fetch", {"v": "1"}, "GET", None, False),
    ("https://t.example/theme.css", "stylesheet", None, "GET", None, False),
    ("https://t.example/font.woff2", "font", None, "GET", None, False),
    # Dominio de distribución de contenido: una descarga no es un envío aunque lleve parámetros…
    ("https://cdn.example/data.json", "fetch", {"v": "1"}, "GET", "cdn", False),
    ("https://cdn.example/data.json", "fetch", {"v": "1"}, "GET", "library_cdn", False),
    # …pero un POST o un beacon a ese mismo dominio sí envía datos.
    ("https://cdn.example/rum", "xhr", None, "POST", "cdn", True),
])
def test_what_counts_as_sending_data(config, url, resource_type, params, method, service, expected):
    assert config.interaction.is_send(get(1, url, resource_type=resource_type, params=params, method=method), service) is expected


def test_navigation_is_never_a_send(config):
    request = get(1, "https://t.example/next", resource_type="document", params={"a": "1"})
    request["is_navigation"] = True
    assert config.interaction.is_send(request) is False


def test_real_sends_after_interactions_are_still_reported(config, catalog):
    cap = interactive([
        get(1, "https://t.tracker.example/e", resource_type="ping", method="POST", ts=T0 + 0.3),
        get(2, "https://t.tracker.example/p.gif", resource_type="image", params={"ev": "click"}, ts=T0 + 10.2),
        get(3, "https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_decoder.wasm", resource_type="fetch", ts=T0 + 10.4),
    ], clicks(0, 10, 20))
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    sent = findings_of(result, "interaction_sent")
    assert len(sent) == 1 and sent[0]["level"] == "EVIDENCIA" and sent[0]["evidence_refs"] == [1, 2]
    assert sent[0]["details"]["domain"] == "tracker.example"


# --- 4. catálogo de organizaciones y servicios ---


@pytest.mark.parametrize("host, organization", [
    ("maps.googleapis.com", "Google"), ("fonts.googleapis.com", "Google"), ("ajax.googleapis.com", "Google"),
    ("storage.googleapis.com", "Google"), ("firebaseinstallations.googleapis.com", "Google"), ("googleapis.com", "Google"),
])
def test_hosts_under_a_public_suffix_get_their_organization(catalog, host, organization):
    assert catalog.lookup(host) == (True, organization)


@pytest.mark.parametrize("host", ["weshareapp.io", "platform.weshareapp.io", "www.e-mailit.com"])
def test_unknown_owner_is_declared_unknown(catalog, host):
    assert catalog.lookup(host) == (True, None)
    assert CatalogLists({"e-mailit.com": PERSON, "weshareapp.io": "Alguien"}, catalog).entity(host) == UNKNOWN_ENTITY


def test_other_domains_are_not_in_the_catalog(catalog):
    assert catalog.lookup("notgoogleapis.com") == (False, None) and catalog.lookup("gstatic.com") == (False, None)


@pytest.mark.parametrize("url, service", [
    ("https://maps.googleapis.com/maps/api/js?key=x", "maps"), ("https://maps.gstatic.com/mapfiles/api-3/images/cb.png", "maps"),
    ("https://fonts.googleapis.com/css?family=Roboto", "fonts"), ("https://fonts.gstatic.com/s/roboto/v30/a.woff2", "fonts"),
    ("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js", "library_cdn"),
    ("https://www.gstatic.com/draco/versioned/decoders/1.5.6/draco_decoder.wasm", "library_cdn"),
    ("https://www.gstatic.com/recaptcha/releases/x/recaptcha__es.js", "antifraud"),
    ("https://www.google.com/recaptcha/api2/anchor?k=x&hl=es-CL", "antifraud"),
    ("https://www.gstatic.com/images/branding/logo.png", "cdn"),
    ("https://storage.googleapis.com/bucket/file.pdf", "cloud_storage"),
    ("https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen", "app_backend"),
    ("https://translate.googleapis.com/translate_a/t", "translation"),
    ("https://youtubei.googleapis.com/youtubei/v1/player", "video"),
    ("https://www.googleapis.com/customsearch/v1", "google_api"),
    ("https://platform.weshareapp.io/widget.js", "share_widget"), ("https://www.e-mailit.com/widget/menu3x/js/button.js", "share_widget"),
    ("https://cdn.jsdelivr.net/npm/x/x.js", "library_cdn"), ("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css", "library_cdn"),
    ("https://a.tile.openstreetmap.org/1/2/3.png", "maps"), ("https://api.openweathermap.org/data/2.5/weather", "weather"),
    ("https://www.youtube.com/embed/abc", "video"),
])
def test_service_type_of_real_hosts(config, catalog, url, service):
    host = url.split("/")[2]
    lists = CatalogLists(ENTITIES, catalog)
    domain = host if host.endswith("googleapis.com") else ".".join(host.split(".")[-2:])
    found = config.service_types.of(entity=lists.entity(domain), domain=domain, host=host, urls=[url])
    assert found is not None and found["type"] == service, found


def test_a_group_of_urls_takes_a_url_pattern_only_if_most_of_them_match(config):
    mixed = ["https://www.google-analytics.com/g/collect", "https://www.googletagmanager.com/gtag/js", "https://maps.googleapis.com/maps/api/js"]
    assert config.service_types.of(entity="Google", domain="google-analytics.com", urls=mixed)["type"] == "analytics"
    assert config.service_types.of(entity="Google", domain="googleapis.com", urls=mixed[2:] * 2 + mixed[:1])["type"] == "maps"
    assert config.service_types.of(entity="Facebook", domain="facebook.com", urls=["https://www.facebook.com/tr?id=1"])["type"] == "conversion_pixel"


def test_municoquimbo_services(config, catalog):
    cap = capture([
        get(1, "https://maps.googleapis.com/maps/api/js", params={"key": "AIza"}, registrable="maps.googleapis.com"),
        get(2, "https://maps.googleapis.com/maps-api-v3/api/js/58/1/common.js", registrable="maps.googleapis.com"),
        get(3, "https://maps.gstatic.com/mapfiles/openhand_8_8.cur", resource_type="other"),
        get(4, "https://fonts.googleapis.com/css", resource_type="stylesheet", params={"family": "Roboto"}, registrable="fonts.googleapis.com"),
        get(5, "https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js", registrable="ajax.googleapis.com"),
        get(6, "https://www.weshareapp.io/widget.js"),
        get(7, "https://www.e-mailit.com/widget/menu3x/js/button.js"),
    ])
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    entities = {item["registrable_domain"]: item["entity"] for item in result["requests"] if item["registrable_domain"]}
    assert entities["maps.googleapis.com"] == entities["fonts.googleapis.com"] == entities["ajax.googleapis.com"] == "Google"
    assert entities["e-mailit.com"] == entities["weshareapp.io"] == UNKNOWN_ENTITY
    listed = services(result)
    assert listed[("Google", "maps")]["requests"] == 3 and listed[("Google", "fonts")]["requests"] == 1
    assert listed[("Google", "library_cdn")]["requests"] == 1
    widgets = [item for item in result["site"]["summary"]["third_party_services"]["items"] if item["service_type"] == "share_widget"]
    assert sorted(item["domains"][0] for item in widgets) == ["e-mailit.com", "weshareapp.io"]
    assert all(item["organization"] == UNKNOWN_ENTITY and item["service_label"] == "widget para compartir en redes sociales" for item in widgets)
    # Los subdominios de googleapis.com son de la misma organización: una sola, no tres «desconocidas».
    assert result["site"]["summary"]["third_party_services"]["organizations"] == 3


# --- 5. nunca nombres de personas ---


@pytest.mark.parametrize("name, domains, legal", [
    (PERSON, ["e-mailit.com"], None), ("Vladimir Fedotov", ["elfsight.com"], None), ("Shashank Kumar", ["pushowl.com"], None),
    ("Troy Hunt", ["troyhunt.com"], None), ("María José Pérez", ["ejemplo.cl"], None), ("riste kocev", ["unlockphonetool.com"], None),
    ("Kirilov Sergey Andreevich", ["x.online"], None), ("Zoni pripta", ["forumsyair.net"], None),
])
def test_names_of_natural_persons_are_detected(catalog, name, domains, legal):
    assert catalog.is_person(name, domains, legal) is True


@pytest.mark.parametrize("name, domains, legal", [
    ("Google", ["google.com"], "Google LLC"), ("Prospect One", ["jsdelivr.net"], "Prospect One"), ("Fonticons", ["fontawesome.com"], "Fonticons Inc"),
    ("Marianne Wartoft", ["seterra.com"], "Marianne Wartoft AB"), ("James Madison University", ["jmu.edu"], None),
    ("Adrian Otto Consulting", ["refdesk.com"], None), ("Signature Hardware", ["signaturehardware.com"], None),
    ("OpenStreetMap Foundation", ["openstreetmap.org"], None), ("unpkg", ["unpkg.com"], None), ("StackPath", ["bootstrapcdn.com"], "StackPath, LLC"),
    ("Yandex Metrica", ["mc.yandex.ru"], None), ("Lucky Orange", ["luckyorange.com"], None), ("Banco de Chile", ["bancochile.cl"], None),
])
def test_organizations_are_not_mistaken_for_persons(catalog, name, domains, legal):
    assert catalog.is_person(name, domains, legal) is False


def test_a_person_is_never_shown_as_owner_anywhere_in_the_analysis(config, catalog):
    cap = capture([get(1, "https://www.e-mailit.com/widget/button.js"),
                   get(2, "https://static.elfsight.com/platform/platform.js"),
                   get(3, "https://static.elfsight.com/p.gif", resource_type="image", params={"uid": "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"})])
    lists = CatalogLists({"e-mailit.com": PERSON, "elfsight.com": "Vladimir Fedotov"}, catalog)
    result = analyze(cap, lists, config)
    dumped = repr(result)
    assert PERSON not in dumped and "Fedotov" not in dumped
    assert {item["entity"] for item in result["requests"] if item["third_party"]} == {UNKNOWN_ENTITY}


@pytest.mark.needs_stack  # usa el mapa de entidades real de ./data (no versionado); se omite en CI.
def test_real_entity_map_never_returns_a_person(analyzer_resources):
    lists, _ = analyzer_resources
    assert lists.entity("e-mailit.com") == UNKNOWN_ENTITY and lists.entity("elfsight.com") == UNKNOWN_ENTITY
    assert lists.entity("maps.googleapis.com") == "Google" and lists.entity("gstatic.com") == "Google"
    assert lists.entity("jsdelivr.net") == "Prospect One" and lists.entity("weshareapp.io") == UNKNOWN_ENTITY
    assert PERSON in lists.persons and "Google" not in lists.persons


# --- 6. frames de error del navegador ---

ERROR_FRAME = "chrome-error://chromewebdata/"


def fp_call(call_id, api, script_url, frame_url, count=1):
    return {"call_id": call_id, "api": api, "script_url": script_url, "frame_url": frame_url, "count": count, "details": {}}


def test_calls_from_the_browser_error_page_are_ignored(config, catalog):
    cap = capture([get(1, "https://cdn.jsdelivr.net/npm/x/x.js")])
    cap["fingerprinting"] = {"available": ["navigator.userAgent"], "truncated": False, "calls": [
        fp_call(1, "navigator.userAgent", "https://www.airbnb.cl/app.js", "https://www.airbnb.cl/"),
        fp_call(2, "navigator.userAgent", ERROR_FRAME, ERROR_FRAME, 4),
        fp_call(3, "canvas.toDataURL", "", ERROR_FRAME),
        fp_call(4, "screen.width", "", ERROR_FRAME, 9),
    ]}
    result = analyze(cap, CatalogLists(ENTITIES, catalog), config)
    scripts = [script["script_url"] for script in result["fingerprinting"]["scripts"]]
    assert scripts == ["https://www.airbnb.cl/app.js"]
    assert "chrome-error" not in repr(result["fingerprinting"]) and "chrome-error" not in repr(result["findings"])
    assert result["site"]["summary"]["error_frames"] == {
        "observed": True, "ignored_messages": 0, "ignored_calls": 3, "ignored_scripts": 1, "requests": 0}


def test_without_error_frames_nothing_is_reported(config, catalog):
    result = analyze(capture([get(1, "https://cdn.jsdelivr.net/npm/x/x.js")]), CatalogLists(ENTITIES, catalog), config)
    assert result["site"]["summary"]["error_frames"] == {
        "observed": False, "ignored_messages": 0, "ignored_calls": 0, "ignored_scripts": 0, "requests": 0}


def test_the_monitor_drops_batches_from_the_error_page():
    class Frame:
        def __init__(self, url):
            self.url = url

    monitor = FingerprintMonitor(context=None)
    batch = '{"t": "%s", "c": [["navigator.userAgent", "", 2]]}' % monitor._token
    monitor._on_message({"frame": Frame(ERROR_FRAME)}, batch)
    monitor._on_message({"frame": Frame("https://sitio.example/")}, batch)
    result = monitor.result()
    assert result["error_frame_messages"] == 1
    assert [(call["frame_url"], call["count"]) for call in result["calls"]] == [("https://sitio.example/", 2)]


def test_a_new_capture_reports_the_dropped_batches(config, catalog):
    cap = capture([get(1, "https://cdn.jsdelivr.net/npm/x/x.js")])
    cap["fingerprinting"] = {"available": [], "truncated": False, "calls": [], "error_frame_messages": 2}
    frames = analyze(cap, CatalogLists(ENTITIES, catalog), config)["site"]["summary"]["error_frames"]
    assert frames["observed"] is True and frames["ignored_messages"] == 2 and frames["ignored_calls"] == 0


# --- 7. varias cuentas de analítica ---


def collect(request_id, tid, host="www.google-analytics.com", path="/g/collect"):
    return get(request_id, f"https://{host}{path}", resource_type="ping", method="POST", params={"tid": tid, "v": "2"})


def test_several_measurement_ids_of_one_vendor_is_a_finding_with_evidence(config, catalog):
    """municoquimbo.cl: 5 IDs G- y 2 UA-."""
    ids = ["G-67RVFLXN63", "G-DFGLMFS8R0", "G-HJBTJZGSR1", "G-KNH486X8LD", "G-W9JDD84Q8B"]
    requests = [collect(index + 1, tid) for index, tid in enumerate(ids)]
    requests.append(get(10, "https://www.googletagmanager.com/gtag/js", params={"id": "UA-136265005-1"}))
    requests.append(collect(11, "UA-6640442-5", path="/collect"))
    result = analyze(capture(requests), CatalogLists(ENTITIES, catalog), config)
    (accounts,) = findings_of(result, "analytics_accounts")
    assert accounts["level"] == "EVIDENCIA" and accounts["evidence_refs"] == [1, 2, 3, 4, 5, 10, 11]
    assert accounts["claim"].startswith("Los datos de la visita se enviaron a 7 cuentas de Google Analytics")
    assert accounts["details"] == {"vendor": "Google Analytics", "accounts": sorted(ids) + ["UA-136265005-1", "UA-6640442-5"], "count": 7}
    (note,) = findings_of(result, "discontinued_tag")
    assert note["level"] == "EVIDENCIA" and note["evidence_refs"] == [10, 11] and note["details"]["informative"] is True
    assert "Etiqueta de un servicio descontinuado" in note["claim"] and "Universal Analytics" in note["claim"]
    assert note["details"]["accounts"] == ["UA-136265005-1", "UA-6640442-5"]
    assert result["site"]["summary"]["analytics_accounts"] == [{
        "vendor": "Google Analytics", "accounts": sorted(ids) + ["UA-136265005-1", "UA-6640442-5"],
        "discontinued": ["UA-136265005-1", "UA-6640442-5"], "discontinued_label": "Universal Analytics"}]


def test_one_account_is_not_a_finding_and_other_ids_do_not_count(config, catalog):
    requests = [collect(1, "G-ABCD123456"), collect(2, "G-ABCD123456"),
                get(3, "https://www.googletagmanager.com/gtm.js", params={"id": "GTM-ABCD123"}),
                get(4, "https://www.googletagmanager.com/gtm.js", params={"id": "GTM-WXYZ987"})]
    result = analyze(capture(requests), CatalogLists(ENTITIES, catalog), config)
    assert findings_of(result, "analytics_accounts") == [] and findings_of(result, "discontinued_tag") == []
    assert result["site"]["summary"]["analytics_accounts"] == [
        {"vendor": "Google Analytics", "accounts": ["G-ABCD123456"], "discontinued": [], "discontinued_label": ""}]


def test_a_single_discontinued_id_is_only_the_informative_note(config, catalog):
    result = analyze(capture([collect(1, "UA-1234567-1", path="/collect")]), CatalogLists(ENTITIES, catalog), config)
    assert findings_of(result, "analytics_accounts") == []
    (note,) = findings_of(result, "discontinued_tag")
    assert "se observó el ID UA-1234567-1 de Universal Analytics" in note["claim"]


def test_accounts_of_different_vendors_are_not_added_together(config, catalog):
    requests = [collect(1, "G-ABCD123456"), get(2, "https://www.facebook.com/tr", resource_type="image", params={"id": "123456789012345", "ev": "PageView"})]
    result = analyze(capture(requests), CatalogLists(ENTITIES, catalog), config)
    assert findings_of(result, "analytics_accounts") == []
    assert [item["vendor"] for item in result["site"]["summary"]["analytics_accounts"]] == ["Google Analytics", "Meta"]
