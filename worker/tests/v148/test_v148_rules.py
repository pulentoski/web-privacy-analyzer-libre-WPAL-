"""v1.4.8 (docs/adr/035), puntos 2–8: bandas, servicios de terceros, fuga de búsqueda, servidor CAPI de Meta,
fuga de URL completa, catálogo y cookies de Alibaba, y WebRTC. Pruebas sin red (salvo el navegador local del
último test, que no sale del worker: la página la sirve una ruta de Playwright)."""

import pathlib

import pytest
import yaml
from playwright.async_api import async_playwright

from app.analyzer.config import load_config
from app.analyzer.engine import _contains_page_url, analyze
from app.analyzer.fingerprinting import analyze_fingerprinting
from app.analyzer.lists import OrganizationCatalog
from app.browser.fp_monitor import FingerprintMonitor
from app.browser.launcher import launch_browser, new_context
from app.config import settings
from tests.helpers import run_async
from tests.v121.test_party_blocking_service_consent import capture, req
from tests.v145.test_rules import ENTITIES, CatalogLists, findings_of

DATA = pathlib.Path(settings.data_dir)
VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"


def read(name):
    return yaml.safe_load((DATA / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="module")
def lists():
    return CatalogLists({**ENTITIES, "facebook.net": "Facebook", "aliexpress.com": "Alibaba"},
                        OrganizationCatalog(read("organizations.yaml"), read("org_aliases.yaml")))


def items(result):
    return result["site"]["summary"]["third_party_services"]


# --- 2. Bandas: solo las de scoring.yaml; «Posible» ya no es una banda ---

def test_bands_come_only_from_scoring_yaml(config):
    names = [band["name"] for band in read("scoring.yaml")["bands"]]
    assert [band["name"] for band in config.bands] == names
    assert "Posible" not in names and names[1] == "Bajo-moderado"
    # ome.tv tenía índice 37: Bajo-moderado. Límites inclusivos.
    assert [config.band(score) for score in (20, 21, 37, 40, 41)] == ["Bajo", "Bajo-moderado", "Bajo-moderado", "Bajo-moderado", "Moderado"]


# --- 3. Servicios de terceros sin señales de rastreo: sin publicidad ni analítica ---

def test_ad_and_analytics_organizations_are_not_listed_as_services(config, lists):
    cap = capture([
        req(1, "https://www.google-analytics.com/a.gif"),          # analítica, por debajo de la banda de rastreador
        req(2, "https://analytics.lfr.cloud/x.png"),                # Liferay: plataforma CMS/analítica
        req(3, "https://maps.googleapis.com/maps/api/js", resource_type="script"),  # mapas: sí es un servicio
    ])
    result = analyze(cap, lists, config)
    services = items(result)
    listed = {(item["organization"], item["service_type"]) for item in services["items"]}
    assert ("Google", "maps") in listed
    assert not any(item["service_type"] in ("analytics", "cms_analytics") for item in services["items"])
    assert services["excluded_requests"] == {"analitica": 2}


# --- 4. Fuga de búsqueda: no si el valor es el título o la meta description/keywords ---

@pytest.mark.parametrize("term, leaks", [
    ("Zapatillas de running", False),        # = título
    ("tienda oficial de calzado", False),    # = meta description
    ("trail", False),                        # = una de las meta keywords
    ("zapatillas trail mujer", True),        # un término que la página no tiene
])
def test_search_leak_ignores_the_page_own_text(config, lists, term, leaks):
    cap = capture([req(1, "https://search.tracker.example/c.gif", params={"q": term})], title="Zapatillas de running",
                  page_meta={"description": "Tienda oficial de calzado", "keywords": "running, trail, calzado"})
    result = analyze(cap, lists, config)
    assert bool(findings_of(result, "search_leak")) is leaks
    assert result["site"]["summary"]["search_leaks_page_text"] == (0 if leaks else 1)


# --- 5. Servidor CAPI de Meta: no es otra organización ---

def test_inferred_capi_server_counts_as_meta(config, lists):
    capi = "https://abc123.lambda-url.us-east-1.on.aws/events"
    cap = capture([
        req(1, "https://www.facebook.com/tr/", params={"id": "1234", "fbp": VISITOR}),
        req(2, capi, params={"fbp": VISITOR, "event_name": "PageView"}),
    ])
    cap["requests"][2]["registrable_domain"] = "abc123.lambda-url.us-east-1.on.aws"
    result = analyze(cap, lists, config)
    assert findings_of(result, "server_side_meta")
    # El mismo identificador a Facebook y a su servidor CAPI no es sincronización entre organizaciones.
    assert not findings_of(result, "id_sync")
    breakdown = {item["component"]: item for item in result["site"]["breakdown"]}
    assert breakdown["id_sync"]["count"] == 0
    assert breakdown["third_party_domains"]["count"] == 1
    entity = next(item["entity"] for item in result["requests"] if item["request_id"] == 2)
    assert entity == "Meta (vía servidor CAPI, inferencia)"
    # Meta es publicidad: el servidor CAPI no es un «servicio de terceros sin señales de rastreo».
    assert not [item for item in items(result)["items"] if "on.aws" in " ".join(item["domains"])]


# --- 6. Fuga de URL: la URL completa, no un trozo ---

def test_url_leak_needs_the_whole_page_url():
    needles = ["https://www.airbnb.cl"]  # página https://www.airbnb.cl/ (sin query ni fragmento)
    assert _contains_page_url("1792082463_EANzZkNDEyNmM5NT_https://www.airbnb.cl/", needles)
    assert _contains_page_url("https://www.airbnb.cl?utm=1", needles)
    assert not _contains_page_url("https://www.airbnb.cl/rooms/9", needles)       # otra ruta del mismo origen
    assert not _contains_page_url("https://www.airbnb.cl.evil.example/", needles)  # otro host que empieza igual
    deep = ["https://www.airbnb.cl/rooms/9"]
    assert _contains_page_url("x=https://www.airbnb.cl/rooms/9/&y", deep)
    assert not _contains_page_url("https://www.airbnb.cl/rooms/99", deep)


def test_pinterest_event_id_with_a_partial_url_is_not_a_leak(config, lists):
    cap = capture([req(1, "https://ct.pinterest.com/v3/", params={"event_id": "1792082463_EANz_https://www.airbnb.cl/s/homes"})])
    assert not findings_of(analyze(cap, lists, config), "url_leak")
    cap = capture([req(1, "https://ct.pinterest.com/v3/", params={"event_id": "1792082463_EANz_https://www.airbnb.cl/"})])
    assert findings_of(analyze(cap, lists, config), "url_leak")


# --- 7. Catálogo, alias y cookies l / cna ---

def test_catalog_liferay_podscribe_and_inacap_alias(config, lists):
    assert lists.entity("lfr.cloud") == lists.entity("liferay.com") == "Liferay"
    assert lists.entity("pdscrb.com") == "Podscribe"
    assert lists.entity("inacapmovil.cl") == lists.entity("inacap.cl") == "INACAP"
    assert config.service_types.of(entity="Liferay", domain="lfr.cloud")["type"] == "cms_analytics"
    assert config.service_types.of(entity="Podscribe", domain="pdscrb.com")["type"] == "ad_attribution"
    assert config.cookie_purposes.of_service("ad_attribution") == "publicidad"


@pytest.mark.parametrize("name, domain, purpose", [
    ("l", "aliexpress.com", "funcional"), ("cna", "mmstat.com", "analitica"), ("cna", "s.alicdn.com", "analitica"),
    ("l", "otro-sitio.cl", "sin_clasificar"), ("cna", "ejemplo.com", "sin_clasificar"),
    ("isg", "otro-sitio.cl", "funcional"),  # los demás nombres no cambian
])
def test_short_alibaba_cookie_names_only_count_on_alibaba_domains(config, name, domain, purpose):
    assert config.cookie_purposes.of(name, domain) == purpose


# --- 8. WebRTC: conexiones y candidatos ICE (grupo 2, Evidencia) ---

def webrtc_calls(**counts):
    return {"available": [], "truncated": False, "calls": [
        {"call_id": index, "api": api, "script_url": "https://chat.example/rtc.js", "frame_url": "https://chat.example/",
         "count": count, "details": {}} for index, (api, count) in enumerate(counts.items(), start=1)]}


def test_webrtc_connection_and_exposed_candidates_are_evidence(config):
    fp = analyze_fingerprinting(webrtc_calls(**{"webrtc.RTCPeerConnection": 2, "webrtc.createOffer": 1, "webrtc.onicecandidate": 1,
                                                "webrtc.icecandidate.local_ip": 1, "webrtc.icecandidate.public_ip": 2}),
                                [], {}, config.scoring["fingerprinting"])
    by_type = {finding["heuristic"]: finding for finding in fp["findings"]}
    assert by_type["webrtc_connection"]["level"] == "EVIDENCIA" and by_type["webrtc_connection"]["call_refs"] == [1]
    exposed = by_type["webrtc_ice_exposed"]
    assert exposed["level"] == "EVIDENCIA" and sorted(exposed["details"]["scopes"]) == ["local_ip", "public_ip"]
    assert "IP local y IP pública" in exposed["claim"] and "no se registra" in exposed["claim"]
    assert by_type["webrtc_ip_discovery"]["details"]["blocked_by_policy"] is False


def test_mdns_only_candidates_do_not_expose_an_ip(config):
    fp = analyze_fingerprinting(webrtc_calls(**{"webrtc.RTCPeerConnection": 1, "webrtc.icecandidate.mdns": 3}), [], {}, config.scoring["fingerprinting"])
    heuristics = {finding["heuristic"] for finding in fp["findings"]}
    assert "webrtc_connection" in heuristics and "webrtc_ice_exposed" not in heuristics


def test_webrtc_findings_are_in_group_2():
    findings = read("explanations.yaml")["findings"]
    assert findings["webrtc_connection"]["step"] == findings["webrtc_ice_exposed"]["step"] == "equipo"
    assert read("explanations.yaml")["steps"][1]["id"] == "equipo"


PAGE = """<!doctype html><title>rtc</title><script>
const pc = new RTCPeerConnection();
const event = (line) => new RTCPeerConnectionIceEvent('icecandidate', {candidate: new RTCIceCandidate({candidate: line, sdpMid: '0'})});
pc.addEventListener('icecandidate', (e) => { window.__seen = (window.__seen || 0) + (e.candidate ? 1 : 0); });
pc.dispatchEvent(event('candidate:1 1 udp 2122260223 192.168.1.20 54321 typ host'));
pc.dispatchEvent(event('candidate:2 1 udp 1686052607 200.1.2.3 54322 typ srflx raddr 0.0.0.0 rport 0'));
pc.dispatchEvent(event('candidate:3 1 udp 2122260223 4a2b3c4d-1111-2222-3333-444455556666.local 54323 typ host'));
</script>"""


@pytest.mark.needs_stack  # lanza el Chromium del worker; se omite en CI (WPA_UNIT_ONLY=1).
def test_instrumentation_classifies_ice_candidates_without_storing_the_address():
    async def collect():
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright)
            try:
                context = await new_context(browser)
                monitor = FingerprintMonitor(context)
                await monitor.install()
                page = await context.new_page()
                # La página la sirve Playwright: no hay request hacia fuera.
                await page.route("https://rtc.example/**", lambda route: route.fulfill(body=PAGE, content_type="text/html"))
                await page.goto("https://rtc.example/")
                seen = await page.evaluate("window.__seen")
                await page.wait_for_timeout(800)
                return seen, monitor.result()
            finally:
                await browser.close()

    seen, result = run_async(collect())
    assert seen == 3  # la página recibe los candidatos igual que sin instrumentación
    counts = {row["api"]: row["count"] for row in result["calls"] if row["api"].startswith("webrtc.")}
    assert counts["webrtc.RTCPeerConnection"] == 1
    assert counts["webrtc.icecandidate.local_ip"] == counts["webrtc.icecandidate.public_ip"] == counts["webrtc.icecandidate.mdns"] == 1
    text = repr(result)
    assert "192.168.1.20" not in text and "200.1.2.3" not in text
