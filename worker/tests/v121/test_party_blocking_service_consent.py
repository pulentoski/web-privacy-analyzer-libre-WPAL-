"""v1.2.1: terceros por organización, fuga al mismo dueño, alerta antibot, giro del servicio y
conclusión de consentimiento. Pruebas unitarias del analizador con capturas en memoria (sin red).
"""

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.config import settings

PAGE = "https://www.airbnb.cl/"
VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"


class Lists:
    """Mapa dominio → organización controlado por el test (como el mapa de entidades real)."""

    version, sources, license_profile = "test", [], "no_comercial"

    def __init__(self, entities=None):
        self._entities = entities or {}

    def entity(self, domain):
        return self._entities.get(domain, "no_disponible")

    def match(self, request, source_host):
        return []


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def req(request_id, url, *, params=None, third_party=True, resource_type="image", headers=None,
        response_headers=None, is_navigation=False, status=200):
    host = url.split("/")[2]
    return {
        "request_id": request_id, "seq": request_id, "method": "GET", "url": url, "host": host,
        "resource_type": resource_type, "is_navigation": is_navigation,
        "query_params": [[name, value] for name, value in (params or {}).items()],
        "request_headers": headers or [], "response_headers": response_headers or [], "post_data": None,
        "sizes": None, "mime_type": "image/gif", "third_party": third_party,
        "registrable_domain": ".".join(host.split(".")[-2:]), "response_status": status,
    }


def capture(requests, *, title="Airbnb", http_status=200, **extra):
    page = req(0, PAGE, third_party=False, resource_type="document", is_navigation=True)
    base = {"start_url": PAGE, "page_url": PAGE, "requests": [page, *requests], "cookies": [], "storage": [],
            "websockets": [], "fingerprinting": None, "tcf": None, "consent": None,
            "title": title, "http_status": http_status, "visit_ts": None}
    base.update(extra)
    return base


# El sitio airbnb.cl pertenece a Airbnb; muscache.com es su CDN (misma organización).
ENTITIES = {"airbnb.cl": "Airbnb", "muscache.com": "Airbnb", "doubleclick.net": "Google",
            "clarity.ms": "Microsoft Clarity", "adtrafficquality.google": "no_disponible"}


# --- Point 1: terceros por organización ---

def test_same_org_cdn_is_not_a_third_party(config):
    cap = capture([
        req(1, "https://www.muscache.com/img/logo.png", resource_type="image"),
        req(2, "https://static.doubleclick.net/pixel.gif", params={"id": VISITOR}),
    ])
    result = analyze(cap, Lists(ENTITIES), config)
    parties = {item["registrable_domain"]: item["party"] for item in result["requests"] if item["registrable_domain"]}
    assert parties["muscache.com"] == "same_org"
    assert parties["doubleclick.net"] == "third_party"
    summary = result["site"]["summary"]
    # Solo cuenta como tercero la otra organización (Google); muscache queda aparte.
    assert "doubleclick.net" in summary["parties"]["third_party_domains"]
    assert "muscache.com" in summary["parties"]["same_org_domains"]
    assert summary["third_party_domains"] == 1
    assert summary["same_org_domains"] == 1


def test_value_shared_only_within_same_org_is_not_id_sync(config):
    # El mismo identificador a airbnb.cl (propio) y a muscache.com (misma org) no es sincronización.
    cap = capture([req(1, "https://www.muscache.com/t", params={"uid": VISITOR}),
                   req(2, "https://www.airbnb.cl/t", params={"uid": VISITOR}, third_party=False)])
    result = analyze(cap, Lists(ENTITIES), config)
    assert result["site"]["summary"]["parties"]["same_org_domains"] == ["muscache.com"]
    assert not any(f["type"] == "id_sync" for f in result["findings"])


# --- Point 2: fuga hacia el mismo dueño ---

def test_url_leak_to_same_org_is_informational_not_a_finding(config):
    # v1.4.8: la URL de la página entera (con query); «{PAGE}listing/123» sería otra página, no una fuga de esta.
    leaked = f"{PAGE}?source=listing"
    cap = capture([
        req(1, "https://www.muscache.com/collect", params={"dl": leaked}),
        req(2, "https://ads.doubleclick.net/collect", params={"dl": leaked}),
    ])
    result = analyze(cap, Lists(ENTITIES), config)
    leak_domains = {f["details"].get("domain") for f in result["findings"] if f["type"] == "url_leak"}
    assert "doubleclick.net" in leak_domains
    assert "muscache.com" not in leak_domains  # misma organización: no es fuga
    assert result["site"]["summary"]["same_org"]["url_recipients"] == ["muscache.com"]


def test_referer_full_url_to_same_org_is_informational(config):
    referer = [{"name": "Referer", "value": f"{PAGE}rooms/9?x=1"}]
    cap = capture([
        req(1, "https://www.muscache.com/a.js", resource_type="script", headers=referer),
        req(2, "https://cdn.doubleclick.net/a.js", resource_type="script", headers=referer),
    ])
    result = analyze(cap, Lists(ENTITIES), config)
    referer_findings = {f["details"].get("domain") for f in result["findings"] if f["type"] == "referer_leak"}
    assert "doubleclick.net" in referer_findings
    assert "muscache.com" not in referer_findings
    assert result["site"]["summary"]["same_org"]["referer_full_url_recipients"] == ["muscache.com"]


# --- Point 3: alerta de visita posiblemente bloqueada ---

def test_few_requests_alone_is_a_possible_note_not_a_block(config):
    # v1.4.8 (docs/adr/035): pocas requests no es una señal dura; queda la nota POSIBLE y el scan sigue en el ranking.
    cap = capture([req(1, "https://www.muscache.com/a.png")])  # 2 requests en total (< 20)
    blocking = analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["blocking"]
    assert blocking["blocked"] is False and blocking["signals"] == []
    variant = blocking["possible_variant"]
    assert variant["level"] == "POSIBLE" and [s["signal"] for s in variant["signals"]] == ["few_requests"]
    assert variant["text"] == ("La página podría haber mostrado una versión distinta al navegador automatizado; "
                               "compare con un HAR propio.")


def test_blocking_by_challenge_title_and_status(config):
    cap = capture([req(i, f"https://www.airbnb.cl/a{i}.png", third_party=False) for i in range(1, 25)],
                  title="Just a moment...", http_status=403)
    cap["requests"][0]["response_status"] = 403  # la navegación respondió 403
    blocking = analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["blocking"]
    assert blocking["blocked"] is True
    signals = {s["signal"] for s in blocking["signals"]}
    assert "challenge_text" in signals and "http_status" in signals


def test_not_blocked_when_many_requests_and_clean(config):
    cap = capture([req(i, f"https://www.airbnb.cl/a{i}.png", third_party=False) for i in range(1, 25)],
                  title="Airbnb: alojamientos", http_status=200)
    assert analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["blocking"]["blocked"] is False


# --- Point 5: giro del servicio ---

def test_service_type_shown_for_known_org(config):
    # El mismo identificador a dos organizaciones (id_sync) hace de Clarity un rastreador: así aparece
    # en "Rastreadores" con su giro.
    cap = capture([
        req(1, "https://www.clarity.ms/collect", params={"uid": VISITOR}),
        req(2, "https://ads.doubleclick.net/collect", params={"uid": VISITOR}),
    ])
    result = analyze(cap, Lists(ENTITIES), config)
    service = result["site"]["summary"]["service_types"].get("Microsoft Clarity")
    assert service and "grabación de sesión" in service["label"]


# --- Point 6: conclusión de consentimiento ---

def test_consent_conclusion_granted_without_interaction(config):
    # gcs=G111: ad_storage y analytics_storage = granted, sin interacción con banner.
    cap = capture([req(1, "https://www.google.com/collect", params={"gcs": "G111"})])
    conclusions = analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["consent"]["conclusions"]
    text = " ".join(c["text"] for c in conclusions)
    assert "G111" in text and "sin que el visitante interactuara" in text
    assert all(c["level"] == "EVIDENCIA" for c in conclusions)


def test_consent_conclusion_undefined_state(config):
    cap = capture([req(1, "https://www.google.com/collect", params={"gcs": "G1--"})])
    conclusions = analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["consent"]["conclusions"]
    assert any("sin declarar estado de consentimiento" in c["text"] for c in conclusions)


def test_consent_conclusion_tcf_present_not_shown(config):
    tcf = {"present": True, "ping": {"cmp_id": 10, "gdpr_applies": False, "display_status": "disabled"}, "tc_data": {}}
    cap = capture([req(1, "https://www.airbnb.cl/a.png", third_party=False)], tcf=tcf)
    conclusions = analyze(cap, Lists(ENTITIES), config)["site"]["summary"]["consent"]["conclusions"]
    assert any("no la muestra en esta visita" in c["text"] for c in conclusions)
