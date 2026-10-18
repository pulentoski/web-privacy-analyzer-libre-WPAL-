"""v1.4.10 (docs/adr/037): linker de Google (_gl) en URLs de navegación y redirección, texto de la cookie que coincide
(o que un script copió, solo con la lectura registrada) y consent.banner_interaction. Sin red."""

import base64

import pytest

from app.analyzer import linker
from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.lists import OrganizationCatalog
from app.config import settings
from tests.v121.test_party_blocking_service_consent import PAGE, Lists, capture, req

# _gl real (AliExpress, scan del 2026-10-15) con un hash y tres campos; los valores decodificados son de un navegador de prueba.
GL = ("1*8k5w2*_gcl_au*MTgxMzY3NjYwNy4xNzkyMDg4NDQ1*_ga*NTg5OTk3NzUyLjE3OTIwODg0NDY.*"
      "_ga_VED1YSGNC7*czE3OTIwODg0NDUkbzEkZzAkdDE3OTIwODg0NDUkajYwJGwwJGgw")
GL_ONLY_UP = "1*abc12*_up*MQ.."            # formato válido, un solo campo (_up = «1»): sin _ga ni _gcl_au
GL_INVALID = "zzzz-no-es-un-linker"
GL_UNDECODABLE = "1*abc12*_ga*%%%%"         # formato reconocido; el valor del campo no es base64
VISITOR = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e"
ENTITIES = {"airbnb.cl": "Airbnb", "airbnb.com": "Airbnb", "reservas.example": "Reservas SpA", "adsone.example": "Ads One",
            "adstwo.example": "Ads Two"}


class BasisLists(Lists):
    """Como el mapa de entidades del test, más el criterio que resolvió cada organización (FilterLists.entity_basis)."""

    def __init__(self, entities=None, basis=None):
        super().__init__(entities or ENTITIES)
        self._basis = basis or {}

    def entity_basis(self, domain):
        return None if self.entity(domain) == "no_disponible" else self._basis.get(domain, "mapa_entidades")


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def run(cap, config, lists=None):
    return analyze(cap, lists or BasisLists(), config)


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


def reasons_of(result, request_id):
    return {r["signal"]: r for r in next(item for item in result["requests"] if item["request_id"] == request_id)["reasons"]}


def linker_items(result):
    return result["site"]["summary"]["linker"]["items"]


def navigation(request_id, url, gl, *, referer=PAGE, third_party=True):
    request = req(request_id, f"{url}?_gl={gl}", params={"_gl": gl}, third_party=third_party, resource_type="document",
                  is_navigation=True, headers=[{"name": "Referer", "value": referer}] if referer else None)
    request["frame_url"] = request["url"]
    return request


def redirect(first_url, second_url, gl, *, first_party_hop=False, extra=None):
    first = req(1, f"{first_url}?_gl={gl}", params={"_gl": gl, **(extra or {})}, resource_type="document", is_navigation=True,
                status=302, third_party=not first_party_hop, headers=[{"name": "Referer", "value": PAGE}])
    second = req(2, f"{second_url}?_gl={gl}", params={"_gl": gl, **(extra or {})}, resource_type="document", is_navigation=True)
    second["redirected_from_seq"] = 1
    return [first, second]


# --- 4b. decodificación: solo lo que el formato permite extraer ---

def test_decodable_linker_reports_only_the_extracted_fields_masked():
    report, values = linker.decode(GL)
    assert report["format"] == linker.FORMAT_V1 and report["present"] is True and report["hash_verified"] is False
    assert [field["name"] for field in report["fields"]] == ["_gcl_au", "_ga", "_ga_VED1YSGNC7"]
    assert report["fields"][1] == {"name": "_ga", "value": "5899…[20 caracteres]", "length": 20}
    assert "589997752.1792088446" in values  # el valor completo solo queda en memoria, para comparar
    assert all("589997752" not in field["value"] for field in report["fields"])


def test_linker_without_ga_does_not_assume_ga():
    report, _ = linker.decode(GL_ONLY_UP)
    assert report["format"] == linker.FORMAT_V1 and report["fields"] == [{"name": "_up", "value": "1", "length": 1}]


def test_invalid_linker_is_only_presence():
    report, values = linker.decode(GL_INVALID)
    assert report == {"present": True, "length": len(GL_INVALID), "format": linker.UNRECOGNIZED, "fields": [],
                      "undecoded_fields": 0, "hash_verified": False}
    assert values == set()


def test_recognized_format_with_undecodable_field_is_not_reported_by_name():
    report, _ = linker.decode(GL_UNDECODABLE)
    assert report["format"] == linker.FORMAT_V1 and report["fields"] == [] and report["undecoded_fields"] == 1


# --- 4a/c/d. navegación hacia otra organización: presencia, campos y conclusión por separado ---

def test_navigation_to_third_party_is_evidence_and_scores_the_request(config):
    result = run(capture([navigation(1, "https://www.reservas.example/checkout", GL)]), config)
    [item] = linker_items(result)
    assert item["source"] == "navigation" and item["request_id"] == 1
    assert item["origin"] == {"url": PAGE.rstrip("/") + "/", "via": "referer", "host": "www.airbnb.cl", "domain": "airbnb.cl"}
    assert item["destination"] == {"url": "https://www.reservas.example/checkout", "host": "www.reservas.example",
                                   "domain": "reservas.example"}
    assert item["classification"] == {"status": "third_party", "label": "Tercero", "organization": "Reservas SpA",
                                      "basis": "mapa_entidades", "basis_label": "mapa de entidades"}
    assert item["counts_in_index"] is True and item["duplicate_of"] is None
    # Presencia, campos y conclusión son cosas distintas.
    assert item["gl"]["present"] is True and [field["name"] for field in item["gl"]["fields"]] == ["_gcl_au", "_ga", "_ga_VED1YSGNC7"]
    [finding] = findings_of(result, "gl_linker")
    assert finding["level"] == "EVIDENCIA" and finding["evidence_refs"] == [1]
    assert "según mapa de entidades" in finding["claim"] and "_ga = 5899…[20 caracteres]" in finding["claim"]
    assert "no muestra que el destino reconociera al visitante ni que se completara una atribución" in finding["claim"]
    assert "reconoció" not in finding["claim"] and "atribuyó" not in finding["claim"]
    reason = reasons_of(result, 1)["linker_transfer"]
    assert reason["level"] == "EVIDENCIA" and reason["weight"] == config.scoring["signals"]["linker_transfer"]["weight"]
    assert reason["data"] == {"organization": "Reservas SpA", "basis": "mapa_entidades"}


def test_invalid_linker_to_third_party_reports_presence_without_content(config):
    result = run(capture([navigation(1, "https://www.reservas.example/checkout", GL_INVALID)]), config)
    [item] = linker_items(result)
    assert item["gl"]["format"] == linker.UNRECOGNIZED and item["gl"]["fields"] == []
    [finding] = findings_of(result, "gl_linker")
    assert "se registra solo su presencia, sin inferir su contenido" in finding["claim"]
    assert "_ga" not in finding["claim"] and "_gcl_au" not in finding["claim"]


def test_unknown_organization_is_reported_without_scoring(config):
    result = run(capture([navigation(1, "https://shop.desconocida.example/p", GL)]), config)
    [item] = linker_items(result)
    assert item["classification"]["status"] == "unknown_org" and item["classification"]["label"] == "Organización no disponible"
    assert item["classification"]["basis"] == "dominio_registrable" and item["counts_in_index"] is False
    assert not findings_of(result, "gl_linker")
    [finding] = findings_of(result, "gl_linker_info")
    assert "Organización no disponible" in finding["claim"] and "No suma al índice" in finding["claim"]
    assert "linker_transfer" not in reasons_of(result, 1)


def test_navigation_to_same_org_by_entity_map_does_not_score(config):
    result = run(capture([navigation(1, "https://www.airbnb.com/rooms", GL)]), config)
    [item] = linker_items(result)
    assert item["classification"]["status"] == "same_org" and item["classification"]["basis"] == "mapa_entidades"
    assert item["counts_in_index"] is False and findings_of(result, "gl_linker_info") and not findings_of(result, "gl_linker")
    assert "linker_transfer" not in reasons_of(result, 1)


# --- redirecciones: cadena registrada; misma organización (alias) y otra organización ---

def test_redirect_between_domains_of_same_org_by_alias(config):
    lists = BasisLists({**ENTITIES, "airbnb-pagos.example": "Airbnb"}, basis={"airbnb-pagos.example": "alias"})
    result = run(capture(redirect("https://go.airbnb.cl/out", "https://www.airbnb-pagos.example/pay", GL, first_party_hop=True)),
                 config, lists)
    [item] = [entry for entry in linker_items(result) if entry["source"] == "redirect"]
    assert item["request_id"] == 2 and item["origin"]["via"] == "referer" and item["origin"]["domain"] == "airbnb.cl"
    assert [hop["url"] for hop in item["redirect_chain"]] == ["https://go.airbnb.cl/out", "https://www.airbnb-pagos.example/pay"]
    assert item["redirect_chain"][0]["status"] == 302
    assert item["classification"]["status"] == "same_org" and item["classification"]["basis"] == "alias"
    assert item["classification"]["basis_label"] == "alias de organización (org_aliases)"
    assert item["counts_in_index"] is False and "linker_transfer" not in reasons_of(result, 2)
    assert any("alias de organización" in finding["claim"] for finding in findings_of(result, "gl_linker_info"))


def test_redirect_to_another_org_is_scored_once(config):
    result = run(capture(redirect("https://go.airbnb.cl/out", "https://www.reservas.example/in", GL, first_party_hop=True)), config)
    by_request = {entry["request_id"]: entry for entry in linker_items(result)}
    assert by_request[1]["classification"]["status"] == "first_party"   # el primer salto es del propio sitio
    assert by_request[1]["classification"]["basis"] == "dominio_registrable" and by_request[1]["counts_in_index"] is False
    assert by_request[2]["source"] == "redirect" and by_request[2]["classification"]["status"] == "third_party"
    assert by_request[2]["counts_in_index"] is True and "Cadena de redirección: 2 saltos." in findings_of(result, "gl_linker")[0]["claim"]
    assert "linker_transfer" in reasons_of(result, 2) and "linker_transfer" not in reasons_of(result, 1)


# --- 4e. no se duplica una transferencia ya informada ---

def test_linker_already_reported_as_redirect_sync_is_not_duplicated(config):
    # El _gl lleva el mismo identificador que los saltos 3xx ya transfieren entre dos organizaciones (redirect_sync).
    gl = "1*abc12*uid*" + base64.b64encode(VISITOR.encode()).decode().replace("=", ".")
    result = run(capture(redirect("https://s.adsone.example/sync", "https://m.adstwo.example/match", gl, extra={"uid": VISITOR})),
                 config)
    assert findings_of(result, "redirect_sync")
    target = next(entry for entry in linker_items(result) if entry["request_id"] == 2)
    assert target["duplicate_of"] == "redirect_sync" and target["counts_in_index"] is False
    assert not findings_of(result, "gl_linker") and "linker_transfer" not in reasons_of(result, 2)


# --- páginas sin request de navegación (pestaña nueva de una captura interactiva, como AliExpress) ---

def test_interactive_page_without_navigation_request_uses_frame_requests_as_evidence(config):
    url = f"https://www.airbnb.cl/ssr/ofertas?source=home&_gl={GL}"
    asset = req(7, "https://www.airbnb.cl/a.css", third_party=False, resource_type="stylesheet")
    asset["frame_url"] = url
    timeline = [{"seq": 0, "tab": 1, "url": PAGE}, {"seq": 1, "tab": 2, "url": url}]
    result = run(capture([asset], timeline=timeline), config)
    [item] = linker_items(result)
    assert item["request_id"] is None and item["tab"] == 2 and item["evidence_refs"] == [7]
    assert item["origin"]["via"] == "pagina_anterior" and item["origin"]["host"] == "www.airbnb.cl"
    assert item["classification"]["label"] == "Propio" and item["counts_in_index"] is False
    [finding] = findings_of(result, "gl_linker_info")
    assert "destino: propio" in finding["claim"].lower() and "según dominio registrable" in finding["claim"]


def test_no_gl_no_linker(config):
    result = run(capture([req(1, "https://www.reservas.example/checkout", resource_type="document", is_navigation=True)]), config)
    assert result["site"]["summary"]["linker"] == {"items": [], "total": 0}


def test_catalog_reports_which_source_resolved_the_organization():
    catalog = OrganizationCatalog({"organizations": {"Google": ["googleapis.com"]}},
                                  {"aliases": {"Municipalidad de La Serena": ["laserena.cl", "munilaserena.cl"]}})
    assert catalog.lookup_basis("munilaserena.cl") == (True, "Municipalidad de La Serena", "alias")
    assert catalog.lookup_basis("maps.googleapis.com") == (True, "Google", "catalogo")
    assert catalog.lookup_basis("otro.example") == (False, None, None)


# --- 2. cookie: «coincide» salvo lectura registrada del mismo script ---

COOKIES = [{"name": "_atrk_siteuid", "value": VISITOR, "domain": "www.airbnb.cl", "expires": None, "third_party": False}]
SCRIPT = "https://cdn.adsone.example/tag.js"


def cookie_request(script=SCRIPT):
    request = req(1, "https://t.adsone.example/p", params={"siteuid": VISITOR})
    request["initiator_script"] = script
    return request


def test_cookie_match_without_recorded_read_is_not_a_copy(config):
    result = run(capture([cookie_request()], cookies=COOKIES), config)
    reason = reasons_of(result, 1)["persistent_id"]
    assert "el valor enviado coincide con la cookie «_atrk_siteuid»" in reason["detail"] and "copió" not in reason["detail"]
    assert reason["data"]["matched_cookie"] == "_atrk_siteuid" and "copied_by_script" not in reason["data"]
    [finding] = findings_of(result, "persistent_id_org")
    assert "coincide con la cookie «_atrk_siteuid»" in finding["claim"] and "copió" not in finding["claim"]


def test_cookie_read_by_the_initiating_script_is_a_copy(config):
    reads = [{"script_url": SCRIPT, "kind": "cookie", "name": "_atrk_siteuid"}]
    result = run(capture([cookie_request()], cookies=COOKIES, storage_reads=reads), config)
    reason = reasons_of(result, 1)["persistent_id"]
    assert "un script copió el valor de la cookie «_atrk_siteuid» en la URL o el cuerpo de la request" in reason["detail"]
    assert reason["data"]["copied_by_script"] == SCRIPT
    [finding] = findings_of(result, "persistent_id_org")
    assert finding["details"]["copied_by_script"] == SCRIPT and "copió" in finding["claim"]


def test_cookie_read_by_another_script_is_only_a_match(config):
    reads = [{"script_url": "https://otro.example/x.js", "kind": "cookie", "name": "_atrk_siteuid"}]
    result = run(capture([cookie_request()], cookies=COOKIES, storage_reads=reads), config)
    reason = reasons_of(result, 1)["persistent_id"]
    assert "copió" not in reason["detail"] and "copied_by_script" not in reason["data"]


def test_storage_item_read_by_the_initiating_script_is_a_copy(config):
    storage = [{"storage_type": "local", "key": "uid", "value": VISITOR, "origin": PAGE}]
    reads = [{"script_url": SCRIPT, "kind": "local", "name": "uid"}]
    result = run(capture([cookie_request()], storage=storage, storage_reads=reads), config)
    reason = reasons_of(result, 1)["persistent_id"]
    assert "un script copió el valor del ítem «uid» de localStorage" in reason["detail"]
    assert "matched_cookie" not in reason["data"]


# --- 3. consentimiento: banner_interaction ---

def test_consent_summary_uses_banner_interaction(config):
    consent = run(capture([]), config)["site"]["summary"]["consent"]
    assert consent["banner_interaction"] is False and "user_interaction" not in consent
    pressed = run(capture([], consent={"interaction_seq": 0, "status": "aceptado"}), config)["site"]["summary"]["consent"]
    assert pressed["banner_interaction"] is True


def test_banner_interaction_is_not_the_interactive_capture_clicks(config):
    # Clics y desplazamientos de una captura interactiva sin escenario de consentimiento: el aviso no se pulsó.
    clicks = [{"ts": 1.0, "kind": "click"}, {"ts": 2.0, "kind": "scroll"}]
    result = run(capture([], interactions=clicks), config)
    assert result["site"]["summary"]["consent"]["banner_interaction"] is False
