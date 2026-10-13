"""v1.4.2 (docs/adr/030): reglas en YAML — datos de interacción en payloads, correlación con la interacción del
usuario, librerías benignas de canvas, rastreo del lado del servidor, catálogo de tipos de servicio y agrupación.
Capturas en memoria, sin red."""

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import analyze
from app.analyzer.fingerprinting import analyze_fingerprinting
from app.analyzer.interaction import leaf
from app.config import settings
from tests.v121.test_party_blocking_service_consent import ENTITIES, PAGE, Lists, capture, req

T0 = 1_800_000_000.0
ORGS = {**ENTITIES, "tracker.example": "Tracker Corp", "beacon.example": "Beacon Corp", "facebook.com": "Facebook", "facebook.net": "Facebook"}


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def sent(request_id, url, ts, *, params=None, resource_type="xhr", method="POST", third_party=True, is_navigation=False):
    request = req(request_id, url, params=params, resource_type=resource_type, third_party=third_party, is_navigation=is_navigation)
    request.update(method=method, ts=ts)
    return request


def findings_of(result, kind):
    return [item for item in result["findings"] if item["type"] == kind]


# --- datos de interacción en payloads (inferencia por nombre) ---


@pytest.mark.parametrize("name, value, category", [
    ("epn.percent_scrolled", "90", "scroll"), ("prev_scp.post-scroll", "1", "scroll"), ("_et", "1089", "dwell"),
    ("gokey.exposure", "{a=b}", "exposure"), ("clientX", "311", "coordinates"), ("data[0].click_target", "button#buy", "element"),
    ("en", "scroll", "event"), ("ev", "click", "event"), ("event_name", "user_engagement", "event"),
])
def test_interaction_parameter_names_seen_in_real_captures(config, name, value, category):
    assert config.interaction.category_of(name, value)[0] == category


@pytest.mark.parametrize("name, value", [
    ("imp[0].video.maxduration", "60"), ("performance[0].duration", "37.5"), ("x", "6acd"), ("y", "2"), ("transactionid", "u32"),
    ("ep.action", "play"), ("event_name", "PageView"), ("en", "bbtv.streaming"), ("ev", "01_262"), ("", "x"), ("pinterest", "1"),
])
def test_generic_names_are_not_interaction_data(config, name, value):
    assert config.interaction.category_of(name, value) is None


def test_leaf_of_nested_names():
    assert leaf("ep.Percent_Scrolled") == "percent_scrolled" and leaf("a[0].b[1]") == "1" and leaf("") == ""


def test_interaction_payload_finding_is_an_inference_grouped_by_domain_and_kind(config):
    result = analyze(capture([
        sent(1, "https://t.tracker.example/c", T0, params={"clientX": "10", "clientY": "20", "uid": "abc"}),
        sent(2, "https://t.tracker.example/c", T0 + 1, params={"clientX": "30"}),
        sent(3, "https://t.tracker.example/s", T0 + 2, params={"scroll_depth": "75"}),
        sent(4, "https://www.muscache.com/e", T0 + 3, params={"dwell_ms": "900"}),
    ]), Lists(ORGS), config)
    found = {(f["details"]["domain"], f["details"]["category"]): f for f in findings_of(result, "interaction_payload")}
    assert set(found) == {("tracker.example", "coordinates"), ("tracker.example", "scroll"), ("muscache.com", "dwell")}
    coordinates = found[("tracker.example", "coordinates")]
    assert coordinates["level"] == "INFERENCIA" and coordinates["evidence_refs"] == [1, 2] and coordinates["details"]["parameters"] == ["clientx", "clienty"]
    assert "El nombre no prueba" in coordinates["claim"] and found[("muscache.com", "dwell")]["details"]["party"] == "same_org"
    payloads = result["site"]["summary"]["interaction"]["payloads"]
    assert {(item["domain"], item["category"], item["requests"]) for item in payloads} == {("tracker.example", "coordinates", 2), ("tracker.example", "scroll", 1), ("muscache.com", "dwell", 1)}


# --- correlación con la interacción del usuario (solo capturas interactivas) ---


def interactive_capture(requests, interactions):
    return capture(requests, source="interactive", interactions=interactions)


def test_sends_right_after_the_users_interaction_are_evidence_with_a_timeline(config):
    clicks = [{"ts": T0 + 10 * i, "kind": "click"} for i in range(1, 5)] + [{"ts": T0 + 55, "kind": "scroll"}, {"ts": T0 + 70, "kind": "key"}]
    requests = [sent(100 + i, "https://t.tracker.example/e", T0 + 10 * i + 0.4, params={"ev": "click"}) for i in range(1, 5)]
    requests += [sent(200, "https://t.tracker.example/e", T0 + 55.9, params={"en": "scroll"}),
                 # Fuera de la ventana de 2 s y hacia el propio sitio: no cuentan.
                 sent(300, "https://t.tracker.example/late", T0 + 73.5), sent(301, PAGE + "api", T0 + 10.2, third_party=False)]
    result = analyze(interactive_capture(requests, clicks), Lists(ORGS), config)
    [finding] = findings_of(result, "interaction_sent")
    assert finding["level"] == "EVIDENCIA" and finding["evidence_refs"] == [101, 102, 103, 104, 200]
    assert finding["details"] == {"domain": "tracker.example", "organization": "Tracker Corp", "interactions": 5, "requests": 5,
                                  "expected": finding["details"]["expected"], "kinds": {"click": 4, "scroll": 1}, "party": "third_party"}
    assert finding["details"]["expected"] < 1 and "secuencia temporal" in finding["claim"] and "no se registró qué se tecleó" in finding["claim"]
    interaction = result["site"]["summary"]["interaction"]
    assert interaction["available"] is True and interaction["interactions"] == {"click": 4, "scroll": 1, "key": 1} and interaction["window_s"] == 2
    assert [(entry["kind"], [(s["organization"], s["requests"]) for s in entry["sends"]]) for entry in interaction["timeline"]] == [
        ("click", [("Tracker Corp", 1)])] * 4 + [("scroll", [("Tracker Corp", 1)]), ("key", [])]
    # La línea de tiempo guarda hora y tipo: nada de lo tecleado ni posiciones.
    assert all(set(entry) == {"ts", "kind", "navigation", "sends"} for entry in interaction["timeline"])


def test_periodic_beacons_and_page_loads_are_not_attributed_to_the_interaction(config):
    interactions = [{"ts": T0 + 20, "kind": "click"}, {"ts": T0 + 40, "kind": "click"}, {"ts": T0 + 60, "kind": "click"}]
    # Baliza cada segundo durante toda la sesión: cae en todas las ventanas, pero es su ritmo normal.
    beacons = [sent(1000 + i, "https://b.beacon.example/hb", T0 + i) for i in range(1, 90)]
    # Clic que abre otra página: el tráfico de esa página no es un envío del clic.
    navigation = [sent(5, PAGE + "otra", T0 + 60.3, third_party=False, resource_type="document", method="GET", is_navigation=True),
                  sent(6, "https://t.tracker.example/pv", T0 + 60.8), sent(7, "https://t.tracker.example/pv2", T0 + 61.0)]
    result = analyze(interactive_capture(beacons + navigation, interactions), Lists(ORGS), config)
    assert findings_of(result, "interaction_sent") == []
    interaction = result["site"]["summary"]["interaction"]
    beacon = next(item for item in interaction["organizations"] if item["organization"] == "Beacon Corp")
    assert beacon["flagged"] is False and beacon["interactions"] == 2 and beacon["expected"] >= 3
    assert [entry["navigation"] for entry in interaction["timeline"]] == [False, False, True] and interaction["timeline"][2]["sends"] == []


def test_without_recorded_interactions_nothing_is_invented(config):
    result = analyze(capture([sent(1, "https://t.tracker.example/e", T0)]), Lists(ORGS), config)
    assert result["site"]["summary"]["interaction"]["available"] is False and findings_of(result, "interaction_sent") == []
    empty = analyze(interactive_capture([sent(1, "https://t.tracker.example/e", T0)], []), Lists(ORGS), config)
    assert empty["site"]["summary"]["interaction"] | {"payloads": []} == {
        "available": True, "window_s": 2.0, "interactions": {}, "total": 0, "organizations": [], "timeline": [], "timeline_truncated": False,
        "payloads": [], "listener_scripts": 0, "recording_domains": []}
    hostile = analyze(interactive_capture([], [{"ts": "ayer", "kind": "click"}, {"ts": T0, "kind": "<script>"}, "x", {"ts": T0, "kind": "key"}]), Lists(ORGS), config)
    assert hostile["site"]["summary"]["interaction"]["interactions"] == {"key": 1}


# --- grabación de sesión ---


def test_session_recording_service_is_reported_as_an_inference(config):
    result = analyze(capture([req(1, "https://www.clarity.ms/tag/abc", resource_type="script"), req(2, "https://k.clarity.ms/collect", resource_type="xhr")]), Lists(ORGS), config)
    [finding] = findings_of(result, "session_recording")
    assert finding["level"] == "INFERENCIA" and finding["evidence_refs"] == [1, 2] and "grabación de sesión" in finding["claim"]
    assert result["site"]["summary"]["interaction"]["recording_domains"] == ["clarity.ms"]


# --- rastreo del lado del servidor (Conversions API de Meta) ---


def body(request, text):
    request["post_data"] = {"data": text, "encoding": "utf8", "size": len(text)}
    request["request_headers"] = [{"name": "content-type", "value": "application/json"}]
    return request


def test_cloud_host_receiving_meta_events_is_labelled_as_possible_conversions_api(config):
    capi = body(sent(1, "https://od-18c2.ecs.us-east-2.on.aws/events", T0), '{"event_name":"PageView","event_id":"e1","fbp":"fb.1.1700000000000.123456789"}')
    capi["registrable_domain"] = "on.aws"
    only_fbp = sent(2, "https://api-x.a.run.app/c", T0, params={"_fbp": "fb.1.1700000000000.987654321"})
    only_fbp["registrable_domain"] = "run.app"
    # Un host de nube sin esas señales, y las mismas señales hacia un dominio con dueño conocido: no se rotulan.
    plain_cloud = sent(3, "https://img.s3.amazonaws.com/a.png", T0, resource_type="image", method="GET")
    plain_cloud["registrable_domain"] = "amazonaws.com"
    known = sent(4, "https://www.facebook.com/tr", T0, params={"fbp": "fb.1.1", "event_name": "PageView"})
    weak = sent(5, "https://x.vercel.app/e", T0, params={"event_name": "View"})
    weak["registrable_domain"] = "vercel.app"
    result = analyze(capture([capi, only_fbp, plain_cloud, known, weak]), Lists(ORGS), config)
    found = {f["details"]["host"]: f for f in findings_of(result, "server_side_meta")}
    assert set(found) == {"od-18c2.ecs.us-east-2.on.aws", "api-x.a.run.app"}
    first = found["od-18c2.ecs.us-east-2.on.aws"]
    assert first["level"] == "INFERENCIA" and first["details"]["signals"] == ["event_id", "event_name", "fbp"] and first["evidence_refs"] == [1]
    assert "es compatible con" in first["claim"] and "no es observable" in first["claim"]
    label = "posible servidor de Conversions API de Meta (rastreo del lado del servidor)"
    assert [(item["host"], item["label"]) for item in result["site"]["summary"]["server_side"]] == [("api-x.a.run.app", label), ("od-18c2.ecs.us-east-2.on.aws", label)]


# --- catálogo de tipos de servicio ---


@pytest.mark.parametrize("domain, expected", [
    ("appier.net", "publicidad"), ("creativecdn.com", "publicidad"), ("liadm.com", "publicidad"), ("360yield.com", "publicidad"),
    ("tremorhub.com", "publicidad"), ("media.net", "publicidad"), ("gssprt.jp", "publicidad"), ("adx.opera.com", "publicidad"),
    ("postrelease.com", "publicidad"), ("1rx.io", "publicidad"), ("clmbtech.com", "publicidad"), ("unrulymedia.com", "publicidad"),
    ("socdm.com", "publicidad"), ("zmaticoo.com", "publicidad móvil"), ("ymmobi.com", "publicidad móvil"),
    ("demdex.net", "plataforma de datos de audiencia (DMP"), ("agkn.com", "broker de datos"), ("rlcdn.com", "broker de datos"),
    ("bluekai.com", "broker de datos"), ("crwdcntrl.net", "broker de datos"),
])
def test_service_catalog_covers_the_organizations_seen_in_real_captures(config, domain, expected):
    assert config.service_types.label(domain=domain).startswith(expected)


def test_meta_pixel_urls_are_a_conversion_pixel_whatever_the_organization_label(config):
    pixel = "publicidad (pixel de conversión)"
    for url in ("https://www.facebook.com/tr/?id=1&ev=PageView", "https://connect.facebook.net/en_US/fbevents.js", "https://connect.facebook.net/signals/config/123?v=2"):
        assert config.service_types.of(entity="Facebook", domain="facebook.com", urls=[url])["label"] == pixel, url
    # Otras páginas de Meta conservan el giro general; la query no cuenta para el patrón.
    assert config.service_types.of(entity="Facebook", domain="facebook.com", urls=["https://www.facebook.com/plugins/like.php?u=facebook.com/tr"])["label"].startswith("red social")
    result = analyze(capture([req(1, "https://www.facebook.com/tr/", params={"id": "1234567890123456", "ev": "PageView", "fbp": "fb.1.1700000000000.123456789"})]), Lists(ORGS), config)
    assert result["site"]["summary"]["service_types"].get("Facebook", {}).get("label") in (pixel, None)


# --- librerías benignas de canvas ---


def canvas_calls(script_url):
    read = {"kind": "canvas", "canvas_width": 80, "canvas_height": 80, "read_width": 80, "read_height": 80, "text_written": True, "colors": 2}
    return {"calls": [{"call_id": 1, "api": "canvas.fillText", "script_url": script_url, "frame_url": PAGE, "count": 1, "details": {}},
                      {"call_id": 2, "api": "canvas.toDataURL", "script_url": script_url, "frame_url": PAGE, "count": 1, "details": {"reads": [read]}}],
            "available": [], "truncated": False}


@pytest.mark.parametrize("script", [
    "https://g.alicdn.com/code/lib/qrcodejs/1.0.0/qrcode.min.js", "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js",
    "https://site.example/static/pdf.js/build/pdf.min.js", "https://site.example/vendor/html2canvas.min.js",
])
def test_known_library_canvas_read_is_evidence_of_the_read_but_not_fingerprinting(config, script):
    result = analyze_fingerprinting(canvas_calls(script), [], {}, config.scoring["fingerprinting"], benign=config.benign_libraries, interaction=config.interaction)
    assert [(f["heuristic"], f["level"], f["call_refs"]) for f in result["findings"]] == [("canvas_read_benign", "EVIDENCIA", [2])]
    assert result["fp_scripts"] == set() and "no se marca como fingerprinting" in result["findings"][0]["claim"]
    assert result["scripts"][0]["fingerprinting_inferred"] is False and result["scripts"][0]["heuristics"] == ["canvas_read_benign"]


@pytest.mark.parametrize("script", [
    "https://fp.tracker.example/collect.js", "https://qrcode.tracker.example/fp.js", "https://t.example/fp.js?lib=qrcode.min.js",
    "(inline o eval en https://site.example/qrcode/)", "",
])
def test_same_canvas_pattern_from_any_other_script_is_still_inferred_fingerprinting(config, script):
    result = analyze_fingerprinting(canvas_calls(script), [], {}, config.scoring["fingerprinting"], benign=config.benign_libraries, interaction=config.interaction)
    assert [f["heuristic"] for f in result["findings"]] == ["canvas_fingerprinting"] and result["findings"][0]["level"] == "INFERENCIA"


# --- escucha de interacción (lo que registra la instrumentación) ---


def test_event_listeners_are_evidence_of_listening_and_stay_out_of_the_fingerprinting_table(config):
    calls = {"calls": [
        {"call_id": 1, "api": "events.click", "script_url": "https://t.tracker.example/rec.js", "frame_url": PAGE, "count": 3, "details": {}},
        {"call_id": 2, "api": "events.mousemove", "script_url": "https://t.tracker.example/rec.js", "frame_url": PAGE, "count": 1, "details": {}},
        {"call_id": 3, "api": "events.scroll", "script_url": "", "frame_url": PAGE + "x?y=1", "count": 1, "details": {}},
        {"call_id": 4, "api": "navigator.userAgent", "script_url": "https://t.tracker.example/ua.js", "frame_url": PAGE, "count": 1, "details": {}},
    ], "available": [], "truncated": False}
    result = analyze_fingerprinting(calls, [], {}, config.scoring["fingerprinting"], benign=config.benign_libraries, interaction=config.interaction)
    listeners = {f["script_url"]: f for f in result["findings"] if f["heuristic"] == "interaction_listener"}
    assert set(listeners) == {"https://t.tracker.example/rec.js", "(inline o eval en https://www.airbnb.cl/x)"}
    recorder = listeners["https://t.tracker.example/rec.js"]
    assert recorder["level"] == "EVIDENCIA" and recorder["details"] == {"events": ["click", "mousemove"], "listeners": 4} and recorder["call_refs"] == [1, 2]
    assert "clic, movimiento del mouse" in recorder["claim"] and "el propósito" in recorder["claim"]
    # Escuchar eventos no es leer atributos del dispositivo: no entra en la tabla de fingerprinting ni infiere nada.
    assert [script["script_url"] for script in result["scripts"]] == ["https://t.tracker.example/ua.js"] and result["fp_scripts"] == set()
