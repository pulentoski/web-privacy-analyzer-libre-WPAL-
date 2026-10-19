"""v1.4.2 (docs/adr/030): textos según el origen de la captura, hallazgos agrupados, misma organización, catálogo
de tipos de servicio, HAR con una página por página visitada, registro de interacción del relé y estado del stack."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, text

from app.db import SessionLocal
from app.explain import explanations, glossary
from app.models import Job
from app.report_html import _interaction_section, executive_summary
from app.routes import resources
from app.routes.analysis import group_findings, report_validator
from app.routes.interactive import InteractionLog
from app.service_types import service_types
from app.version import APP_VERSION
from tests.factories import _request

HOSTILE = '<img src=x onerror="window.__XSS=1">'


# --- 1. textos coherentes con el origen ---


def test_last_group_says_human_navigation_in_interactive_captures():
    explainer = explanations()
    last = {source: explainer.story([], {}, {}, source)["steps"][-1] for source in ("scan", "interactive", "har_import")}
    assert "La visita fue automatizada, sin inicio de sesión, búsquedas ni clics" in last["scan"]["sentences"][1]["text"]
    assert last["scan"]["technical"] == "límites de una visita automatizada"
    for source in ("interactive", "har_import"):
        texts = " ".join(sentence["text"] for sentence in last[source]["sentences"])
        assert "automatizada" not in texts and "automatizada" not in last[source]["technical"], source
        assert "en los servidores de cada organización no es observable" in texts and len(last[source]["sentences"]) == 2
    assert "Hubo navegación humana" in last["interactive"]["sentences"][1]["text"]
    assert "navegador real del usuario" in last["har_import"]["sentences"][1]["text"]
    # Ocho grupos, con «Registro de interacción» antes del grupo fijo.
    assert [step["id"] for step in explainer.story([], {}, {})["steps"]][-2:] == ["interaccion", "no_visible"]


@pytest.mark.parametrize("source, expected", [("scan", "Durante la carga de la página"), ("interactive", "Durante la sesión"), ("har_import", "Durante la sesión")])
def test_executive_summary_wording_by_source(source, expected):
    report = {"scan": {"source": source, "interactive": {"timeline": [], "end_reason": "user_stop"}, "import": {}},
              "capture": {"total_requests": 10, "third_party": 4}, "site": {"summary": {}, "exposure_score": 10, "band": "Bajo"}, "trackers": [], "findings": []}
    found = " ".join(executive_summary(report)["found"])
    assert f"{expected}, el sitio realizó 10 requests" in found
    assert ("Durante la carga de la página" in found) == (source == "scan")


# --- 2. hallazgos repetidos en una fila ---


def finding(index, kind, level, organizations, requests):
    return {"id": index, "kind": "general", "type": kind, "level": level, "plain": f"frase {kind}", "step": "identificador",
            "organizations": organizations, "evidence_refs": {"requests": requests, "calls": []}}


def test_findings_with_same_type_level_and_organizations_share_a_row():
    items = [
        finding(1, "id_sync", "EVIDENCIA", ["Facebook", "on.aws"], [1, 2]), finding(2, "id_sync", "EVIDENCIA", ["Facebook", "on.aws"], [2, 3]),
        finding(3, "id_sync", "EVIDENCIA", ["Facebook", "on.aws"], [4]), finding(4, "id_sync", "EVIDENCIA", ["Google"], [5]),
        finding(5, "url_leak", "EVIDENCIA", ["Google"], [5]), finding(6, "identifier_param", "INFERENCIA", ["Google"], [6]),
        finding(7, "identifier_param", "POSIBLE", ["Google"], [6]),
    ]
    groups = group_findings(items)
    assert [(g["type"], g["level"], g["organizations"], g["count"], g["requests"], g["items"]) for g in groups] == [
        ("id_sync", "EVIDENCIA", ["Facebook", "on.aws"], 3, 4, [0, 1, 2]), ("id_sync", "EVIDENCIA", ["Google"], 1, 1, [3]),
        ("url_leak", "EVIDENCIA", ["Google"], 1, 1, [4]), ("identifier_param", "INFERENCIA", ["Google"], 1, 1, [5]),
        ("identifier_param", "POSIBLE", ["Google"], 1, 1, [6]),
    ]
    # Ningún hallazgo se pierde ni se repite.
    assert sorted(index for group in groups for index in group["items"]) == list(range(len(items)))


def test_findings_endpoint_returns_groups_that_cover_every_item(client, scan):
    body = client.get(f"/api/scans/{scan}/findings").json()
    assert sorted(index for group in body["groups"] for index in group["items"]) == list(range(len(body["items"])))
    assert all(isinstance(item["organizations"], list) for item in body["items"])


# --- 9. misma organización ---


def test_same_organization_requests_are_not_described_as_third_party():
    explainer = explanations()
    reasons = [{"signal": "third_party", "level": "EVIDENCIA", "detail": "x"}]
    same = explainer.request_phrase(reasons=reasons, entity="Alibaba", domain="alicdn.com", third_party=True, party="same_org")
    assert same["text"].startswith("Recurso de la misma organización (Alibaba)") and "no es un tercero" in same["text"] and same["signal"] == "same_org"
    assert "Request a tercero" not in same["text"] and same["level"] == "EVIDENCIA"
    no_signal = explainer.request_phrase(reasons=[], entity=None, domain="alicdn.com", third_party=True, party="same_org")
    assert no_signal["text"].startswith("Recurso de la misma organización (alicdn.com)")
    static = explainer.request_phrase(reasons=[{"signal": "third_party_static_clean", "level": "EVIDENCIA"}], entity="Alibaba", domain="alicdn.com", third_party=True, party="same_org")
    assert static["signal"] == "same_org"
    # Una señal más específica sigue ganando; y un tercero de verdad conserva su frase.
    leak = explainer.request_phrase(reasons=[*reasons, {"signal": "url_leak", "level": "EVIDENCIA", "data": {"parameter": "u"}}], entity="Alibaba", domain="alicdn.com", third_party=True, party="same_org")
    assert leak["signal"] == "url_leak"
    third = explainer.request_phrase(reasons=reasons, entity="Google", domain="doubleclick.net", third_party=True, party="third_party")
    assert third["text"].startswith("Request a tercero") and third["signal"] == "third_party"
    legacy = explainer.request_phrase(reasons=reasons, entity="Google", domain="doubleclick.net", third_party=True)
    assert legacy["signal"] == "third_party"


# --- 3 y 4. catálogo de tipos de servicio y glosario ---


@pytest.mark.parametrize("domain, expected", [
    ("appier.net", "publicidad"), ("creativecdn.com", "publicidad"), ("liadm.com", "publicidad"), ("360yield.com", "publicidad"),
    ("tremorhub.com", "publicidad"), ("media.net", "publicidad"), ("gssprt.jp", "publicidad"), ("opera.com", "publicidad"),
    ("postrelease.com", "publicidad"), ("1rx.io", "publicidad"), ("clmbtech.com", "publicidad"), ("unrulymedia.com", "publicidad"),
    ("socdm.com", "publicidad"), ("zmaticoo.com", "publicidad móvil"), ("ymmobi.com", "publicidad móvil"),
    ("demdex.net", "plataforma de datos de audiencia (DMP"), ("agkn.com", "broker de datos"), ("rlcdn.com", "broker de datos"),
    ("bluekai.com", "broker de datos"), ("crwdcntrl.net", "broker de datos"),
])
def test_service_catalog(domain, expected):
    assert service_types().of(domain=domain)["label"].startswith(expected)


def test_meta_pixel_is_a_conversion_pixel_by_url():
    resolver = service_types()
    assert resolver.of(entity="Facebook, Inc.", domain="facebook.com", urls=["https://www.facebook.com/tr/?id=1"])["label"] == "publicidad (pixel de conversión)"
    assert resolver.of(entity="Facebook, Inc.", domain="facebook.net", urls=["https://connect.facebook.net/es_LA/fbevents.js"])["label"] == "publicidad (pixel de conversión)"
    assert resolver.of(entity="Facebook, Inc.", domain="facebook.com", urls=["https://www.facebook.com/plugins/like.php"])["label"].startswith("red social")
    assert resolver.of(domain="facebook.com", urls=[None, 5, ""])["label"].startswith("red social")


def test_glossary_explains_server_side_tracking_and_interaction():
    terms = {term["id"]: term for term in glossary().as_dict()["terms"]}
    assert "Conversions API" in terms["rastreo_servidor"]["plain"] and "no es observable" in terms["rastreo_servidor"]["definition"]
    assert "Inferencia" in terms["rastreo_servidor"]["definition"]
    assert {"registro_interaccion", "dmp", "broker_datos"} <= set(terms)


# --- 7. HAR exportado ---


@pytest.fixture()
def interactive_job(client):
    job_id = uuid.uuid4()
    start = datetime(2026, 10, 12, 15, 0, 0, tzinfo=timezone.utc)
    timeline = [
        {"seq": 0, "ts": (start + timedelta(seconds=1)).isoformat(), "url": "http://site.example/", "title": "Inicio", "tab": 1},
        {"seq": 1, "ts": (start + timedelta(seconds=30)).isoformat(), "url": "http://site.example/producto?id=7", "title": HOSTILE, "tab": 1},
        {"seq": 2, "ts": (start + timedelta(seconds=60)).isoformat(), "url": "http://otro.example/", "title": None, "tab": 2},
        "basura", {"ts": "ayer", "url": "http://x.example/"},
    ]

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="completed", options={"source": "interactive"},
                            result={"source": "interactive", "interactive": {"timeline": timeline, "end_reason": "user_stop"}}))
            await session.flush()
            # Una request anterior a la primera navegación registrada, y varias en cada página.
            for seq, offset in enumerate((0, 2, 29, 31, 45, 61, 90)):
                session.add(_request(job_id, seq, ts=start + timedelta(seconds=offset)))
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id)
    client.portal.call(cleanup)


def test_har_export_has_one_page_per_visited_page_and_the_real_version(client, interactive_job, scan):
    har = client.get(f"/api/scans/{interactive_job}/har").json()["log"]
    assert har["creator"] == {"name": "Web Privacy & Tracker Analyzer", "version": APP_VERSION} and APP_VERSION == "1.6.0"
    assert [(page["id"], page["title"]) for page in har["pages"]] == [("page_1", "Inicio"), ("page_2", HOSTILE), ("page_3", "http://otro.example/")]
    assert har["pages"][1]["comment"] == "http://site.example/producto?id=7 · pestaña 1" and har["pages"][2]["comment"].endswith("pestaña 2")
    assert [page["startedDateTime"] for page in har["pages"]] == sorted(page["startedDateTime"] for page in har["pages"])
    # Cada entrada va con la última página cargada antes de ella.
    assert [entry["pageref"] for entry in har["entries"]] == ["page_1", "page_1", "page_1", "page_2", "page_2", "page_3", "page_3"]
    assert {entry["pageref"] for entry in har["entries"]} <= {page["id"] for page in har["pages"]}
    # Un scan normal conserva su única página.
    plain = client.get(f"/api/scans/{scan}/har").json()["log"]
    assert [page["id"] for page in plain["pages"]] == ["page_1"] and {entry["pageref"] for entry in plain["entries"]} == {"page_1"}
    assert plain["creator"]["version"] == APP_VERSION


# --- 8. registro de interacción en el relé: solo hora y tipo ---


def key(down, keysym=0x61):
    return bytes([4, down, 0, 0]) + keysym.to_bytes(4, "big")


def pointer(buttons, x=100, y=200):
    return bytes([5, buttons]) + x.to_bytes(2, "big") + y.to_bytes(2, "big")


def test_interaction_log_keeps_time_and_kind_only():
    log = InteractionLog()
    assert log.feed(pointer(0), 1000) is True and log.pending == []                # mover el puntero no es un clic
    assert log.feed(pointer(1), 2000) is True and log.pending == [[2000, "click"]]   # botón presionado
    log.feed(pointer(1, 150, 250), 2100)                                             # arrastre: mismo botón, sin clic nuevo
    log.feed(pointer(0), 2200)
    log.feed(pointer(8), 3000); log.feed(pointer(0), 3010); log.feed(pointer(16), 3020)  # rueda: ráfaga = un desplazamiento
    log.feed(key(1, 0x70), 4000); log.feed(key(0, 0x70), 4050); log.feed(key(1, 0x61), 4100); log.feed(key(1, 0x73), 4500)
    assert log.take() == [[2000, "click"], [3000, "scroll"], [4000, "key"], [4500, "key"]] and log.pending == []
    # Nada de lo registrado depende de la tecla ni de la posición: otra tecla y otro punto dan lo mismo.
    other = InteractionLog()
    other.feed(pointer(1, 5, 5), 2000); other.feed(pointer(0), 2200); other.feed(pointer(8), 3000); other.feed(key(1, 0xFFFF), 4000); other.feed(key(1, 0x31), 4500)
    assert other.take() == [[2000, "click"], [3000, "scroll"], [4000, "key"], [4500, "key"]]


def test_interaction_log_parses_batched_and_unknown_messages():
    log = InteractionLog()
    update_request = bytes([3, 1]) + bytes(8)
    encodings = bytes([2, 0, 0, 2]) + bytes(8)
    batch = update_request + encodings + pointer(1) + key(1)
    assert log.feed(batch, 1000) is True and log.take() == [[1000, "click"], [1000, "key"]]
    assert log.feed(update_request, 5000) is False                      # pedir pantalla no es entrada del usuario
    assert log.feed(bytes([250, 1, 2, 3]) + pointer(1), 6000) is False  # extensión desconocida: no se interpreta el resto
    assert log.feed(bytes([5, 1, 0]), 7000) is False and log.feed(b"", 8000) is False  # mensaje cortado o vacío
    cut_text = bytes([6, 0, 0, 0]) + (5).to_bytes(4, "big") + b"hola!"
    assert log.feed(cut_text + key(1), 9000) is True and log.take() == [[9000, "key"]]
    limited = InteractionLog()
    for index in range(4000):
        limited.feed(key(1), index * 1000)
    assert limited.total == 3000 and len(limited.take()) == 3000


def test_interaction_section_of_the_report_escapes_and_states_what_is_not_kept():
    summary = {"interaction": {
        "available": True, "window_s": 2, "interactions": {"click": 2, "key": 1}, "total": 3,
        "organizations": [{"organization": HOSTILE, "interactions": 2, "requests": 3, "expected": 0.0, "flagged": True},
                          {"organization": "Beacon Corp", "interactions": 2, "requests": 4, "expected": 4.0, "flagged": False}],
        "timeline": [{"ts": 1791817200.0, "kind": "click", "navigation": False, "sends": [{"organization": HOSTILE, "requests": 2}]},
                     {"ts": 1791817210.0, "kind": "key", "navigation": True, "sends": []}],
        "payloads": [{"domain": "tracker.example", "label": "coordenadas del puntero", "parameters": ["clientx", HOSTILE], "requests": 2}],
        "recording_domains": ["clarity.ms"]}}
    html = _interaction_section({"site": {"summary": summary}})
    assert HOSTILE not in html and "&lt;img src=x onerror=" in html and "Beacon Corp" not in html
    assert "nunca qué se tecleó ni dónde se hizo clic" in html and "abrió otra página" in html and "clarity.ms" in html
    unavailable = _interaction_section({"site": {"summary": {"interaction": {"available": False, "payloads": [], "organizations": []}}}})
    assert "no registró la interacción del usuario" in unavailable
    assert _interaction_section({"site": {"summary": {}}}) == ""


# --- 12. bloque de estado del indicador ---


@pytest.mark.needs_stack  # lee el estado de los servicios en marcha (worker/frontend); se omite en CI.
def test_resources_reports_stack_and_worker_status(client):
    resources._cache["body"] = None
    body = client.get("/api/resources").json()
    assert body["status"]["database"] is True and body["status"]["worker"] is True
    assert body["status"]["stack"] in ("ok", "degradado") and (body["status"]["stack"] == "ok") == (body["totals"]["services_reporting"] == 5)
    assert body["generated_at"].endswith("+00:00")


def test_report_schema_has_the_eight_groups():
    schema = report_validator().schema
    steps = schema["properties"]["story"]["properties"]["steps"]
    assert schema["properties"]["schema_version"]["const"] == "1.11.0" and steps["minItems"] == steps["maxItems"] == 8
    assert steps["items"]["properties"]["id"]["enum"][-2:] == ["interaccion", "no_visible"]
