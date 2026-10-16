"""F10: frases técnicas, «Hallazgos por grupo», glosario, progreso real y borrado del historial."""

import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import yaml
from sqlalchemy import text

from app import history
from app.config import Settings, get_settings
from app.db import SessionLocal
from app.explain import LEVELS, Explanations, explanations, glossary
from app.models import Job, RequestAnalysis
from app.report_html import render_scan_report
from app.routes.analysis import report_validator
from app.routes.scans import STAGES, scan_progress
from tests.factories import _request

NOT_FACT = ("INFERENCIA", "POSIBLE", "DESCONOCIDO")
STEP_IDS = ["etiquetado", "equipo", "navegacion", "datos", "identificador", "consentimiento", "interaccion", "no_visible"]
PAYLOAD = '<img src=x onerror="window.__XSS=1">'
# Lo mismo que vigila el test de textos del frontend: nada de prometer anonimato.
FORBIDDEN = [r"\ban[oó]nim[oa]s?\b", r"ocult[oa]s?\b", r"ocultar|ocultan|oculte", r"invisible", r"indetectable", r"irrastreable"]
# Trato de usted: ninguna forma de tuteo en los textos.
TUTEO = [r"\btu\b", r"\btus\b", r"\bte\b", r"\bti\b", r"\bcontigo\b", r"\bpuedes\b", r"\bquieres\b", r"\btienes\b", r"\best[aá]s\b"]
REQUIRED_TERMS = {
    "request", "tercero", "tracker", "pixel", "beacon", "cookie", "cookie persistente", "sincronización de identificadores", "referer",
    "user-agent", "base64", "url codificada", "canvas", "webgl", "fingerprinting", "exfiltración", "evidencia", "inferencia",
    "posible", "desconocido", "cmp / tcf", "consent mode",
}


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def data_file(name):
    return yaml.safe_load(open(f"{get_settings().data_dir}/{name}", encoding="utf-8"))


# Datos de sobra para rellenar cualquier plantilla.
DETAILS = {
    "domain": "tracker.example", "parameter": "uid", "domains": ["tracker.example", "ads.example"], "stored_in": "la cookie «_id»",
    "cookies": 3, "max_days": 390, "third_party": True, "list": "easyprivacy", "cmp_name": "CMP de prueba", "cmp_id": 7,
    "ad_storage": "granted", "analytics_storage": "denied", "signal": "ad_storage", "api": "canvas.toDataURL",
    "distinct_fonts": 60, "properties": ["a", "b"], "host": "metrics.site.example", "cname_target": "t.tracker.example",
    "organization": "Tracker Corp", "datos": "el tamaño de su pantalla",
    # v1.4.2: registro de interacción y rastreo del lado del servidor.
    "events": ["click", "scroll"], "label": "profundidad de desplazamiento", "interactions": 3,
    # v1.3: fuga de búsqueda y ola de sincronización.
    "term": "zapatillas rojas", "initiator": "gum.tracker.example", "organizations": 5, "requests": 9,
}


def finding(kind, level, **details):
    fingerprinting = kind in ("canvas_fingerprinting", "font_enumeration", "audio_fingerprinting", "webgl_fingerprinting",
                              "webgl_unmasked_read", "webrtc_ip_discovery", "webrtc_connection", "webrtc_ice_exposed", "property_sweep", "exfiltration",
                              "fp_read", "interaction_listener", "canvas_read_benign")
    return {"type": kind, "level": level, "kind": "fingerprinting" if fingerprinting else "general", "claim": "detalle técnico",
            "script_url": "https://t.tracker.example/fp.js" if fingerprinting else None, "details": {**DETAILS, **details},
            "evidence_refs": {"requests": [1, 2], "calls": [3]}}


# --- Criterio 4: la frase respeta el nivel ---


def test_no_inference_is_ever_written_as_a_fact():
    """Cualquier hallazgo o señal, con CUALQUIER nivel que no sea EVIDENCIA, sale con un matiz."""
    explainer = explanations()
    checked = 0
    for kind in [*explainer.findings, "tipo_que_no_existe"]:
        for level in NOT_FACT:
            phrase = explainer.finding_phrase(finding(kind, level), {"tracker.example": "Tracker Corp"}, {})
            assert phrase["level"] == level and explainer.hedged(phrase["text"]), (kind, level, phrase["text"])
            checked += 1
    for signal in explainer.signals:
        for level in NOT_FACT:
            reason = {"signal": signal, "level": level, "data": {"parameter": "uid", "api": "canvas.toDataURL", "other_domains": ["ads.example"], "stored_in": "la cookie «_id»", "list": "easyprivacy"}}
            phrase = explainer.request_phrase(reasons=[reason], entity="Tracker Corp", domain="tracker.example", third_party=True)
            assert phrase["level"] == level and explainer.hedged(phrase["text"]), (signal, level, phrase["text"])
            checked += 1
    assert checked >= 100


def test_declared_templates_carry_their_hedge_and_evidence_templates_fill_in():
    data = data_file("explanations.yaml")
    explainer = explanations()
    for group in ("signals", "findings"):
        for name, spec in data[group].items():
            assert set(spec) & set(LEVELS), f"{group}.{name} no tiene ninguna variante de nivel"
            for level in NOT_FACT:
                if level in spec:
                    assert explainer.hedged(spec[level]), f"{group}.{name}.{level} se redacta como hecho: {spec[level]}"
    # Con datos reales, la plantilla propia se usa (no la genérica) y lleva la empresa.
    for kind, spec in explainer.findings.items():
        for level in LEVELS:
            if level in spec:
                phrase = explainer.finding_phrase(finding(kind, level), {"tracker.example": "Tracker Corp"}, {"https://t.tracker.example/fp.js": "Tracker Corp"})
                assert phrase["generic"] is False, (kind, level, phrase)
                assert "{" not in phrase["text"] and "None" not in phrase["text"], phrase["text"]


def test_a_template_that_states_an_inference_as_fact_is_rejected_at_load():
    data = data_file("explanations.yaml")
    data["findings"]["identifier_param"]["INFERENCIA"] = "El dato «{parametro}» es un identificador suyo."
    with pytest.raises(ValueError, match="se redacta como hecho"):
        Explanations(data)
    data = data_file("explanations.yaml")
    data["steps"][1]["inference"] = "En {n|caso|casos} hay fingerprinting."
    with pytest.raises(ValueError, match="se redacta como hecho"):
        Explanations(data)


def test_missing_data_falls_back_to_the_generic_phrase_instead_of_inventing():
    explainer = explanations()
    phrase = explainer.finding_phrase({"type": "url_leak", "level": "EVIDENCIA", "kind": "general", "details": {}, "evidence_refs": [1]}, {}, {})
    assert phrase["generic"] is True and phrase["text"] == explainer.fallback["EVIDENCIA"]
    assert explainer.request_phrase(reasons=None, entity=None, domain=None, third_party=True) is None


def test_phrases_use_the_real_data_of_the_finding():
    explainer = explanations()
    entities = {"taboola.com": "Taboola", "google.com": "Google LLC", "doubleclick.net": "Google LLC"}
    sync = explainer.finding_phrase(finding("id_sync", "EVIDENCIA", domains=["taboola.com", "google.com", "doubleclick.net"]), entities, {})
    assert sync["text"] == ("Sincronización de identificadores (cookie syncing): Taboola y Google LLC recibieron el mismo identificador; "
                            "el valor común permite correlacionar sus registros del mismo navegador.")
    leak = explainer.finding_phrase(finding("url_leak", "EVIDENCIA", domain="taboola.com", parameter="page_url"), entities, {})
    assert leak["text"] == "Fuga de URL: la URL de la página se envió a Taboola en el parámetro «page_url»."
    exfiltration = explainer.finding_phrase(finding("exfiltration", "EVIDENCIA", domain="unknown.example", api="webgl.UNMASKED_RENDERER_WEBGL"), entities, {})
    assert exfiltration["text"] == "Exfiltración de atributos: un script leyó el modelo de la GPU (WebGL UNMASKED_RENDERER) y el valor se transmitió a unknown.example."
    cookie = explainer.finding_phrase(finding("persistent_cookie", "EVIDENCIA", domain="taboola.com", cookies=1, max_days=1), entities, {})
    assert cookie["text"].startswith("Cookies persistentes: ") and "1 cookie persistente" in cookie["text"] and "expira en 1 día." in cookie["text"]
    request = explainer.request_phrase(
        reasons=[{"signal": "third_party", "level": "EVIDENCIA"}, {"signal": "url_leak", "level": "EVIDENCIA", "data": {"parameter": "u"}},
                 {"signal": "mechanism_pixel", "level": "INFERENCIA"}],
        entity="Taboola", domain="taboola.com", third_party=True)
    assert request == {"text": "Fuga de URL: la URL de la página se envió a Taboola en un parámetro de la request.", "level": "EVIDENCIA", "generic": False, "signal": "url_leak"}


def test_captured_text_is_inserted_verbatim_and_never_reinterpreted():
    explainer = explanations()
    hostile = "{empresa}" + PAYLOAD
    phrase = explainer.finding_phrase(finding("url_leak", "EVIDENCIA", parameter=hostile), {"tracker.example": "Tracker Corp"}, {})
    # El nombre del parámetro aparece tal cual (acotado): ni se expande como plantilla ni se altera.
    assert "«{empresa}<img src=x onerror=" in phrase["text"] and phrase["text"].count("Tracker Corp") == 1
    assert "\x00" not in explainer.finding_phrase(finding("url_leak", "EVIDENCIA", parameter="a\x00b"), {}, {})["text"]


# --- Textos: usted y sin promesas ---


@pytest.mark.parametrize("name", ["explanations.yaml", "glossary.yaml"])
def test_texts_use_usted_and_never_promise_anonymity(name):
    texts = list(strings(data_file(name)))
    assert len(texts) > 60
    for sentence in texts:
        for pattern in FORBIDDEN + TUTEO:
            assert not re.search(pattern, sentence, re.I), f"{name}: «{sentence}» coincide con {pattern}"


# --- Criterio 6: glosario y paneles ---


def test_glossary_has_every_required_term_and_a_panel_per_tab(client):
    response = client.get("/api/glossary")
    assert response.status_code == 200
    body = response.json()
    assert body == glossary().as_dict()
    terms = {term["term"].lower(): term for term in body["terms"]}
    assert REQUIRED_TERMS <= set(terms), REQUIRED_TERMS - set(terms)
    for term in body["terms"]:
        assert len(term["definition"]) > 40 and term["plain"] and re.fullmatch(r"[a-z_0-9]+", term["id"])
    assert set(body["panels"]) == {"summary", "story", "trackers", "fingerprinting", "traffic"}
    for panel in body["panels"].values():
        assert len(panel["definition"]) > 60 and len(panel["method"]) > 40 and panel["terms"]
    # Registro técnico: sin analogías, exclamaciones ni comparaciones coloquiales.
    for entry in [*body["terms"], *body["panels"].values()]:
        assert "analogy" not in entry
        text = " ".join(str(value) for value in entry.values()).lower()
        assert not re.search(r"[¡!]|\b(guardia|carta|firma|lienzo|como un|como una)\b", text), text
    assert "inferencia" in terms["fingerprinting"]["definition"].lower() and "todataurl" in terms["canvas"]["definition"].lower()


# --- Criterio 5: «Hallazgos por grupo» ---


@pytest.fixture(scope="module")
def story_scan(client):
    """Scan analizado con un hallazgo en cada paso, razones con `data` y un parámetro cuyo nombre es un payload."""
    job_id = uuid.uuid4()
    ids, calls = {}, {}

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="completed", analysis_status="completed",
                            result={"final_url": "http://site.example/", "http_status": 200, "title": "T",
                                    "capture": {"truncated": False, "total_requests": 4, "duration_ms": 4200, "fingerprinting": {"truncated": False, "rejected": 0}}},
                            progress={"stage": "building", "requests": 4, "max_s": 60}))
            await session.flush()
            requests = [
                _request(job_id, 0, resource_type="document", is_navigation=True),
                _request(job_id, 1, host="t.taboola.example", registrable_domain="taboola.example", third_party=True, url="http://t.taboola.example/fp.js"),
                _request(job_id, 2, host="s.gads.example", registrable_domain="gads.example", third_party=True),
                _request(job_id, 3, host="x.unknown.example", registrable_domain="unknown.example", third_party=True),
            ]
            session.add_all(requests)
            await session.flush()
            for request in requests:
                ids[request.seq] = request.id

            def reason(signal, ref, level="EVIDENCIA", **data):
                return {"signal": signal, "weight": 10, "level": level, "evidence_ref": ref, "detail": "detalle", **({"data": data} if data else {})}

            rows = [
                (0, 0, "Bajo", "first-party", "document", "no_disponible", []),
                (1, 75, "Alto", "advertising", "script", "Taboola", [reason("third_party", ids[1]), reason("id_sync", ids[1], other_domains=["gads.example"], other_entities=["Google"]), reason("fp_script", ids[1], "INFERENCIA")]),
                (2, 55, "Moderado", "advertising", "pixel", "Google", [reason("third_party", ids[2]), reason("url_leak", ids[2], parameter=PAYLOAD), reason("mechanism_pixel", ids[2], "INFERENCIA")]),
                (3, 45, "Moderado", "third-party", "fetch/xhr", "no_disponible", [reason("third_party", ids[3]), reason("fp_exfiltration", ids[3], parameter="gpu", api="webgl.UNMASKED_RENDERER_WEBGL", form="valor")]),
            ]
            session.add_all(
                RequestAnalysis(job_id=job_id, request_id=ids[seq], score=score, band=band, category=category, mechanism=mechanism,
                                entity=entity, list_matches=[], reasons=reasons, analyzer_version="1.4.0")
                for seq, score, band, category, mechanism, entity, reasons in rows
            )
            general = [
                ("persistent_cookie", "EVIDENCIA", [ids[1]], {"domain": "taboola.example", "cookies": 2, "max_days": 390, "third_party": True, "names": ["t_gid"]}),
                ("third_party_set_cookie", "EVIDENCIA", [ids[2]], {"domain": "gads.example"}),
                ("identifier_param", "INFERENCIA", [ids[2]], {"domain": "gads.example", "parameter": "uid"}),
                ("url_leak", "EVIDENCIA", [ids[2]], {"domain": "gads.example", "parameter": PAYLOAD}),
                ("id_sync", "EVIDENCIA", [ids[1], ids[2]], {"domains": ["taboola.example", "gads.example"], "owners": 2}),
                ("opaque_payload", "DESCONOCIDO", [ids[3]], {"domain": "unknown.example"}),
                ("consent_mode_state", "EVIDENCIA", [ids[2]], {"raw": "G111", "ad_storage": "granted", "analytics_storage": "granted", "source": "gcs"}),
                ("list_match", "EVIDENCIA", [ids[1]], {"list": "easyprivacy", "domain": "taboola.example"}),
            ]
            for kind, level, refs, details in general:
                await session.execute(
                    text("INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version) "
                         "VALUES (:job, :type, :level, :claim, CAST(:refs AS jsonb), CAST(:details AS jsonb), '1.4.0')"),
                    {"job": job_id, "type": kind, "level": level, "claim": f"Detalle técnico de {kind} «{PAYLOAD}»", "refs": json.dumps(refs), "details": json.dumps(details)},
                )
            script = "http://t.taboola.example/fp.js"
            for api, count in (("canvas.toDataURL", 2), ("webgl.UNMASKED_RENDERER_WEBGL", 1), ("screen.width", 4)):
                calls[api] = await session.scalar(
                    text("INSERT INTO fp_api_calls (job_id, api, script_url, frame_url, count, details) VALUES (:job, :api, :url, 'http://site.example/', :count, '{}') RETURNING id"),
                    {"job": job_id, "api": api, "url": script, "count": count},
                )
            for heuristic, level, call_refs, request_refs, details in (
                ("canvas_fingerprinting", "INFERENCIA", [calls["canvas.toDataURL"]], [], {"api": "canvas.toDataURL"}),
                ("webgl_unmasked_read", "EVIDENCIA", [calls["webgl.UNMASKED_RENDERER_WEBGL"]], [], {}),
                ("exfiltration", "EVIDENCIA", [calls["webgl.UNMASKED_RENDERER_WEBGL"]], [ids[3]], {"api": "webgl.UNMASKED_RENDERER_WEBGL", "domain": "unknown.example", "form": "valor", "parameter": "gpu"}),
            ):
                await session.execute(
                    text("INSERT INTO fp_findings (job_id, script_url, heuristic, level, claim, call_refs, request_refs, details, analyzer_version) "
                         "VALUES (:job, :url, :h, :level, 'detalle técnico', CAST(:calls AS jsonb), CAST(:requests AS jsonb), CAST(:details AS jsonb), '1.4.0')"),
                    {"job": job_id, "url": script, "h": heuristic, "level": level, "calls": json.dumps(call_refs), "requests": json.dumps(request_refs), "details": json.dumps(details)},
                )
            await session.execute(
                text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                     "VALUES (:job, '1.4.0', 'abc', '[]', 40, 'Bajo-moderado', '[]', '[]', '{}', '{\"trackers\": 3}', false, 10)"),
                {"job": job_id},
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
            await session.commit()

    client.portal.call(insert)
    yield str(job_id), ids, calls
    client.portal.call(cleanup)


def test_story_has_the_seven_steps_in_order_with_phrase_count_level_and_evidence(client, story_scan):
    job_id, ids, calls = story_scan
    response = client.get(f"/api/scans/{job_id}/report")
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["schema_version"] == "1.8.0" and not list(report_validator().iter_errors(report))
    steps = report["story"]["steps"]
    assert [step["id"] for step in steps] == STEP_IDS and [step["number"] for step in steps] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert [step["title"] for step in steps] == ["Identificadores persistentes", "Fingerprinting", "Fugas de URL y Referer", "Exfiltración de atributos",
                                                 "Sincronización de identificadores", "Consentimiento (TCF / Consent Mode)", "Registro de interacción", "Fuera del alcance observable"]
    by_id = {step["id"]: step for step in steps}
    # Cada paso: frase(s) con nivel, conteo y hallazgos con evidencia.
    for step in steps[:6]:
        assert step["observed"] is True and step["count"] == len(step["items"]) == step["total_items"] >= 1
        assert sum(step["levels"].values()) == step["count"]
        for sentence in step["sentences"]:
            assert sentence["level"] in LEVELS and len(sentence["text"]) > 20
            if sentence["level"] != "EVIDENCIA":
                assert explanations().hedged(sentence["text"])
        for item in step["items"]:
            assert item["level"] in LEVELS and item["plain"] and (item["evidence_refs"]["requests"] or item["evidence_refs"]["calls"])
            if item["level"] != "EVIDENCIA":
                assert explanations().hedged(item["plain"]), item
    assert {item["type"] for item in by_id["etiquetado"]["items"]} == {"persistent_cookie", "third_party_set_cookie", "identifier_param"}
    assert by_id["etiquetado"]["levels"] == {"EVIDENCIA": 2, "INFERENCIA": 1}
    assert by_id["etiquetado"]["sentences"][0]["text"].startswith("2 organizaciones establecieron cookies en el navegador")
    assert "Taboola" in by_id["etiquetado"]["sentences"][0]["text"] and "Google" in by_id["etiquetado"]["sentences"][0]["text"]
    # Fingerprinting: la lectura es EVIDENCIA y el propósito INFERENCIA, por separado.
    equipo = {item["type"]: item for item in by_id["equipo"]["items"]}
    assert equipo["fp_read"]["level"] == "EVIDENCIA" and equipo["webgl_unmasked_read"]["level"] == "EVIDENCIA" and equipo["canvas_fingerprinting"]["level"] == "INFERENCIA"
    assert sorted(equipo["fp_read"]["evidence_refs"]["calls"]) == sorted(calls.values())
    assert "Lectura de atributos: un script de Taboola leyó:" in equipo["fp_read"]["plain"] and "la resolución y profundidad de color de la pantalla" in equipo["fp_read"]["plain"]
    assert [sentence["level"] for sentence in by_id["equipo"]["sentences"]] == ["EVIDENCIA", "INFERENCIA"]
    assert by_id["navegacion"]["items"][0]["plain"] == f"Fuga de URL: la URL de la página se envió a Google en el parámetro «{PAYLOAD}»."
    assert {item["type"] for item in by_id["datos"]["items"]} == {"exfiltration", "opaque_payload"}
    assert by_id["identificador"]["items"][0]["plain"].startswith("Sincronización de identificadores (cookie syncing): Taboola y Google recibieron el mismo identificador")
    assert by_id["consentimiento"]["items"][0]["plain"] == "Consent Mode: 1 request a Google transmitió el estado de consentimiento: publicidad (ad_storage) concedido, medición (analytics_storage) concedido."
    # El último paso es fijo: lo que no se puede ver.
    last = by_id["no_visible"]
    assert last["fixed"] is True and last["items"] == [] and len(last["sentences"]) == 2
    assert "no es observable" in last["sentences"][0]["text"] and "sin inicio de sesión, búsquedas ni clics" in last["sentences"][1]["text"]
    # list_match no pertenece a ningún paso, pero conserva su frase técnica en la lista técnica.
    assert all(item["type"] != "list_match" for step in steps for item in step["items"])
    assert all(item["plain"] for item in report["findings"]) and len(report["findings"]) == 8
    assert all(request["plain"]["text"] for group in report["trackers"] for request in group["requests"])


def test_steps_without_findings_say_so(client):
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="completed", analysis_status="completed", result={"capture": {"truncated": False}}))
            await session.flush()
            session.add(_request(job_id, 0, resource_type="document", is_navigation=True))
            await session.execute(
                text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                     "VALUES (:job, '1.4.0', 'abc', '[]', 0, 'Bajo', '[]', '[]', '{}', '{}', false, 1)"), {"job": job_id})
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
            await session.commit()

    client.portal.call(insert)
    try:
        steps = client.get(f"/api/scans/{job_id}/report").json()["story"]["steps"]
        assert [step["id"] for step in steps] == STEP_IDS
        for step in steps[:7]:
            assert step["observed"] is False and step["count"] == 0 and step["items"] == []
            assert step["sentences"] == [{"text": "No se observó en esta visita.", "level": None}]
        assert steps[7]["fixed"] is True
    finally:
        client.portal.call(cleanup)


def test_findings_and_requests_carry_the_plain_phrase_before_the_detail(client, story_scan):
    job_id, ids, _ = story_scan
    findings = client.get(f"/api/scans/{job_id}/findings").json()["items"]
    assert len(findings) == 11 and all(item["plain"] and item["claim"] for item in findings)
    by_type = {item["type"]: item for item in findings}
    assert by_type["id_sync"]["step"] == "identificador" and by_type["list_match"]["step"] is None
    assert by_type["list_match"]["plain"] == "Coincidencia con lista de filtros: Taboola figura en EasyPrivacy (1 request en esta visita)."
    for item in findings:
        if item["level"] != "EVIDENCIA":
            assert explanations().hedged(item["plain"]), item
    items = client.get(f"/api/scans/{job_id}/requests").json()["items"]
    plain = {item["seq"]: item["plain"] for item in items}
    assert plain[0] == {"text": "Request de primera parte: conexión con el sitio analizado.", "level": "EVIDENCIA", "signal": "_first_party"}
    assert plain[1]["text"] == ("Sincronización de identificadores (cookie syncing): Taboola recibió un identificador que también recibió Google; "
                                "el valor común permite correlacionar los registros del mismo navegador.")
    assert plain[2] == {"text": "Fuga de URL: la URL de la página se envió a Google en un parámetro de la request.", "level": "EVIDENCIA", "signal": "url_leak"}
    assert plain[3]["text"] == "Exfiltración de atributos: un script leyó el modelo de la GPU (WebGL UNMASKED_RENDERER) y el valor se transmitió a unknown.example."
    detail = client.get(f"/api/scans/{job_id}/requests/{ids[2]}").json()
    assert detail["plain"]["signal"] == "url_leak" and detail["reasons"][1]["data"] == {"parameter": PAYLOAD}
    assert {item["type"]: item["plain"] for item in detail["findings"]}["url_leak"].startswith("Fuga de URL: la URL de la página se envió a Google en el parámetro")


def test_requests_without_analysis_have_no_plain_phrase(client, scan):
    items = client.get(f"/api/scans/{scan}/requests").json()["items"]
    assert items and all(item["plain"] is None for item in items)


def test_exported_report_has_the_story_sober_and_escaped(client, story_scan):
    """Criterio 9: el HTML del cliente lleva los 7 pasos, sin el tema de la interfaz, y todo lo capturado va escapado."""
    job_id, _, _ = story_scan
    report = client.get(f"/api/scans/{job_id}/report").json()
    html = render_scan_report(report, "0" * 64)
    summary = html[html.index("Resumen ejecutivo"):html.index("Anexo técnico")]
    positions = [summary.index(f"{number}. {title}") for number, title in enumerate(
        ["Identificadores persistentes", "Fingerprinting", "Fugas de URL y Referer", "Exfiltración de atributos", "Sincronización de identificadores",
         "Consentimiento (TCF / Consent Mode)", "Registro de interacción", "Fuera del alcance observable"], start=1)]
    assert positions == sorted(positions)
    assert "Hallazgos por grupo" in summary and "ocho grupos técnicos" in summary
    assert 'class="lvl lvl-INFERENCIA"' in summary and 'class="lvl lvl-EVIDENCIA"' in summary
    assert "Hallazgos por grupo: detalle y evidencia" in html
    # Texto capturado dentro de una frase técnica: escapado, nunca como etiqueta.
    assert "<img src=x" not in html and "&lt;img src=x onerror=" in html
    # Sobrio: ni fuentes ni colores del tema de la interfaz, ni scripts.
    lowered = html.lower()
    for forbidden in ("bangers", "comic", "barlow", "jetbrains", "#0b0614", "#7cff4f", "conic-gradient", "<script", "halftone", "box-shadow"):
        assert forbidden not in lowered, forbidden
    exported = client.post(f"/api/scans/{job_id}/export")
    assert exported.status_code == 202, exported.text
    downloaded = client.get(f"/api/scans/{job_id}/export/html")
    assert downloaded.status_code == 200 and "8. Fuera del alcance observable" in downloaded.text and "7. Registro de interacción" in downloaded.text and "<img src=x" not in downloaded.text
    masked = client.get(f"/api/scans/{job_id}/export/json").json()
    assert masked["masked"] is True and len(masked["story"]["steps"]) == 8


# --- Criterio 2: progreso real ---


def job_like(**values):
    return SimpleNamespace(**{"status": "queued", "analysis_status": None, "progress": None, "result": None, **values})


def test_scan_progress_only_reports_what_was_measured():
    now = datetime(2026, 10, 7, 12, 0, 30, tzinfo=timezone.utc)
    started = (now - timedelta(seconds=12.3)).isoformat()
    assert STAGES == ("queued", "opening", "capturing", "analyzing", "building", "done")
    assert scan_progress(job_like()) == {"stage": "queued", "failed_at": None, "requests": None, "capture_elapsed_s": None, "capture_max_s": None}
    opening = scan_progress(job_like(status="running", progress={"stage": "opening", "requests": None, "max_s": 60, "capture_started_at": None}), now)
    assert opening == {"stage": "opening", "failed_at": None, "requests": None, "capture_elapsed_s": None, "capture_max_s": 60}
    capturing = scan_progress(job_like(status="running", progress={"stage": "capturing", "requests": 37, "max_s": 60, "capture_started_at": started}), now)
    assert capturing == {"stage": "capturing", "failed_at": None, "requests": 37, "capture_elapsed_s": 12.3, "capture_max_s": 60}
    done_capture = {"capture": {"total_requests": 41, "duration_ms": 15400}}
    reported = {"stage": "analyzing", "requests": 41, "max_s": 60, "capture_started_at": started}
    assert scan_progress(job_like(status="completed", analysis_status="queued", progress=reported, result=done_capture))["stage"] == "analyzing"
    building = scan_progress(job_like(status="completed", analysis_status="running", progress={**reported, "stage": "building"}, result=done_capture))
    assert building == {"stage": "building", "failed_at": None, "requests": 41, "capture_elapsed_s": 15.4, "capture_max_s": 60}
    assert scan_progress(job_like(status="completed", analysis_status="completed", progress={**reported, "stage": "building"}, result=done_capture))["stage"] == "done"
    failed = scan_progress(job_like(status="failed", progress={"stage": "failed", "requests": None, "max_s": 60}))
    assert failed["stage"] == "failed" and failed["requests"] is None and failed["capture_elapsed_s"] is None
    assert scan_progress(job_like(status="completed", analysis_status="failed", progress=reported, result=done_capture))["stage"] == "failed"
    # Datos corruptos en progress: nunca un número inventado.
    odd = scan_progress(job_like(status="running", progress={"stage": "otra", "requests": "muchas", "max_s": "x", "capture_started_at": "ayer"}), now)
    assert odd == {"stage": "opening", "failed_at": None, "requests": None, "capture_elapsed_s": None, "capture_max_s": None}


def test_scan_endpoints_expose_progress(client, story_scan):
    job_id, _, _ = story_scan
    scan = client.get(f"/api/scans/{job_id}").json()
    assert scan["progress"] == {"stage": "done", "failed_at": None, "requests": 4, "capture_elapsed_s": 4.2, "capture_max_s": 60}
    listed = {item["job_id"]: item for item in client.get("/api/scans?limit=100").json()["items"]}
    assert listed[job_id]["stage"] == "done" and listed[job_id]["group_id"] is None
    created = client.post("/api/scans", json={"url": "https://example.com/"})
    assert created.status_code == 202 and created.json()["progress"]["stage"] in ("queued", "opening")
    try:
        queued = client.get(f"/api/scans/{created.json()['job_id']}").json()
        if queued["status"] == "queued":
            assert queued["progress"]["queue_position"] >= 1 and queued["progress"]["requests"] is None
    finally:
        async def cleanup():
            async with SessionLocal() as session:
                await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": uuid.UUID(created.json()["job_id"])})
                await session.commit()
        client.portal.call(cleanup)


# --- Criterio 1: borrar un scan y borrar todo ---


async def _make_scan(session, group_id=None, with_report=True) -> uuid.UUID:
    job_id = uuid.uuid4()
    session.add(Job(id=job_id, url="http://borrar.example/", status="completed", analysis_status="completed", result={"capture": {"truncated": False}}))
    await session.flush()
    if group_id is not None:
        await session.execute(text("UPDATE jobs SET group_id = :group WHERE id = :id"), {"group": group_id, "id": job_id})
    # Datos aleatorios: Postgres comprime lo repetitivo y lo que se mide es el tamaño guardado.
    request = _request(job_id, 0, post_data=secrets.token_hex(2000), post_data_encoding="utf8")
    session.add(request)
    await session.flush()
    session.add(RequestAnalysis(job_id=job_id, request_id=request.id, score=0, band="Bajo", category="first-party", mechanism="document",
                                entity="no_disponible", list_matches=[], reasons=[], analyzer_version="1.4.0"))
    await session.execute(text("INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version) VALUES (:job, 'x', 'EVIDENCIA', 'c', '[1]', '{}', '1.4.0')"), {"job": job_id})
    await session.execute(text("INSERT INTO scan_cookies (job_id, name, value, domain, path, http_only, secure, third_party) VALUES (:job, 'a', 'b', 'c', '/', false, false, false)"), {"job": job_id})
    if with_report:
        for kind in ("json", "html", "pdf"):
            await session.execute(
                text("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES ('scan', :id, :kind, false, 'x', 'ready', :data)"),
                {"id": job_id, "kind": kind, "data": os.urandom(2000)},
            )
    return job_id


async def _rows(session, job_id) -> dict:
    counts = {}
    for table in [*await history.job_tables(session)]:
        counts[table] = await session.scalar(text(f"SELECT count(*) FROM {table} WHERE job_id = :id"), {"id": job_id})
    counts["jobs"] = await session.scalar(text("SELECT count(*) FROM jobs WHERE id = :id"), {"id": job_id})
    counts["report_files"] = await session.scalar(text("SELECT count(*) FROM report_files WHERE subject_id = :id"), {"id": job_id})
    return counts


def test_job_tables_come_from_the_catalog_and_cover_every_scan_table(client):
    async def tables():
        async with SessionLocal() as session:
            return await history.job_tables(session)

    found = set(client.portal.call(tables))
    assert {"scan_requests", "scan_redirects", "scan_cookies", "scan_storage", "scan_websockets", "scan_ws_frames", "scan_destinations", "scan_cnames",
            "scan_artifacts", "fp_api_calls", "fp_findings", "fp_attributes", "request_analysis", "parameters", "decoded_values", "findings", "site_analysis"} <= found


def test_delete_one_scan_removes_its_data_and_reports_and_nothing_else(client):
    made = {}

    async def insert():
        async with SessionLocal() as session:
            made["target"] = await _make_scan(session)
            made["other"] = await _make_scan(session)
            await session.commit()

    async def rows(job_id):
        async with SessionLocal() as session:
            return await _rows(session, job_id)

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": list(made.values())})
            await session.commit()

    client.portal.call(insert)
    try:
        before = client.portal.call(rows, made["target"])
        assert before["jobs"] == 1 and before["scan_requests"] == 1 and before["request_analysis"] == 1 and before["findings"] == 1 and before["report_files"] == 3
        stats = client.get("/api/history").json()
        assert stats["delete_enabled"] is True and stats["confirmation"] == "BORRAR" and stats["scans"] >= 2 and stats["disk_bytes"] > 0
        response = client.delete(f"/api/scans/{made['target']}")
        assert response.status_code == 200, response.text
        deleted = response.json()["deleted"]
        # Cuántos scans y cuánto espacio: lo medido de las filas borradas (3 reportes de 2 KB + una request con cuerpo).
        assert deleted["scans"] == 1 and deleted["groups"] == 0 and deleted["reports"] == 3 and 6000 < deleted["bytes_freed"] < 200_000
        assert "backups/" in response.json()["note"]
        after = client.portal.call(rows, made["target"])
        assert set(after.values()) == {0}, after
        assert client.portal.call(rows, made["other"]) == before
        assert client.get(f"/api/scans/{made['target']}").status_code == 404
        assert client.get(f"/api/scans/{made['target']}/export/html").status_code == 404
        again = client.delete(f"/api/scans/{made['target']}")
        assert again.status_code == 404 and again.json()["error_code"] == "JOB_NOT_FOUND"
        assert client.delete("/api/scans/no-es-uuid").status_code == 422
        assert client.get("/api/history").json()["scans"] == stats["scans"] - 1
    finally:
        client.portal.call(cleanup)


def test_deleting_the_last_scan_of_a_privacy_test_removes_the_group_and_its_reports(client):
    group_id = uuid.uuid4()
    made = {}

    async def insert():
        async with SessionLocal() as session:
            await session.execute(text("INSERT INTO test_groups (id, url, config) VALUES (:id, 'http://borrar.example/', '{}')"), {"id": group_id})
            made["first"] = await _make_scan(session, group_id, with_report=False)
            made["second"] = await _make_scan(session, group_id, with_report=False)
            await session.execute(text("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES ('group', :id, 'json', false, 'x', 'ready', 'x')"), {"id": group_id})
            await session.commit()

    async def state():
        async with SessionLocal() as session:
            return (await session.scalar(text("SELECT count(*) FROM test_groups WHERE id = :id"), {"id": group_id}),
                    await session.scalar(text("SELECT count(*) FROM report_files WHERE subject_id = :id"), {"id": group_id}))

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM test_groups WHERE id = :id"), {"id": group_id})
            await session.commit()

    client.portal.call(insert)
    try:
        first = client.delete(f"/api/scans/{made['first']}").json()["deleted"]
        assert first["scans"] == 1 and first["groups"] == 0 and client.portal.call(state) == (1, 1)
        second = client.delete(f"/api/scans/{made['second']}").json()["deleted"]
        assert second == {"scans": 1, "groups": 1, "reports": 1, "bytes_freed": second["bytes_freed"]} and client.portal.call(state) == (0, 0)
    finally:
        client.portal.call(cleanup)


def test_delete_everything_requires_typing_the_confirmation(client):
    for body in (None, {}, {"confirm": ""}, {"confirm": "borrar"}, {"confirm": "BORRAR "}, {"confirm": "SI"}):
        response = client.request("DELETE", "/api/scans", json=body) if body is not None else client.delete("/api/scans")
        assert response.status_code == 400 and response.json()["error_code"] == "CONFIRMATION_REQUIRED", (body, response.text)
    assert client.request("DELETE", "/api/scans", json={"confirm": "BORRAR", "otro": 1}).status_code == 422
    assert client.get("/api/history").json()["scans"] >= 1  # nada se borró


@pytest.mark.needs_stack  # necesita scans reales producidos por el worker; se omite en CI.
def test_delete_everything_removes_all_scans_groups_and_reports(client):
    """Se ejecuta el borrado completo de verdad, dentro de una transacción que se revierte al final:
    así se comprueba contra la base real sin perder los datos del equipo."""
    group_id = uuid.uuid4()

    async def run():
        async with SessionLocal() as session:
            await session.execute(text("INSERT INTO test_groups (id, url, config) VALUES (:id, 'http://borrar.example/', '{}')"), {"id": group_id})
            await _make_scan(session, group_id)
            await _make_scan(session)
            await session.execute(text("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES ('group', :id, 'json', false, 'x', 'ready', 'x')"), {"id": group_id})
            await session.flush()
            before = await history.stats(session)
            result = await history.delete_all(session)
            after = await history.stats(session)
            left = {table: await session.scalar(text(f"SELECT count(*) FROM {table}")) for table in [*await history.job_tables(session), *history.EXTRA_TABLES]}
            heartbeats = await session.scalar(text("SELECT count(*) FROM worker_heartbeats"))
            await session.rollback()
            return before, result, after, left, heartbeats

    before, result, after, left, heartbeats = client.portal.call(run)
    assert before["scans"] >= 2 and before["groups"] >= 1 and before["reports"] >= 4
    assert result["scans"] == before["scans"] and result["groups"] == before["groups"] and result["reports"] == before["reports"]
    assert result["bytes_freed"] > 12_000
    assert (after["scans"], after["groups"], after["reports"]) == (0, 0, 0)
    assert set(left.values()) == {0}, left
    assert heartbeats >= 1  # lo que no es historial no se toca
    # La transacción se revirtió: el historial real sigue ahí.
    assert client.get("/api/history").json()["scans"] == before["scans"] - 2


def test_history_cannot_be_deleted_in_demo_mode(client, monkeypatch, scan):
    """403 en DEMO_MODE, para un scan y para todo; leer sigue permitido."""
    from app.routes import history as routes

    for mode in ("1", "exposure"):
        demo = Settings(postgres_user="u", postgres_password="p", postgres_db="d", demo_mode=mode)
        assert demo.demo is True
        monkeypatch.setattr(routes, "get_settings", lambda demo=demo: demo)
        one = client.delete(f"/api/scans/{scan}")
        everything = client.request("DELETE", "/api/scans", json={"confirm": "BORRAR"})
        for response in (one, everything):
            assert response.status_code == 403 and response.json()["error_code"] == "HISTORY_DELETE_DISABLED", response.text
        assert client.get("/api/history").json()["delete_enabled"] is False
    monkeypatch.undo()
    assert client.get(f"/api/scans/{scan}").status_code == 200  # el scan sigue ahí
    for mode in ("0", "", "false"):
        assert Settings(postgres_user="u", postgres_password="p", postgres_db="d", demo_mode=mode).demo is False
    assert get_settings().demo is False
