"""v1.5.2: comparación de visitas (creación, validez, clasificación y textos del reporte)."""

import json
import uuid

import pytest
from sqlalchemy import select, text

from app import comparison
from app.config import get_settings
from app.db import SessionLocal
from app.models import Job
from tests.factories import _request

URL = "https://example.com/"


def obs(**kinds):
    """Observaciones de una visita a partir de {kind: {contexto: {valor: meta}}} parciales."""
    out = {kind: {} for kind in comparison.KINDS}
    for kind, contexts in kinds.items():
        for context, values in contexts.items():
            out[kind][context] = {value: {"session": False, "identifier_like": False, **meta} for value, meta in values.items()}
    return out


UID_A, UID_B = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", "0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e"
COOKIE = ("site.example", "/", "uid")


def classified(v1, v2, v3, reveal=True):
    return comparison.classify({1: v1, 2: v2, 3: v3}, comparison.load_constants(get_settings().data_dir), reveal=reveal)


def test_same_value_in_1_and_2_and_different_in_3_is_persistent_with_the_fixed_text():
    result = classified(obs(cookies={COOKIE: {UID_A: {}}}), obs(cookies={COOKIE: {UID_A: {}}}), obs(cookies={COOKIE: {UID_B: {}}}))
    persistent = result["classes"]["persistent"]
    assert persistent["text"] == ("se observó un identificador persistente entre dos visitas con el mismo perfil; "
                                  "el perfil limpio de control mostró un resultado distinto")
    assert persistent["total"] == 1
    item = persistent["items"][0]
    assert item["kind"] == "cookies" and item["context"] == {"domain": "site.example", "path": "/", "name": "uid"}
    assert item["value"] == UID_A and item["visits"] == {"1": "observado", "2": "observado", "3": "valor distinto"}
    # El valor de B no es persistente: solo lo vio el perfil limpio de control.
    assert result["classes"]["clean_only"]["total"] == 1


def test_absent_in_control_is_never_said_to_not_exist():
    result = classified(obs(cookies={COOKIE: {UID_A: {}}}), obs(cookies={COOKIE: {UID_A: {}}}), obs())
    item = result["classes"]["persistent"]["items"][0]
    assert item["visits"]["3"] == "no observado en esta captura" == comparison.ABSENT_TEXT
    assert "no existe" not in json.dumps(result, ensure_ascii=False)


def test_static_session_constant_and_non_identifier_values_are_discarded():
    same = {COOKIE: {UID_A: {}}}
    session = {("site.example", "/", "sess"): {UID_A: {"session": True}}}
    constant = {("site.example", "/", "x-gtm"): {"GTM-ABC1234": {}}}  # cabecera con un ID de contenedor de Google
    word = {("site.example", "/", "x-mode"): {"oscuro": {}}}
    result = classified(obs(cookies={**same, **session}, headers={**constant, **word}),
                        obs(cookies={**same, **session}, headers={**constant, **word}), obs(cookies=same))
    assert result["classes"]["persistent"]["total"] == 0
    assert {name: item["total"] for name, item in result["discarded"].items()} == {
        "static": 1, "session": 1, "constant": 1, "not_identifier": 1, "varies": 0}


def test_only_in_visit_2_needs_the_clean_profiles_to_agree_or_lack_the_field():
    context = ("tracker.example", "/px", "query", "seg")
    new_field = classified(obs(), obs(url={context: {"vuelve": {}}}), obs())
    assert new_field["classes"]["only_visit_2"]["total"] == 1
    assert new_field["classes"]["only_visit_2"]["text"] == "cambio observado en el perfil persistente que no apareció en los perfiles limpios"
    agree = classified(obs(url={context: {"nuevo": {}}}), obs(url={context: {"vuelve": {}}}), obs(url={context: {"nuevo": {}}}))
    assert agree["classes"]["only_visit_2"]["total"] == 1
    # Un valor distinto en cada visita (marca de tiempo, nonce) no es un cambio del perfil.
    varies = classified(obs(url={context: {"1": {}}}), obs(url={context: {"2": {}}}), obs(url={context: {"3": {}}}))
    assert varies["classes"]["only_visit_2"]["total"] == 0 and varies["discarded"]["varies"]["total"] == 1


def test_seen_in_2_and_3_is_also_observed_in_the_control_without_cause():
    context = ("site.example", "/", "query", "campaign")
    result = classified(obs(url={context: {"inicio": {}}}), obs(url={context: {"rotada": {}}}), obs(url={context: {"rotada": {}}}))
    item = result["classes"]["also_control"]
    assert item["text"] == "también observado en el control" and item["total"] == 1
    assert item["items"][0]["visits"] == {"1": "valor distinto", "2": "observado", "3": "observado"}


def test_presence_kinds_compare_contexts_not_values():
    request = ("GET", "site.example", "/v152/welcome-back.gif")
    result = classified(obs(), obs(requests={request: {None: {}}}), obs())
    assert result["classes"]["only_visit_2"]["items"][0]["context"] == {"method": "GET", "host": "site.example", "path": "/v152/welcome-back.gif"}
    both_a = classified(obs(organizations={("Tracker Corp",): {None: {}}}), obs(organizations={("Tracker Corp",): {None: {}}}), obs())
    assert both_a["classes"]["profile_a"]["total"] == 1 and both_a["classes"]["persistent"]["total"] == 0
    assert comparison.generic_path("/sync/a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e/x") == "/sync/:id/x"


def test_values_are_masked_unless_revealed():
    data = (obs(cookies={COOKIE: {UID_A: {}}}), obs(cookies={COOKIE: {UID_A: {}}}), obs())
    masked = classified(*data, reveal=False)["classes"]["persistent"]["items"][0]["value"]
    assert masked != UID_A and UID_A not in masked
    assert classified(*data, reveal=True)["classes"]["persistent"]["items"][0]["value"] == UID_A


def test_observations_take_exact_values_in_their_context():
    data = {
        "requests": [{"method": "GET", "host": "t.example", "path": "/px", "request_headers": [
            {"name": "X-Id", "value": UID_A}, {"name": "Cookie", "value": f"uid={UID_A}"}, {"name": "Accept", "value": "*/*"},
            {"name": "Sec-Fetch-Dest", "value": "image"}, {"name": "Proxy-Authorization", "value": "Basic c2Nhbi0xOnNlY3JldG8="}]}],
        "cookies": [{"name": "uid", "value": UID_A, "domain": ".site.example", "path": "/", "expires": 2e9},
                    {"name": "s", "value": "v", "domain": ".site.example", "path": "/", "expires": -1}],
        "storage": [{"origin": "http://site.example", "storage_type": "local", "key": "k", "value": UID_A}],
        "parameters": [
            {"source": "query", "name": "uid", "value": UID_A, "identifier_like": True, "host": "t.example", "path": "/px"},
            {"source": "post_body_decoded", "name": "id", "value": UID_A, "identifier_like": True, "host": "t.example", "path": "/c"},
            {"source": "cookie", "name": "s", "value": "v", "identifier_like": False, "host": "site.example", "path": "/"},
        ],
        "organizations": ["Tracker Corp"], "destinations": ["t.example"],
    }
    found = comparison.observations(data)
    # Solo las cabeceras que pone el sitio: ni Cookie (se compara aparte), ni las del navegador, ni las del proxy.
    assert found["headers"] == {("t.example", "/px", "x-id"): {UID_A: {"session": False, "identifier_like": False}}}
    assert found["url"][("t.example", "/px", "query", "uid")][UID_A]["identifier_like"] is True
    assert ("t.example", "/c", "post_body_decoded", "id") in found["bodies"]
    assert found["cookies"][(".site.example", "/", "s")]["v"]["session"] is True
    # La cookie de sesión también es de sesión cuando viaja en la cabecera Cookie.
    assert found["cookie_identifiers"][("site.example", "cookie", "s")]["v"]["session"] is True


def visits_state(**overrides):
    state = {
        "1": {"start": {"dir_existed": False, "files_before_launch": 0, "cookies_read": True, "cookies_at_start": 0},
              "closed_at": "2026-10-18T10:00:00.000+00:00", "conditions": {"url": URL, "browser_version": "153", "egress_country": "CL"}},
        "2": {"start": {"manifest_matches": True, "cookies_read": True, "persistent_cookies_missing": 0},
              "launched_at": "2026-10-18T10:05:02.500+00:00", "conditions": {"url": URL, "browser_version": "153", "egress_country": "CL"}},
        "3": {"start": {"dir_existed": False, "files_before_launch": 0, "separate_from_a": True, "cookies_read": True, "cookies_at_start": 0},
              "conditions": {"url": URL, "browser_version": "153", "egress_country": "AR"}},
    }
    for key, value in overrides.items():
        visit, field = key.split("_", 1)
        state[visit]["start"][field] = value
    return state


DONE = {visit: {"status": "completed", "analysis_status": "completed", "pending": False, "error": None} for visit in (1, 2, 3)}


def test_validity_requires_kept_state_and_clean_profiles():
    assert comparison.validity(DONE, visits_state()) == {"status": "valida", "valid": True, "reasons": []}
    lost = comparison.validity(DONE, visits_state(**{"2_persistent_cookies_missing": 2}))
    assert lost["status"] == "no_valida" and "Se perdió el estado del perfil A" in lost["reasons"][0]
    changed = comparison.validity(DONE, visits_state(**{"2_manifest_matches": False, "2_manifest_changed_count": 3}))
    assert changed["valid"] is False and "cambió entre las visitas 1 y 2" in changed["reasons"][0]
    dirty_b = comparison.validity(DONE, visits_state(**{"3_cookies_at_start": 1}))
    assert dirty_b["reasons"] == ["El perfil de la visita 3 tenía cookies antes de navegar."]
    failed = {**DONE, 2: {"status": "failed", "analysis_status": None, "pending": False, "error": {"error_code": "COMPARISON_STATE_LOST"}},
              3: {"status": "failed", "analysis_status": None, "pending": False, "error": {"error_code": "COMPARISON_ABORTED"}}}
    assert comparison.validity(failed, visits_state())["reasons"][:2] == [
        "Se perdió el estado del perfil A: su directorio no estaba al empezar la visita 2.",
        "La visita 3 no se hizo porque falló una visita anterior."]
    running = {**DONE, 3: {"status": "queued", "analysis_status": None, "pending": True, "error": None}}
    assert comparison.validity(running, visits_state())["status"] == "en_curso"
    assert comparison.validity({1: DONE[1], 2: DONE[2]}, visits_state())["status"] == "no_valida"


def test_interval_and_condition_differences_are_recorded():
    state = visits_state()
    assert comparison.interval({"interval_s": 300}, state) == {"configured_s": 300, "real_s": 302.5}
    assert comparison.condition_differences(state) == [
        {"condition": "egress_country", "label": "País de la IP de salida", "values": {"1": "CL", "2": "CL", "3": "AR"}}]


@pytest.fixture
def cleanup(client):
    ids: list[str] = []
    yield ids

    async def purge():
        async with SessionLocal() as session:
            for comparison_id in ids:
                await session.execute(text("DELETE FROM visit_comparisons WHERE id = :id"), {"id": uuid.UUID(comparison_id)})
            await session.commit()

    client.portal.call(purge)


def test_create_queues_three_single_attempt_visits(client, cleanup):
    response = client.post("/api/comparisons", json={"url": URL})
    assert response.status_code == 202, response.text
    body = response.json()
    cleanup.append(body["comparison_id"])
    assert body["config"] == {"interval_s": 300}  # VISIT_COMPARISON_INTERVAL_S por defecto

    async def rows():
        async with SessionLocal() as session:
            return (await session.execute(text(
                "SELECT options, max_attempts, not_before IS NULL AS free, not_before = 'infinity'::timestamptz AS blocked "
                "FROM jobs WHERE comparison_id = :id ORDER BY (options->'comparison'->>'visit')::int"), {"id": uuid.UUID(body["comparison_id"])})).mappings().all()

    jobs = client.portal.call(rows)
    assert [job["options"]["comparison"]["visit"] for job in jobs] == [1, 2, 3]
    assert [job["options"]["comparison"]["profile"] for job in jobs] == ["A", "A", "B"]
    assert all(job["max_attempts"] == 1 for job in jobs)
    assert [job["free"] for job in jobs] == [True, False, False] and [job["blocked"] for job in jobs] == [None, True, True]
    detail = client.get(f"/api/comparisons/{body['comparison_id']}").json()
    assert detail["status"] == "en_curso" and detail["result"] is None
    assert detail["warning"].startswith("Tres visitas no prueban causalidad.")
    assert [visit["label"] for visit in detail["visits"]] == [
        "Perfil A limpio", "Perfil A persistente (mismo perfil, tras el intervalo)", "Perfil B limpio de control"]
    listed = client.get("/api/comparisons").json()["items"]
    assert any(item["comparison_id"] == body["comparison_id"] for item in listed)


def test_create_validates_interval_and_counts_three_scans(client, cleanup, monkeypatch):
    for bad in (-1, 86_401, "5", 1.5):
        assert client.post("/api/comparisons", json={"url": URL, "interval_s": bad}).status_code == 422
    assert client.post("/api/comparisons", json={"url": URL, "otra": 1}).status_code == 422
    monkeypatch.setattr(get_settings(), "scan_rate_limit", 4)
    first = client.post("/api/comparisons", json={"url": URL, "interval_s": 0})
    assert first.status_code == 202 and first.json()["config"] == {"interval_s": 0}
    cleanup.append(first.json()["comparison_id"])
    second = client.post("/api/comparisons", json={"url": URL})
    assert second.status_code == 429 and second.json()["details"]["requested"] == 3
    assert client.get(f"/api/comparisons/{uuid.uuid4()}").status_code == 404


def insert_finished_comparison(client, values: dict[int, str]) -> str:
    """Comparación terminada con una cookie y un parámetro por visita (sin pasar por el worker)."""
    comparison_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            await session.execute(text(
                "INSERT INTO visit_comparisons (id, url, config, state) VALUES (:id, :url, CAST(:config AS jsonb), CAST(:state AS jsonb))"),
                {"id": comparison_id, "url": URL, "config": json.dumps({"interval_s": 300}), "state": json.dumps({"visits": visits_state()})})
            for visit, value in values.items():
                job = Job(url=URL, status="completed", analysis_status="completed", result={"capture": {"total_requests": 1}},
                          options={"comparison": {"id": str(comparison_id), "visit": visit, "profile": "AAB"[visit - 1]}})
                session.add(job)
                await session.flush()
                await session.execute(text("UPDATE jobs SET comparison_id = :c, max_attempts = 1 WHERE id = :id"), {"c": comparison_id, "id": job.id})
                session.add(_request(job.id, 0, host="t.example", path="/px", registrable_domain="example"))
                await session.flush()
                request_id = (await session.execute(text("SELECT id FROM scan_requests WHERE job_id = :j"), {"j": job.id})).scalar_one()
                await session.execute(text(
                    "INSERT INTO scan_cookies (job_id, name, value, domain, path, expires, http_only, secure, same_site, third_party) "
                    "VALUES (:j, 'uid', :v, 'site.example', '/', 2000000000, false, false, 'Lax', false)"), {"j": job.id, "v": value})
                await session.execute(text(
                    "INSERT INTO parameters (job_id, request_id, source, name, value, value_truncated, category, shapes, length, entropy, "
                    "identifier_like, encoding_chain) VALUES (:j, :r, 'query', 'uid', :v, false, 'identity', '[]', 32, 4.0, true, '[]')"),
                    {"j": job.id, "r": request_id, "v": value})
            await session.commit()

    client.portal.call(insert)
    return str(comparison_id)


def test_finished_comparison_reports_classes_masked_by_default(client, cleanup):
    comparison_id = insert_finished_comparison(client, {1: UID_A, 2: UID_A, 3: UID_B})
    cleanup.append(comparison_id)
    body = client.get(f"/api/comparisons/{comparison_id}").json()
    assert body["status"] == "valida" and body["interval"] == {"configured_s": 300, "real_s": 302.5}
    persistent = body["result"]["classes"]["persistent"]
    assert persistent["total"] == 2 and {item["kind"] for item in persistent["items"]} == {"cookies", "url"}
    assert UID_A not in json.dumps(body) and body["revealed"] is False
    revealed = client.get(f"/api/comparisons/{comparison_id}", params={"reveal": "true"}).json()
    assert {item["value"] for item in revealed["result"]["classes"]["persistent"]["items"]} == {UID_A}
    assert revealed["condition_differences"][0]["condition"] == "egress_country"
    assert revealed["profiles"]["2"]["start"]["manifest_matches"] is True


def test_comparison_visits_stay_out_of_the_panel(client, cleanup):
    """La visita 2 no es un perfil limpio: ninguna visita de una comparación entra en el Panel. Un scan suelto, sí."""
    comparison_id = insert_finished_comparison(client, {1: UID_A, 2: UID_A, 3: UID_B})
    cleanup.append(comparison_id)
    control = uuid.uuid4()

    async def analyze():
        async with SessionLocal() as session:
            session.add(Job(id=control, url="https://panel-control.example/", status="completed", analysis_status="completed"))
            await session.flush()
            ids = (await session.execute(text("SELECT id FROM jobs WHERE comparison_id = :c"), {"c": uuid.UUID(comparison_id)})).scalars().all()
            for job_id in [*ids, control]:
                await session.execute(text(
                    "INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, "
                    "mechanisms, summary, partial, duration_ms) VALUES (:j, 'test', 'test', '[]', 100, 'Muy alto', '{}', '{}', '{}', "
                    "'{\"requests\": 1}', false, 1)"), {"j": job_id})
            await session.commit()
            return [str(job_id) for job_id in ids]

    visit_ids = client.portal.call(analyze)
    try:
        panel = json.dumps(client.get("/api/panel", params={"include_tests": "true"}).json())
        assert str(control) in panel
        assert not any(job_id in panel for job_id in visit_ids)
    finally:
        async def drop():
            async with SessionLocal() as session:
                await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": control})
                await session.commit()

        client.portal.call(drop)
