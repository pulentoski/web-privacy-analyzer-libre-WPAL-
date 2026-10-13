"""Privacy Test (F7): agregación pura y validación de los endpoints."""

import uuid

import pytest
from sqlalchemy import delete, text

from app.config import get_settings
from app.db import SessionLocal
from app.models import Job
from app.privacy import build_result, stats
from app.ratelimit import SlidingWindowLimiter

URL = "http://site.fixtures.test/"  # fixture local: si el worker llega a tomar un job, no sale a internet


def job(job_id, scenario="sin_interaccion", profile="real", run=1, consent=None, profile_info=None, status="completed"):
    return {"job_id": job_id, "scenario": scenario, "profile": profile, "run": run, "status": status,
            "analysis_status": "completed" if status == "completed" else None, "consent": consent, "profile_info": profile_info}


def tracker(job_id, seq, domain, path="/t.gif", entity="no_disponible"):
    return {"job_id": job_id, "request_id": hash((job_id, seq)) % 10000, "seq": seq, "host": f"t.{domain}", "path": path, "domain": domain, "entity": entity}


def counts(*job_ids, requests=10, domains=2):
    return {job_id: {"requests": requests, "third_party_domains": domains} for job_id in job_ids}


def test_stats():
    assert stats([409, 765, 414]) == {"median": 414, "min": 409, "max": 765, "values": [409, 765, 414]}
    assert stats([]) is None


def test_stability_is_k_of_n_per_group():
    jobs = [job("a1"), job("a2", run=2), job("a3", run=3)]
    rows = [tracker("a1", 1, "siempre.example"), tracker("a2", 1, "siempre.example"), tracker("a3", 1, "siempre.example"),
            tracker("a1", 2, "aveces.example"), tracker("a1", 3, "aveces.example"), tracker("a3", 2, "una.example")]
    result = build_result(jobs, {"a1": {"requests": 10, "third_party_domains": 3}, "a2": {"requests": 30, "third_party_domains": 1},
                                 "a3": {"requests": 20, "third_party_domains": 2}}, rows, [])
    cell = result["cells"][0]
    assert (cell["runs"], cell["completed"]) == (3, 3)
    assert cell["requests"] == {"median": 20, "min": 10, "max": 30, "values": [10, 30, 20]}
    assert cell["tracker_requests"]["values"] == [3, 1, 2]
    stability = {d["domain"]: (d["appeared"], d["of"]) for d in cell["tracker_domains"]}
    assert stability == {"siempre.example": (3, 3), "aveces.example": (1, 3), "una.example": (1, 3)}
    assert result["tracker_differences"] == []  # un solo grupo: nada que comparar


def test_failed_runs_do_not_count_in_the_denominator():
    jobs = [job("a1"), job("a2", run=2, status="failed")]
    cell = build_result(jobs, counts("a1", "a2"), [tracker("a1", 1, "x.example")], [])["cells"][0]
    assert (cell["runs"], cell["completed"]) == (2, 1)
    assert cell["tracker_domains"][0]["appeared"] == 1 and cell["tracker_domains"][0]["of"] == 1


def test_tracker_differences_between_groups_carry_stability():
    jobs = [job("r1"), job("r2", run=2), job("w1", profile="windows-chrome-es-cl"), job("w2", profile="windows-chrome-es-cl", run=2)]
    rows = [tracker("r1", 1, "ambos.example"), tracker("r2", 1, "ambos.example"), tracker("w1", 1, "ambos.example"), tracker("w2", 1, "ambos.example"),
            tracker("w1", 2, "solo-windows.example"), tracker("r1", 2, "inestable.example"), tracker("w2", 2, "inestable.example")]
    result = build_result(jobs, counts("r1", "r2", "w1", "w2"), rows, [])
    differences = {d["domain"]: d["by_cell"] for d in result["tracker_differences"]}
    assert "ambos.example" not in differences
    assert differences["solo-windows.example"] == {"sin_interaccion|real": {"appeared": 0, "of": 2}, "sin_interaccion|windows-chrome-es-cl": {"appeared": 1, "of": 2}}
    assert "inestable.example" not in differences  # 1/2 en ambos grupos: no hay diferencia que mostrar


def consent(status, interaction_seq=None, verified=None, detected=True):
    return {"scenario": "x", "status": status, "banner_detected": detected, "cmp_name": "OneTrust", "interaction_seq": interaction_seq,
            "verified": verified, "state": {"verified_by": "tcf"}, "has_banner_image": detected, "reason": None}


def test_consent_findings():
    jobs = [job("s", "sin_interaccion", consent=consent("sin_interaccion")),
            job("a", "aceptar", consent=consent("aceptado", 5, True)), job("r", "rechazar", consent=consent("rechazado", 5, True))]
    rows = [tracker("s", 1, "t.example", "/pre.gif"), tracker("a", 1, "t.example", "/pre.gif"), tracker("a", 6, "t.example", "/accept-only.gif"),
            tracker("a", 7, "t.example", "/ignores.gif"), tracker("r", 1, "t.example", "/pre.gif"), tracker("r", 6, "t.example", "/ignores.gif")]
    result = build_result(jobs, counts("s", "a", "r"), rows, [])["consent"]
    findings = result["findings"]
    assert result["cmp"] == "OneTrust" and result["banner_job_id"] == "s" and result["not_applicable"] is False
    pre = {i["resource"]: (i["runs"], i["of"]) for i in findings["pre_consent"]["items"]}
    assert pre == {"t.t.example/pre.gif": (3, 3)}
    post = findings["post_reject"]
    assert [i["resource"] for i in post["items"]] == ["t.t.example/ignores.gif"] and post["verified_runs"] == 1
    assert post["items"][0]["evidence"][0]["job_id"] == "r"
    assert [i["resource"] for i in findings["only_after_accept"]["items"]] == ["t.t.example/accept-only.gif"]
    assert all(f["level"] == "EVIDENCIA" for f in findings.values())
    assert "No es un juicio" in result["note"]


def test_unrecognized_banner_gives_no_findings():
    jobs = [job("s", "rechazar", consent={**consent("no_aplicable", detected=False), "reason": "No se reconoció"})]
    result = build_result(jobs, counts("s"), [tracker("s", 1, "t.example")], [])["consent"]
    assert result["not_applicable"] is True and result["banner_detected_runs"] == 0
    assert all(f["items"] == [] for f in result["findings"].values())
    assert result["scenarios"][0]["status"] == "no_aplicable"


def info(platform, renderer="GPU real", canvas="aaa", inconsistencies=None):
    return {"label": platform, "declared_coherent": True, "inconsistencies": inconsistencies or [],
            "js": {"user_agent": f"UA {platform}", "platform": platform, "languages": ["es-CL"], "timezone": "UTC", "screen": [1920, 1080],
                   "device_pixel_ratio": 1, "max_touch_points": 0, "hardware_concurrency": 8, "device_memory": None,
                   "webgl_vendor": "V", "webgl_renderer": renderer, "canvas_hash": canvas, "ua_ch": {"platform": platform}},
            "headers": {"user-agent": f"UA {platform}", "accept-language": "es-CL", "sec-ch-ua-platform": f'"{platform}"'}}


def test_real_vs_profile_table():
    windows = info("Windows", renderer="Direct3D11")
    windows["js"]["device_memory"] = 8
    jobs = [job("r", profile_info=info("Linux")), job("w", profile="windows-chrome-es-cl", profile_info=windows)]
    profiles = build_result(jobs, counts("r", "w"), [], [])["profiles"]
    rows = {row["attribute"]: row for row in profiles["attributes"]}
    name = "windows-chrome-es-cl"
    assert rows["platform"]["real"] == "Linux" and rows["platform"]["values"][name] == "Windows" and rows["platform"]["status"][name] == "CAMBIO"
    assert rows["timezone"]["status"][name] == "PERMANECIO" and rows["timezone"]["potentially_identifying"] == []
    assert rows["device_memory"]["status"][name] == "NUEVO"
    # La huella de canvas no cambió: sigue sirviendo para reconocer el equipo. La IP nunca cambia.
    assert rows["canvas_hash"]["status"][name] == "PERMANECIO" and rows["canvas_hash"]["potentially_identifying"] == [name]
    assert rows["ip"]["not_modifiable"] is True and rows["ip"]["potentially_identifying"] == [name]
    summary = profiles["summary"][name]
    assert "navigator.platform" in summary["changed"] and "Huella de canvas" in summary["potentially_identifying"]
    assert "Dirección IP" in summary["potentially_identifying"] and "Memoria del dispositivo" in summary["new"]
    assert "ningún perfil la cambia" in profiles["ip_note"] and profiles["has_real_reference"] is True


def ident(job_id, value, domain="tracker.example", name="fpid"):
    return {"job_id": job_id, "request_id": 1, "domain": domain, "name": name, "value": value, "entity": "Tracker SA"}


def test_persistent_id_same_in_clean_runs_and_changes_with_profile():
    jobs = [job("r1"), job("r2", run=2), job("w1", profile="windows-chrome-es-cl"), job("w2", profile="windows-chrome-es-cl", run=2)]
    rows = [ident("r1", "aaaaaaaa11111111-99999999ipipipip"), ident("r2", "aaaaaaaa11111111-99999999ipipipip"),
            ident("w1", "bbbbbbbb22222222-99999999ipipipip"), ident("w2", "bbbbbbbb22222222-99999999ipipipip"),
            ident("r1", "sesion-aleatoria-1", name="sid"), ident("r2", "sesion-aleatoria-2", name="sid"),
            ident("r1", "clave-del-sitio-123456", name="key"), ident("r2", "clave-del-sitio-123456", name="key"),
            ident("w1", "clave-del-sitio-123456", name="key"), ident("w2", "clave-del-sitio-123456", name="key")]
    result = build_result(jobs, counts("r1", "r2", "w1", "w2"), [], rows)["persistent_ids"]
    by_key = {(i["parameter"], i["profile"]): i for i in result["items"]}
    assert ("sid", "real") not in by_key  # cambia en cada corrida: no es persistente
    fpid = by_key[("fpid", "real")]
    assert fpid["level"] == "EVIDENCIA" and (fpid["same_in_runs"], fpid["of_runs"]) == (2, 2)
    assert "2 de 2 corridas con contextos nuevos" in fpid["claim"] and "aaaaaaaa11111111-99999999ipipipip" not in fpid["claim"]
    assert fpid["across_profiles"][0]["result"] == "CAMBIA_EN_PARTE" and fpid["changes_with_profile"] is True
    assert fpid["across_profiles"][0]["kept_parts"] and "IP" in fpid["inference"] and fpid["inference_level"] == "INFERENCIA"
    key = by_key[("key", "real")]
    assert key["across_profiles"][0]["result"] == "SE_MANTIENE" and "constante del sitio" in key["inference"]
    # Primero los que cambian con el perfil: son los que dependen de la huella.
    assert result["items"][0]["parameter"] == "fpid" and result["comparable_profiles"] == ["real", "windows-chrome-es-cl"]


def test_persistent_ids_need_two_runs_of_the_same_profile():
    jobs = [job("r1"), job("w1", profile="windows-chrome-es-cl")]
    result = build_result(jobs, counts("r1", "w1"), [], [ident("r1", "aaaaaaaa11111111"), ident("w1", "aaaaaaaa11111111")])["persistent_ids"]
    assert result["items"] == [] and result["comparable_profiles"] == [] and "al menos 2 corridas" in result["note"]


def test_no_text_claims_anonymity():
    jobs = [job("r", profile_info=info("Linux")), job("w", profile="windows-chrome-es-cl", profile_info=info("Windows")), job("r2", run=2)]
    dumped = str(build_result(jobs, counts("r", "w", "r2"), [], [ident("r", "aaaaaaaa11111111"), ident("r2", "aaaaaaaa11111111")])).lower()
    for word in ("anónimo", "anonimo", "anonimato", "oculto", "oculta", "invisible", "indetectable"):
        assert word not in dumped


# --- Endpoints ---


@pytest.fixture
def cleanup(client):
    groups: list[str] = []
    yield groups

    async def remove():
        async with SessionLocal() as session:
            for group_id in groups:
                await session.execute(text("DELETE FROM test_groups WHERE id = :id"), {"id": uuid.UUID(group_id)})
            await session.commit()

    client.portal.call(remove)


def test_profiles_endpoint(client):
    body = client.get("/api/privacy/profiles").json()
    names = [p["name"] for p in body["profiles"]]
    assert names[0] == "real" and {"windows-chrome-es-cl", "macos-chrome-es-cl", "android-chrome-es-cl", "incoherente-demo"} <= set(names)
    assert {p["name"]: p["coherent"] for p in body["profiles"]}["incoherente-demo"] is False
    assert "No cambia la dirección IP" in body["note"]


def test_create_group_counts_every_run_for_the_rate_limit(client, cleanup, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_rate_limit", 7)
    body = {"url": URL, "scenarios": ["sin_interaccion", "rechazar"], "profiles": ["real", "windows-chrome-es-cl"], "runs": 1}
    created = client.post("/api/privacy/test", json=body)
    assert created.status_code == 202, created.text
    data = created.json()
    cleanup.append(data["group_id"])
    assert data["total"] == 4 and data["status"] == "running"
    # Quedan 3 de cupo: un grupo de 4 no cabe, y no se crea ninguna de sus corridas.
    second = client.post("/api/privacy/test", json=body)
    assert second.status_code == 429 and second.json()["error_code"] == "RATE_LIMITED" and second.json()["details"]["requested"] == 4
    state = client.get(f"/api/privacy/test/{data['group_id']}").json()
    assert state["progress"]["total"] == 4 and state["result"] is None or state["status"] == "completed"
    assert sorted((j["scenario"], j["profile"]) for j in state["jobs"]) == sorted(
        (s, p) for s in body["scenarios"] for p in body["profiles"])
    # Un scan suelto sí cabe todavía (3 libres).
    single = client.post("/api/scans", json={"url": URL})
    assert single.status_code == 202

    async def remove_single():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == uuid.UUID(single.json()["job_id"])))
            await session.commit()

    client.portal.call(remove_single)


def test_check_many_is_all_or_nothing():
    limiter = SlidingWindowLimiter()
    assert limiter.check_many("ip", 6, 10, 60) is None
    assert limiter.check_many("ip", 5, 10, 60) > 0  # 6 + 5 > 10: no se cuenta ninguna
    assert limiter.check_many("ip", 4, 10, 60) is None
    assert limiter.check("ip", 10, 60) > 0
    assert limiter.check_many("otra", 11, 10, 60) == 60.0  # nunca cabría


@pytest.mark.parametrize(
    "body, code, error",
    [
        ({"url": URL, "profiles": ["no-existe"]}, 400, "UNKNOWN_PROFILE"),
        ({"url": URL, "profiles": ["../../etc/passwd"]}, 400, "UNKNOWN_PROFILE"),
        ({"url": URL, "scenarios": ["sin_interaccion", "aceptar", "rechazar"], "profiles": ["real", "windows-chrome-es-cl"], "runs": 2}, 400, "GROUP_TOO_LARGE"),
        ({"url": "http://127.0.0.1/"}, 400, "IP_FORBIDDEN"),
        ({"url": URL, "runs": 6}, 422, "REQUEST_INVALID"),
        ({"url": URL, "runs": 0}, 422, "REQUEST_INVALID"),
        ({"url": URL, "scenarios": ["adivinar"]}, 422, "REQUEST_INVALID"),
        ({"url": URL, "scenarios": []}, 422, "REQUEST_INVALID"),
        ({"url": URL, "extra": 1}, 422, "REQUEST_INVALID"),
    ],
)
def test_create_group_validation(client, body, code, error):
    response = client.post("/api/privacy/test", json=body)
    assert response.status_code == code and response.json()["error_code"] == error


def test_unknown_group_and_artifact(client):
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/privacy/test/{missing}").json()["error_code"] == "TEST_NOT_FOUND"
    assert client.get(f"/api/privacy/artifacts/{missing}/consent_banner").json()["error_code"] == "ARTIFACT_NOT_FOUND"
    assert client.get(f"/api/privacy/artifacts/{missing}/otra_cosa").status_code == 422
