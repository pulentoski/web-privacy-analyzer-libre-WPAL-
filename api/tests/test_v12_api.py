"""v1.2: URL de entrada limpia, IDs de cuenta del sitio, Panel, Historial, tabla de atributos y conclusión."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.db import SessionLocal
from app.privacy import build_result, failures
from app.report_html import DEFAULT_BRAND_NAME, load_brand
from app.url_cleaning import TRACKING_PARAMS, clean_url, describe, inspect, is_tracking_param

SITE = "http://site.fixtures.test/"  # fixture local: si el worker toma el job, no sale a internet


# --- 7a. Parámetros de seguimiento en la URL de entrada ---


@pytest.mark.parametrize("name", ["gclid", "gclsrc", "gbraid", "wbraid", "dclid", "fbclid", "msclkid", "ttclid", "yclid", "_gl", "mc_eid",
                                  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "UTM_Source", "GCLID"])
def test_every_listed_tracking_parameter_is_removed(name):
    cleaned, removed = clean_url(f"https://tienda.example/p?id=7&{name}=abc123&q=zapatos")
    assert cleaned == "https://tienda.example/p?id=7&q=zapatos" and removed == [name.lower()]


@pytest.mark.parametrize("url", [
    "https://tienda.example/", "https://tienda.example/p?id=7&q=a%20b", "https://tienda.example/p?gclidx=1&myutm_source=2&glid=3",
    "https://tienda.example/p?ref=gclid", "no es una url", "https://tienda.example/p#utm_source=x",
])
def test_urls_without_tracking_parameters_are_returned_untouched(url):
    assert clean_url(url) == (url, [])


@pytest.mark.parametrize("name", [
    "gad_source", "gad_campaignid", "srsltid", "spm", "scm", "igshid", "si", "_hsenc", "_hsmi",
    "mkt_tok", "oly_anon_id", "oly_enc_id", "rb_clickid", "s_cid", "vero_id", "wickedid", "ref_src",
])
def test_tracking_params_added_in_v121_are_recognized(name):
    """v1.2.1 (point 4): la lista vive en data/tracking_params.yaml y suma estos parámetros."""
    assert name in TRACKING_PARAMS
    assert is_tracking_param(name) and is_tracking_param(name.upper())
    cleaned, removed = clean_url(f"https://tienda.example/p?keep=1&{name}=x")
    assert cleaned == "https://tienda.example/p?keep=1" and removed == [name]


def test_the_rest_of_the_url_is_kept_byte_for_byte():
    """Caso real: una URL de anuncio. Salen los de seguimiento (gclsrc, gad_source, gbraid, gclid); lo demás no se reordena ni se recodifica."""
    original = ("https://www.airbnb.cl/?c=.pi0.pk243051560_18108098960&gclsrc=aw.ds&&c=.pi0.pk243051560_18108098960"
                "&localized_ghost=true&gad_source=1&gbraid=0AAAAADz55Lm&gclid=CjwKCAjw_BwE#seccion")
    cleaned, removed = clean_url(original)
    # gad_source es parámetro de seguimiento desde v1.2.1 (data/tracking_params.yaml): también se quita.
    assert cleaned == "https://www.airbnb.cl/?c=.pi0.pk243051560_18108098960&c=.pi0.pk243051560_18108098960&localized_ghost=true#seccion"
    assert removed == ["gclsrc", "gad_source", "gbraid", "gclid"]
    assert clean_url("https://a.example/p?utm_source=x&utm_source=y&fbclid=1") == ("https://a.example/p", ["utm_source", "fbclid"])
    assert describe(cleaned, original) == {"original_url": original, "url_cleaned": True, "removed_params": removed}
    assert describe(cleaned, None) == {"original_url": cleaned, "url_cleaned": False, "removed_params": []}


def test_inspect_endpoint_reports_without_validating_or_scanning(client):
    body = client.post("/api/scans/inspect-url", json={"url": "  https://tienda.example/p?a=1&fbclid=XYZ&utm_medium=cpc "}).json()
    assert body == {"url": "https://tienda.example/p?a=1&fbclid=XYZ&utm_medium=cpc", "cleaned_url": "https://tienda.example/p?a=1",
                    "tracking_params": ["fbclid", "utm_medium"], "has_tracking_params": True}
    assert inspect("https://tienda.example/")["has_tracking_params"] is False
    assert client.post("/api/scans/inspect-url", json={}).status_code == 422 or client.post("/api/scans/inspect-url", json={}).status_code == 400


async def _delete_jobs(ids):
    async with SessionLocal() as session:
        await session.execute(text("DELETE FROM jobs WHERE id = ANY(:ids)"), {"ids": ids})
        await session.commit()


def test_scan_is_created_with_the_clean_url_and_keeps_the_original(client):
    dirty = f"{SITE}?page=2&gclid=abc&utm_source=news"
    created = []
    try:
        default = client.post("/api/scans", json={"url": dirty})
        assert default.status_code == 202, default.text
        body = default.json()
        created.append(uuid.UUID(body["job_id"]))
        assert body["url"] == f"{SITE}?page=2" and body["original_url"] == dirty
        assert body["url_cleaned"] is True and body["removed_params"] == ["gclid", "utm_source"]
        # Se guardaron las dos: el detalle y el listado las devuelven.
        detail = client.get(f"/api/scans/{body['job_id']}").json()
        assert (detail["url"], detail["original_url"], detail["removed_params"]) == (f"{SITE}?page=2", dirty, ["gclid", "utm_source"])
        listed = next(item for item in client.get("/api/scans?limit=50").json()["items"] if item["job_id"] == body["job_id"])
        assert listed["original_url"] == dirty and listed["url_cleaned"] is True and listed["is_test"] is True

        kept = client.post("/api/scans", json={"url": dirty, "clean_url": False}).json()
        created.append(uuid.UUID(kept["job_id"]))
        assert kept["url"] == dirty and kept["original_url"] == dirty and kept["url_cleaned"] is False and kept["removed_params"] == []

        plain = client.post("/api/scans", json={"url": SITE}).json()
        created.append(uuid.UUID(plain["job_id"]))
        assert plain["url"] == SITE and plain["url_cleaned"] is False
        assert client.post("/api/scans", json={"url": dirty, "clean_url": "si"}).status_code in (400, 422)
    finally:
        client.portal.call(_delete_jobs, created)


def test_group_is_created_with_the_clean_url_and_keeps_the_original(client):
    dirty = f"{SITE}?fbclid=abc&x=1"
    body = client.post("/api/privacy/test", json={"url": dirty, "runs": 1}).json()
    group_id = uuid.UUID(body["group_id"])

    async def remove():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM test_groups WHERE id = :id"), {"id": group_id})
            await session.commit()

    try:
        assert body["url"] == f"{SITE}?x=1" and body["original_url"] == dirty and body["removed_params"] == ["fbclid"]
        loaded = client.get(f"/api/privacy/test/{group_id}").json()
        assert loaded["url"] == f"{SITE}?x=1" and loaded["original_url"] == dirty and loaded["url_cleaned"] is True
        listed = next(item for item in client.get("/api/privacy/tests?limit=200").json()["items"] if item["group_id"] == str(group_id))
        assert listed["original_url"] == dirty and listed["total"] == 1 and listed["status"] in ("active", "done", "failed")
    finally:
        client.portal.call(remove)


# --- 3. Historial: filtros ---


@pytest.fixture
def history_rows(client):
    tag = uuid.uuid4().hex[:10]
    old = datetime(2020, 3, 15, 12, 0, tzinfo=timezone.utc)
    rows = {
        "done": (uuid.uuid4(), f"https://www.tienda-{tag}.cl/a_b%c", "completed", "completed", old),
        "failed": (uuid.uuid4(), f"https://www.tienda-{tag}.cl/falla", "failed", None, old + timedelta(days=1)),
        "other": (uuid.uuid4(), f"https://www.otro-{tag}.cl/", "completed", "completed", old + timedelta(days=40)),
    }

    async def insert():
        async with SessionLocal() as session:
            for job_id, url, status, analysis, created in rows.values():
                await session.execute(
                    text("INSERT INTO jobs (id, url, status, analysis_status, created_at, error) VALUES (:id, :url, :status, :analysis, :created, CAST(:error AS jsonb))"),
                    {"id": job_id, "url": url, "status": status, "analysis": analysis, "created": created,
                     "error": json.dumps({"error_code": "NAVIGATION_TIMEOUT", "message": "tardó"}) if status == "failed" else None},
                )
            await session.commit()

    client.portal.call(insert)
    yield tag, {kind: str(row[0]) for kind, row in rows.items()}
    client.portal.call(_delete_jobs, [row[0] for row in rows.values()])


def test_history_filters_by_site_status_and_date(client, history_rows):
    tag, ids = history_rows

    def found(query):
        body = client.get(f"/api/scans?limit=200&{query}")
        assert body.status_code == 200, body.text
        return {item["job_id"] for item in body.json()["items"]} & set(ids.values()), body.json()["total"]

    assert found(f"site=tienda-{tag}")[0] == {ids["done"], ids["failed"]}
    assert found(f"site=TIENDA-{tag}")[0] == {ids["done"], ids["failed"]}, "sin distinguir mayúsculas"
    assert found(f"site={tag}&status=failed") == ({ids["failed"]}, 1)
    assert found(f"site={tag}&status=done") == ({ids["done"], ids["other"]}, 2)
    assert found(f"site={tag}&status=active") == (set(), 0)
    assert found(f"site={tag}&date_from=2020-03-16&date_to=2020-03-16") == ({ids["failed"]}, 1)
    assert found(f"site={tag}&date_from=2020-03-17")[0] == {ids["other"]}
    assert found(f"site={tag}&date_to=2020-03-15")[0] == {ids["done"]}
    # El texto del filtro es literal: % y _ no son comodines.
    assert found(f"site=tienda-{tag}.cl/a_b%25c")[0] == {ids["done"]}
    assert found(f"site=tienda-{tag}.cl/a%25")[0] == set()
    assert found(f"site=tienda-{tag}_cl")[0] == set()
    assert client.get("/api/scans?status=cualquiera").status_code in (400, 422)
    assert client.get("/api/scans?date_from=ayer").status_code in (400, 422)
    failed = next(item for item in client.get(f"/api/scans?limit=200&site={tag}&status=failed").json()["items"])
    assert failed["error_code"] == "NAVIGATION_TIMEOUT" and failed["is_test"] is False


# --- 2. Panel ---


@pytest.fixture
def panel_rows(client):
    """Dos sitios reales (uno escaneado dos veces) y un scan de fixtures, con análisis y fingerprinting."""
    tag = uuid.uuid4().hex[:10]
    org = f"Org {tag}"
    now = datetime.now(timezone.utc)
    jobs = {
        "a_old": (uuid.uuid4(), f"https://www.alfa-{tag}.cl/viejo", now - timedelta(days=2), 90, [org, f"Solo vieja {tag}"]),
        "a_new": (uuid.uuid4(), f"https://alfa-{tag}.cl/", now - timedelta(days=1), 55, [org]),
        "b": (uuid.uuid4(), f"https://beta-{tag}.cl/", now, 72, [org, f"Solo beta {tag}"]),
        "fixture": (uuid.uuid4(), "http://site.fixtures.test/fp/", now, 99, [f"Fixture {tag}"]),
    }

    async def insert():
        async with SessionLocal() as session:
            for job_id, url, created, score, entities in jobs.values():
                await session.execute(text("INSERT INTO jobs (id, url, status, analysis_status, created_at) VALUES (:id, :url, 'completed', 'completed', :created)"),
                                      {"id": job_id, "url": url, "created": created})
                summary = {"requests": 100, "trackers": 7, "third_party_domains": 5,
                           "entities": [{"entity": name, "requests": 10, "domains": ["x.example"], "max_score": 80} for name in entities]
                           + [{"entity": "no_disponible", "requests": 3, "domains": ["y.example"], "max_score": 0}]}
                await session.execute(
                    text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                         "VALUES (:id, 'test', 'test', '[]', :score, 'Alto', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 1)"),
                    {"id": job_id, "score": score, "summary": json.dumps(summary)},
                )
                await session.execute(
                    text("INSERT INTO fp_attributes (job_id, attribute, status, value, scripts, call_refs, request_refs) "
                         "VALUES (:id, 'canvas', 'UTILIZADO', NULL, CAST(:scripts AS jsonb), '[11]', '[]')"),
                    {"id": job_id, "scripts": json.dumps([f"https://cdn.lector-{tag}.net/fp.js"])},
                )
                await session.execute(
                    text("INSERT INTO fp_findings (job_id, script_url, heuristic, level, claim, call_refs, request_refs, details, analyzer_version) "
                         "VALUES (:id, 'https://cdn.invalid/fp.js', 'exfiltration', 'EVIDENCIA', 'claim', '[11]', '[]', CAST(:details AS jsonb), 'test')"),
                    {"id": job_id, "details": json.dumps({"api": "navigator.userAgent", "domain": f"receptor-{tag}.net"})},
                )
            await session.commit()

    client.portal.call(insert)
    yield tag, org, {kind: str(row[0]) for kind, row in jobs.items()}
    client.portal.call(_delete_jobs, [row[0] for row in jobs.values()])


def test_panel_counts_each_site_once_and_excludes_fixtures(client, panel_rows):
    tag, org, ids = panel_rows
    body = client.get("/api/panel").json()
    assert body["level"] == "EVIDENCIA" and "más reciente de cada sitio" in body["basis"]
    totals = body["totals"]
    assert totals["sites"] >= 2 and totals["scans"] >= 3 and totals["organizations"] >= 2 and totals["requests"] >= 200
    ranking = {item["site"]: item for item in body["ranking"]}
    # alfa: «www.» no hace otro sitio, y vale su scan más reciente (55), no el más antiguo (90).
    alfa = ranking.get(f"alfa-{tag}.cl")
    if alfa is not None:  # con muchos sitios reales guardados puede quedar fuera del top
        assert alfa["job_id"] == ids["a_new"] and alfa["site_exposure_score"] == 55
    assert not [site for site in ranking if site.endswith("fixtures.test")]
    scores = [item["site_exposure_score"] for item in body["ranking"]]
    assert scores == sorted(scores, reverse=True)
    names = [item["entity"] for item in body["organizations"]]
    assert f"Fixture {tag}" not in names and f"Solo vieja {tag}" not in names and "no_disponible" not in names
    for item in body["organizations"]:
        assert 1 <= item["sites"] <= item["of"] == totals["sites"]
    mine = next((item for item in body["organizations"] if item["entity"] == org), None)
    if mine is not None:
        assert mine["sites"] == 2 and mine["requests"] == 20
    read = {item["attribute"]: item for item in body["attributes"]["read"]}
    sent = {item["attribute"]: item for item in body["attributes"]["sent"]}
    # Con otros scans reales guardados, canvas o user_agent pueden quedar fuera del top: si están, cuentan estos dos sitios.
    assert "canvas" not in read or (read["canvas"]["sites"] >= 2 and read["canvas"]["of"] == totals["sites"])
    assert "user_agent" not in sent or sent["user_agent"]["sites"] >= 2
    assert all(1 <= item["sites"] <= item["of"] for item in list(read.values()) + list(sent.values()))
    assert read or sent


def test_panel_only_shows_fixture_scans_when_the_test_stack_asks_for_them(client, panel_rows, monkeypatch):
    tag, _, ids = panel_rows
    from app.config import get_settings

    def fixture_in(body):
        return any(item["job_id"] == ids["fixture"] for item in body["ranking"]) or any(item["entity"] == f"Fixture {tag}" for item in body["organizations"])

    monkeypatch.setattr(get_settings(), "allow_fixtures", True)
    assert fixture_in(client.get("/api/panel?include_tests=true").json())
    assert not fixture_in(client.get("/api/panel").json())
    # En una instalación normal el parámetro no hace nada.
    monkeypatch.setattr(get_settings(), "allow_fixtures", False)
    assert not fixture_in(client.get("/api/panel?include_tests=true").json())


# --- 4 y 5. Atributos leídos y enviados por el sitio de UN scan ---


def test_fingerprinting_table_and_scan_usage_for_one_scan(client, panel_rows):
    tag, _, ids = panel_rows
    body = client.get(f"/api/scans/{ids['b']}/fingerprinting").json()
    rows = {row["attribute"]: row for row in body["browser_attributes"]}
    assert set(rows) == {"canvas", "user_agent"}
    reader = rows["canvas"]["read_by"][0]
    assert reader["script_url"] == f"https://cdn.lector-{tag}.net/fp.js" and reader["call_ref"] == 11
    assert reader["organization"] == "no_disponible" and reader["is_entity"] is False, "sin request del script no se inventa organización"
    assert rows["canvas"]["sent_to"] == [] and rows["user_agent"]["read_by"] == []
    assert rows["user_agent"]["sent_to"] == [{"organization": f"receptor-{tag}.net", "is_entity": False, "domain": f"receptor-{tag}.net",
                                              "request_ref": None, "level": "EVIDENCIA"}]
    # Los atributos enviados van primero.
    assert [row["attribute"] for row in body["browser_attributes"]] == ["user_agent", "canvas"]

    # «Comparar con un scan»: mismo cruce, solo de ese scan (también si es de fixtures: se eligió a mano).
    usage = client.get(f"/api/exposure/scan-usage?job_id={ids['fixture']}").json()
    assert usage["job_id"] == ids["fixture"] and usage["excludes"] is None
    assert [item["label"] for item in usage["attributes"]["user_agent"]["sent"]] == [f"receptor-{tag}.net"]
    examples = {item["example"]["job_id"] for entry in usage["attributes"].values() for item in entry["read"] + entry["sent"]}
    assert examples == {ids["fixture"]}
    assert client.get("/api/exposure/scan-usage?job_id=no-es-uuid").status_code in (400, 422)
    assert client.get(f"/api/exposure/scan-usage?job_id={uuid.uuid4()}").json()["attributes"] == {}


# --- 7b y 8. Opciones avanzadas: IDs de cuenta, conclusión y motivos de fallo ---


def job(job_id, scenario="sin_interaccion", profile="real", run=1, consent=None, status="completed", error=None):
    return {"job_id": job_id, "scenario": scenario, "profile": profile, "run": run, "status": status,
            "analysis_status": "completed" if status == "completed" else None, "consent": consent, "profile_info": None,
            "error_code": (error or (None, None))[0], "error_message": (error or (None, None))[1]}


def tracker(job_id, seq, domain, entity="no_disponible"):
    return {"job_id": job_id, "request_id": seq, "seq": seq, "host": f"t.{domain}", "path": "/t.gif", "domain": domain, "entity": entity}


def counts(*job_ids):
    return {job_id: {"requests": 10, "third_party_domains": 2} for job_id in job_ids}


def consent(status, interaction_seq=None, detected=True):
    return {"banner_detected": detected, "cmp_name": "CMP de prueba" if detected else None, "status": status,
            "interaction_seq": interaction_seq, "verified": True if interaction_seq else None, "state": {}}


def ident(job_id, value, name="fpid"):
    return {"job_id": job_id, "request_id": 1, "domain": "tracker.example", "name": name, "value": value, "entity": None}


def test_site_account_ids_are_not_persistent_identifiers():
    jobs = [job("a", run=1), job("b", run=2)]
    pixel = {"rule": "meta_pixel_id", "vendor": "Meta", "label": "ID del pixel", "value": "123456789012345", "level": "INFERENCIA", "evidence_refs": [1]}
    rows = [ident("a", "123456789012345", "id"), ident("b", "123456789012345", "id"), ident("a", "visitante-9f8e7d6c5b4a"), ident("b", "visitante-9f8e7d6c5b4a")]
    result = build_result(jobs, counts("a", "b"), [], rows, {"a": [pixel], "b": [pixel]})
    persistent = result["persistent_ids"]
    assert [item["parameter"] for item in persistent["items"]] == ["fpid"] and persistent["account_ids_excluded"] == 1
    assert result["account_ids"] == [{"rule": "meta_pixel_id", "vendor": "Meta", "label": "ID del pixel", "value": "123456789012345"}]
    # Control: sin la lista de IDs de cuenta, el pixel sí aparece como valor repetido.
    control = build_result(jobs, counts("a", "b"), [], rows)
    assert sorted(item["parameter"] for item in control["persistent_ids"]["items"]) == ["fpid", "id"]
    assert control["persistent_ids"]["account_ids_excluded"] == 0 and control["account_ids"] == []


def test_conclusion_when_rejecting_uses_the_measured_figures():
    jobs = [job("acc", "aceptar", consent=consent("aceptado", 2)), job("rej", "rechazar", consent=consent("rechazado", 2))]
    trackers = [tracker("acc", seq, "ads.example", "Ads Corp") for seq in range(3, 50)] \
        + [tracker("rej", seq, "ads.example", "Ads Corp") for seq in range(3, 9)] \
        + [tracker("rej", seq, "metrics.example", "Metrics Inc") for seq in range(9, 13)] \
        + [tracker("rej", 13, "sin-dueno.example"), tracker("rej", 14, "sin-dueno.example")]
    conclusion = build_result(jobs, counts("acc", "rej"), trackers, [])["conclusion"]
    assert conclusion["text"] == "Al rechazar: 47 → 12 requests de rastreo; 3 organizaciones siguieron recibiendo datos."
    assert conclusion["level"] == "EVIDENCIA" and conclusion["kind"] == "rechazo"
    assert conclusion["data"] == {"baseline": "aceptar", "before": 47, "after": 12, "organizations": 3}


def test_conclusion_singular_and_zero_recipients():
    jobs = [job("base", "sin_interaccion", consent=consent("sin_interaccion")), job("rej", "rechazar", consent=consent("rechazado", 5))]
    one = build_result(jobs, counts("base", "rej"), [tracker("base", 1, "ads.example"), tracker("base", 2, "ads.example"), tracker("rej", 7, "ads.example")], [])["conclusion"]
    assert one["text"] == "Al rechazar: 2 → 1 requests de rastreo; 1 organización siguió recibiendo datos."
    none = build_result(jobs, counts("base", "rej"), [tracker("base", 1, "ads.example")], [])["conclusion"]
    assert none["text"] == "Al rechazar: 1 → 0 requests de rastreo; ninguna organización siguió recibiendo datos."


def test_conclusion_when_the_banner_was_not_recognised():
    unknown = consent("no_aplicable", detected=False)
    jobs = [job("a", "aceptar", consent=unknown), job("r", "rechazar", consent=unknown)]
    conclusion = build_result(jobs, counts("a", "r"), [tracker("a", 1, "ads.example")], [])["conclusion"]
    assert conclusion["text"] == "Banner no reconocido: los escenarios fueron equivalentes." and conclusion["level"] == "EVIDENCIA"


def test_conclusion_without_consent_scenarios_and_without_results():
    plain = build_result([job("a", run=1), job("b", run=2)], counts("a", "b"), [tracker("a", 1, "ads.example"), tracker("b", 1, "ads.example")], [])["conclusion"]
    assert plain["text"] == "1 requests de rastreo por visita (mediana de 2 corridas)." and plain["kind"] == "medicion"
    profiles = build_result([job("a"), job("b", profile="windows-chrome-es-cl")], counts("a", "b"), [tracker("a", 1, "ads.example")], [])["conclusion"]
    assert profiles["text"] == "Con 2 perfiles: entre 0 y 1 requests de rastreo por visita; la IP no cambió."
    failed = [job("a", status="failed", error=("NAVIGATION_TIMEOUT", "tardó"))]
    nothing = build_result(failed, counts("a"), [], [])["conclusion"]
    assert nothing["level"] == "DESCONOCIDO" and "Ningún scan terminó" in nothing["text"]
    for text_ in (plain["text"], profiles["text"], nothing["text"]):
        assert "\n" not in text_ and len(text_) < 140, "una sola línea"


def test_failed_scans_are_grouped_with_their_reason_in_the_summary_table():
    jobs = [
        job("ok"), job("t1", run=2, status="failed", error=("NAVIGATION_TIMEOUT", "La página tardó demasiado.")),
        job("t2", run=3, status="failed", error=("NAVIGATION_TIMEOUT", "La página tardó demasiado.")),
        job("e1", "rechazar", status="failed", error=("EGRESS_BLOCKED", "Destino bloqueado.")),
        {**job("an", "rechazar", run=2), "analysis_status": "failed"},
    ]
    result = build_result(jobs, counts("ok", "t1", "t2", "e1", "an"), [], [])
    assert [(item["error_code"], item["count"]) for item in result["failures"]] == [("NAVIGATION_TIMEOUT", 2), ("ANALYSIS_FAILED", 1), ("EGRESS_BLOCKED", 1)]
    assert result["failures"][0]["message"] == "La página tardó demasiado." and result["failures"][0]["job_ids"] == ["t1", "t2"]
    cells = {cell["key"]: cell for cell in result["cells"]}
    assert [(item["error_code"], item["count"]) for item in cells["sin_interaccion|real"]["failures"]] == [("NAVIGATION_TIMEOUT", 2)]
    assert {item["error_code"] for item in cells["rechazar|real"]["failures"]} == {"EGRESS_BLOCKED", "ANALYSIS_FAILED"}
    assert failures([job("ok")]) == []
    # Un fallo sin código no se inventa: queda como no_disponible.
    assert failures([job("x", status="failed")])[0]["error_code"] == "no_disponible"


# --- 10. Logo en los reportes ---


def test_reports_carry_the_project_logo_unless_a_brand_is_configured(tmp_path):
    default = load_brand("", str(tmp_path))
    assert default.name == DEFAULT_BRAND_NAME and default.logo_data_uri.startswith("data:image/png;base64,iVBOR")
    assert load_brand("", "") == default
    custom = load_brand("Consultora Ñandú", str(tmp_path))
    assert custom.name == "Consultora Ñandú" and custom.logo_data_uri == "", "REPORT_BRAND_NAME reemplaza la marca por defecto"
