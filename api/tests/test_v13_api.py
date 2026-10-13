"""v1.3: terceros por organización en el resumen, importar/exportar HAR y comparar scan vs HAR."""

import json
import uuid

import pytest
from sqlalchemy import text

from app import har_import
from app.config import get_settings
from app.db import SessionLocal
from app.models import Job, RequestAnalysis
from app.report_html import executive_summary, render_scan_report
from app.routes.har import compare_sides
from tests import har_fixture
from tests.factories import _request

SITE = "http://tienda.example/"


# --- 1. Bug del resumen: «terceros» sale de request_analysis.party, no del dominio ---

@pytest.fixture(scope="module")
def party_scan(client):
    """6 requests: 1 propia, 3 a otro dominio del mismo dueño y 2 a otra organización."""
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url=SITE, status="completed", analysis_status="completed",
                            result={"final_url": SITE, "title": "Tienda", "http_status": 200, "capture": {"truncated": False}}))
            await session.flush()
            rows = [
                (0, "tienda.example", False, "first_party", "Tienda SA"),
                (1, "tienda-cdn.example", True, "same_org", "Tienda SA"),
                (2, "tienda-cdn.example", True, "same_org", "Tienda SA"),
                (3, "tienda-media.example", True, "same_org", "Tienda SA"),
                (4, "anuncios.example", True, "third_party", "Anuncios Corp"),
                (5, "medidor.example", True, "third_party", "no_disponible"),
            ]
            requests = [_request(job_id, seq, host=f"a.{domain}", registrable_domain=domain, third_party=third, url=f"http://a.{domain}/r{seq}")
                        for seq, domain, third, _, _ in rows]
            session.add_all(requests)
            await session.flush()
            session.add_all(
                RequestAnalysis(job_id=job_id, request_id=request.id, score=10, band="Bajo", category="third-party", mechanism="image",
                                entity=entity, list_matches=[], reasons=[], analyzer_version="1.7.0", party=party)
                for request, (_, _, _, party, entity) in zip(requests, rows)
            )
            await session.execute(
                text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                     "VALUES (:job, '1.7.0', 'abc', '[]', 10, 'Bajo', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 10)"),
                {"job": job_id, "summary": json.dumps({"trackers": 0, "third_party_domains": 2, "same_org_domains": 2})},
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
            await session.commit()

    client.portal.call(insert)
    yield str(job_id)
    client.portal.call(cleanup)


def test_report_counts_third_parties_by_organization_not_by_domain(client, party_scan):
    report = client.get(f"/api/scans/{party_scan}/report").json()
    # Por dominio serían 5 «terceros»; por organización son 2, y 3 de la misma organización.
    assert report["capture"] == {"total_requests": 6, "first_party": 1, "third_party": 2, "same_org": 3, "blocked": 0,
                                 "blocked_by_client": 0, "capture_truncated": False}
    parties = {domain["domain"]: (domain["party"], domain["third_party"]) for domain in report["destinations"]["domains"]}
    assert parties == {"tienda.example": ("first_party", False), "tienda-cdn.example": ("same_org", False),
                       "tienda-media.example": ("same_org", False), "anuncios.example": ("third_party", True),
                       "medidor.example": ("third_party", True)}
    assert client.get(f"/api/scans/{party_scan}").json()["summary"]["third_party"] == 2
    domains = {item["domain"]: item["party"] for item in client.get(f"/api/scans/{party_scan}/domains").json()["domains"]}
    assert domains["tienda-cdn.example"] == "same_org" and domains["anuncios.example"] == "third_party"


def test_executive_summary_and_html_use_the_party_counts(client, party_scan):
    report = client.get(f"/api/scans/{party_scan}/report").json()
    found = " ".join(executive_summary(report)["found"])
    assert "realizó 6 requests, de las cuales 2 se dirigieron a terceros (organizaciones distintas del sitio), distribuidas en 2 dominios de terceros." in found
    assert "Otras 3 requests se dirigieron a 2 dominios de la misma organización que el sitio; no se cuentan como terceros." in found
    html = render_scan_report(report, "0" * 64)
    assert "de las cuales 2 se dirigieron a terceros" in html and "5 se dirigieron a terceros" not in html
    row = html.split('<span class="mono">tienda-cdn.example</span>')[1].split("</tr>")[0]
    assert "misma organización" in row and ">tercero<" not in row


def test_requests_filter_and_items_follow_party(client, party_scan):
    third = client.get(f"/api/scans/{party_scan}/requests?third_party=true").json()
    assert third["total"] == 2 and {item["party"] for item in third["items"]} == {"third_party"}
    rest = client.get(f"/api/scans/{party_scan}/requests?third_party=false").json()
    assert rest["total"] == 4 and {item["party"] for item in rest["items"]} == {"first_party", "same_org"}


# --- 2. Importar HAR ---

def test_inspect_lists_loads_blocked_and_sensitive_headers_without_storing(client):
    response = client.post("/api/har/inspect", content=har_fixture.as_bytes())
    assert response.status_code == 200, response.text
    info = response.json()
    loads = {load["id"]: load for load in info["loads"]}
    assert set(loads) == {"time:0", "page:0", "page:1"} and info["default_load"] == "page:0"
    # 11 con pageref (la data: URL se ignora) + 1 sin pageref dentro de su ventana de tiempo.
    assert loads["page:0"]["requests"] == 12 and loads["page:0"]["blocked_by_client"] == 2 and loads["page:0"]["page_url"] == har_fixture.PAGE_URL
    assert loads["time:0"]["requests"] == 2 and loads["time:0"]["kind"] == "time" and loads["page:1"]["requests"] == 2
    assert info["entries_ignored"] == 1
    assert info["sensitive"] == {"cookie": 2, "set_cookie": 1, "authorization": 1, "cookie_objects": 1}
    assert "se descartan antes de guardar" in info["warnings"][0]
    assert info["notes"][0] == "Captura importada: navegador real del usuario." and "fingerprinting" in info["notes"][1]
    assert not any(secret in response.text for secret in har_fixture.SECRETS)


def test_import_discards_cookie_set_cookie_and_authorization_before_saving(client):
    response = client.post("/api/har/import?load=page:0&name=sintetico.har", content=har_fixture.as_bytes())
    assert response.status_code == 202, response.text
    body = response.json()
    job_id = body["job_id"]
    try:
        assert body["source"] == "har_import" and body["url"] == har_fixture.PAGE_URL
        assert body["import"]["sensitive_removed"] == {"cookie": 2, "set_cookie": 1, "authorization": 1, "cookie_objects": 1}
        assert body["import"]["blocked_by_client"] == 2 and body["import"]["entries_load"] == 12 and body["import"]["loads_in_file"] == 3

        async def stored():
            async with SessionLocal() as session:
                payload = (await session.execute(text("SELECT payload::text FROM har_imports WHERE job_id = :id"), {"id": job_id})).scalar_one_or_none()
                result = (await session.execute(text("SELECT result::text FROM jobs WHERE id = :id"), {"id": job_id})).scalar_one()
                rows = (await session.execute(text("SELECT request_headers::text || COALESCE(response_headers::text, '') FROM scan_requests WHERE job_id = :id"), {"id": job_id})).scalars().all()
                return payload, result, rows

        payload, result, rows = client.portal.call(stored)
        # El worker puede haberlo tomado ya: lo guardado es o el staging o la captura, nunca los secretos.
        everything = (payload or "") + (result or "") + "".join(rows)
        assert everything and not any(secret in everything for secret in har_fixture.SECRETS)
        assert "CUERPO-DE-RESPUESTA-NO-SE-GUARDA" not in everything
        if payload is not None:
            entries = json.loads(payload)["entries"]
            document = entries[0]
            assert document["request_headers"][0] == {"name": "Cookie", "value": "", "redacted": True, "length": len(har_fixture.SECRET_COOKIE)}
            assert document["response_headers"][0] == {"name": "Set-Cookie", "value": "", "redacted": True, "length": len(har_fixture.SECRET_SET_COOKIE)}
            authorization = next(h for h in entries[2]["request_headers"] if h["name"] == "Authorization")
            assert authorization == {"name": "Authorization", "value": "", "redacted": True, "length": len(har_fixture.SECRET_AUTH)}
            assert [entry["error"] for entry in entries].count("net::ERR_BLOCKED_BY_CLIENT") == 2
    finally:
        client.portal.call(_delete, job_id)


async def _delete(job_id):
    async with SessionLocal() as session:
        await session.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
        await session.commit()


def test_build_import_is_text_only_and_bounded():
    document = har_fixture.build()
    document["log"]["entries"][2]["request"]["headers"].append({"name": "X-Largo", "value": "a" * 50000})
    document["log"]["entries"][2]["request"]["headers"].append({"name": {"no": "texto"}, "value": ["lista"]})
    document["log"]["entries"][3]["request"]["url"] = "javascript:alert(1)"
    imported = har_import.build_import(json.dumps(document).encode(), "page:0", "x" * 500)
    assert len(imported["meta"]["file_name"]) == 200 and imported["meta"]["entries_load"] == 11
    headers = imported["entries"][0]["request_headers"]
    assert max(len(header["value"]) for header in headers) == har_import.MAX_HEADER_VALUE_CHARS and all(isinstance(header["name"], str) for header in headers)
    assert all(entry["url"].startswith("https://") for entry in imported["entries"])
    # El payload XSS se conserva como texto (dato no confiable), nunca se interpreta.
    assert imported["entries"][0]["response_headers"][1] == {"name": "X-Demo", "value": har_fixture.XSS}


@pytest.mark.parametrize("raw, code, status", [
    (b"esto no es json", "HAR_INVALID", 400),
    (b'{"log": {"entries": "no"}}', "HAR_INVALID", 400),
    (b'{"log": {"entries": []}}', "HAR_INVALID", 400),
    (b'[1, 2, 3]', "HAR_INVALID", 400),
    (json.dumps({"log": {"entries": [{"request": {"url": "ftp://x/", "method": "GET"}, "startedDateTime": "2026-01-01T00:00:00Z"}]}}).encode(), "HAR_INVALID", 400),
])
def test_invalid_har_is_rejected(client, raw, code, status):
    for path in ("/api/har/inspect", "/api/har/import"):
        response = client.post(path, content=raw)
        assert response.status_code == status and response.json()["error_code"] == code, response.text


def test_unknown_load_and_oversized_file_are_rejected(client, monkeypatch):
    response = client.post("/api/har/import?load=page:99", content=har_fixture.as_bytes())
    assert response.status_code == 400 and response.json()["error_code"] == "HAR_INVALID"
    assert get_settings().har_max_bytes == 50 * 1024 * 1024
    monkeypatch.setattr(get_settings(), "har_max_bytes", 1000)
    for path in ("/api/har/inspect", "/api/har/import"):
        response = client.post(path, content=har_fixture.as_bytes())
        assert response.status_code == 413 and response.json()["error_code"] == "HAR_TOO_LARGE", response.text


# --- 3. Exportar HAR ---

def test_export_har_omits_cookies_and_authorization_by_default(client, scan):
    job_id = scan if isinstance(scan, str) else scan[0]

    async def add_sensitive():
        async with SessionLocal() as session:
            await session.execute(
                text("UPDATE scan_requests SET request_headers = CAST(:req AS jsonb), response_headers = CAST(:res AS jsonb) WHERE job_id = :id AND seq = 0"),
                {"id": job_id, "req": json.dumps([{"name": "Cookie", "value": "sid=SECRETO-EXPORT"}, {"name": "Authorization", "value": "Bearer SECRETO-EXPORT"},
                                                  {"name": "Accept", "value": "*/*"}]),
                 "res": json.dumps([{"name": "Set-Cookie", "value": "a=SECRETO-EXPORT"}, {"name": "Content-Type", "value": "text/html"}])},
            )
            await session.commit()

    client.portal.call(add_sensitive)
    response = client.get(f"/api/scans/{job_id}/har")
    assert response.status_code == 200 and "attachment" in response.headers["content-disposition"] and ".har" in response.headers["content-disposition"]
    assert "SECRETO-EXPORT" not in response.text
    log = response.json()["log"]
    assert log["version"] == "1.2" and log["pages"][0]["id"] == "page_1" and "sin las cabeceras Cookie" in log["comment"]
    first = log["entries"][0]
    assert [header["name"] for header in first["request"]["headers"]] == ["Accept"]
    assert [header["name"] for header in first["response"]["headers"]] == ["Content-Type"]
    assert first["request"]["cookies"] == [] and first["pageref"] == "page_1" and first["request"]["method"] and first["startedDateTime"]
    # El HAR exportado se puede volver a importar.
    assert har_import.inspect(response.content)["loads"][0]["requests"] == len(log["entries"])
    explicit = client.get(f"/api/scans/{job_id}/har?include_sensitive=true")
    assert "SECRETO-EXPORT" in explicit.text


# --- 4. Comparar ---

def _side(source, organizations, wave):
    return {"job_id": "x", "url": SITE, "source": source, "analyzer_version": "1.7.0", "finished_at": None, "requests": 10,
            "import": {"blocked_by_client": 3} if source == "har_import" else None, "sync_wave": wave,
            "organizations": {name: {"requests": requests, "blocked": blocked, "domains": [name.lower()]} for name, requests, blocked in organizations}}


WAVE = {"available": True, "detected": True, "requests": 17, "organizations": 13, "initiator": "gum.socio.example", "domains": []}
NO_WAVE = {"available": True, "detected": False, "requests": 0, "organizations": 0, "initiator": None, "domains": []}


def test_compare_lists_organizations_wave_and_blocked_with_one_line_conclusion():
    scan = _side("scan", [("Google", 5, 0), ("Solo Scan", 1, 0)], NO_WAVE)
    har = _side("har_import", [("Google", 4, 0), ("Criteo", 6, 1), ("Taboola", 2, 2)], WAVE)
    result = compare_sides(scan, har)
    assert [item["organization"] for item in result["organizations"]["only_har"]] == ["Criteo", "Taboola"]
    assert [item["organization"] for item in result["organizations"]["only_scan"]] == ["Solo Scan"] and result["organizations"]["both"] == ["Google"]
    assert result["sync_wave"]["state"] == "only_har"
    assert result["blocked_by_extension"]["requests"] == 3 and [item["organization"] for item in result["blocked_by_extension"]["organizations"]] == ["Taboola", "Criteo"]
    conclusion = result["conclusion"]
    assert conclusion["level"] == "EVIDENCIA" and "\n" not in conclusion["text"]
    assert conclusion["text"] == (
        "El navegador real recibió una ola de sincronización (17 requests a 13 organizaciones, iniciada por gum.socio.example) que el scan "
        "automatizado no observó; 2 organizaciones aparecen solo en el HAR y 1 solo en el scan. Una extensión del navegador bloqueó 3 requests en el HAR."
    )


def test_compare_does_not_invent_a_missing_wave_measurement():
    result = compare_sides(_side("scan", [], None), _side("har_import", [], WAVE))
    assert result["sync_wave"]["state"] == "unknown" and result["conclusion"]["level"] == "DESCONOCIDO"
    assert compare_sides(_side("scan", [], NO_WAVE), _side("har_import", [], NO_WAVE))["sync_wave"]["state"] == "none"


def test_compare_endpoint_needs_one_scan_and_one_har(client, scan, party_scan):
    job_id = scan if isinstance(scan, str) else scan[0]
    response = client.get(f"/api/scans/{job_id}/compare/{party_scan}")
    assert response.status_code == 400 and response.json()["error_code"] == "COMPARE_NEEDS_SCAN_AND_HAR"
    candidates = client.get(f"/api/scans/{party_scan}/compare-candidates").json()
    assert candidates["source"] == "scan" and all(item["source"] == "har_import" for item in candidates["candidates"])
