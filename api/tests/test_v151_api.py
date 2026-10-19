"""v1.5.1: enmascarado del detalle de request y marca de la organización («LinkedIn (Microsoft)»)."""

import json
import uuid

import pytest
from sqlalchemy import delete, text

from app import brands
from app.db import SessionLocal
from app.masking import mask_identifiers
from app.models import Job, RequestAnalysis, ScanRedirect
from tests.factories import _request
from tests.test_analysis_api import VERSION

ID = "5f0c3e9a7b1d4c2e8f6a0b9c3d7e1f42"
EMAIL = "juan.perez@example.com"
MASKED_ID = "5f0c…[32 caracteres]"


@pytest.mark.parametrize("value, expected", [
    (f"li_sugr={ID}; lang=v=2&lang=es-cl", f"li_sugr={MASKED_ID}; lang=v=2&lang=es-cl"),
    ("_ga=GA1.2.242234892.1792082466", "_ga=GA1.2.2422…[9 caracteres].1792…[10 caracteres]"),
    (f"https://px.ads.linkedin.com/collect?uid={ID}", f"https://px.ads.linkedin.com/collect?uid={MASKED_ID}"),
    (f"ver https://t.example/u/{ID}/p.gif y {EMAIL}", f"ver https://t.example/u/{MASKED_ID}/p.gif y juan…[22 caracteres]"),
    ("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
     "Bearer eyJh…[20 caracteres].eyJz…[27 caracteres].dozj…[43 caracteres]"),
    # Lo legible no cambia.
    ("text/html,application/xhtml+xml,application/xml;q=0.9", None),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36", None),
    ("es-CL,es;q=0.9", None),
    ("max-age=31536000; includeSubDomains", None),
    (None, None),
])
def test_mask_identifiers_masks_only_id_shaped_values(value, expected):
    assert mask_identifiers(value) == (value if expected is None else expected)


def test_mask_identifiers_does_not_trust_nul_from_the_site():
    # Un NUL del sitio no puede hacerse pasar por un marcador interno.
    assert mask_identifiers(f"a=\x000\x00&uid={ID}") == f"a=�0�&uid={MASKED_ID}"


def test_brand_only_when_the_owner_matches():
    assert brands.brand("Microsoft", "linkedin.com") == "LinkedIn"
    assert brands.brand("Microsoft", "px.ads.linkedin.com") == "LinkedIn"
    assert brands.label("Microsoft", "px.ads.linkedin.com") == "LinkedIn (Microsoft)"
    # Dueño distinto del declarado (otro mapa o perfil de licencia): solo el dueño, nunca una marca inventada.
    assert brands.brand("Microsoft Corporation", "linkedin.com") is None
    assert brands.label("Microsoft Corporation", "linkedin.com") == "Microsoft Corporation"
    assert brands.brand("no_disponible", "linkedin.com") is None and brands.brand(None, "linkedin.com") is None
    # Sin marca propia: la organización tal cual. «notlinkedin.com» no es linkedin.com.
    assert brands.label("Microsoft", "microsoft.com") == "Microsoft" and brands.brand("Microsoft", "notlinkedin.com") is None
    assert brands.group_brand("Microsoft", ["linkedin.com", "licdn.com"]) == "LinkedIn"
    assert brands.group_brand("Microsoft", ["linkedin.com", "bing.com"]) is None


@pytest.fixture(scope="module")
def id_scan(client):
    """Request a px.ads.linkedin.com con el mismo ID en URL, parámetros, cookies, cabeceras y cadena de redirección."""
    job_id = uuid.uuid4()
    ids = {}

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.example/", status="completed", analysis_status="completed",
                            result={"final_url": "http://site.example/", "http_status": 200, "title": "T", "capture": {"truncated": False}}))
            await session.flush()
            requests = [
                _request(job_id, 0, resource_type="document", is_navigation=True),
                _request(job_id, 1, host="px.ads.linkedin.com", registrable_domain="linkedin.com", third_party=True,
                         url=f"https://px.ads.linkedin.com/collect?pid=123&uid={ID}", path="/collect", query_params=[["pid", "123"], ["uid", ID]],
                         frame_url=f"http://site.example/?ref={ID}", response_status=302,
                         request_headers=[{"name": "accept", "value": "image/avif,image/webp,*/*"}, {"name": "cookie", "value": f"li_sugr={ID}; lang=es-cl"}],
                         response_headers=[{"name": "set-cookie", "value": f"bcookie={ID}; Path=/; Secure"},
                                           {"name": "location", "value": f"https://www.linkedin.com/sync/{ID}"},
                                           {"name": "content-type", "value": "image/gif"}]),
                _request(job_id, 2, host="www.linkedin.com", registrable_domain="linkedin.com", third_party=True,
                         url=f"https://www.linkedin.com/sync/{ID}", path=f"/sync/{ID}", query_params=[]),
            ]
            session.add_all(requests)
            await session.flush()
            ids.update({request.seq: request.id for request in requests})
            for seq in (1, 2):
                session.add(RequestAnalysis(
                    job_id=job_id, request_id=ids[seq], score=70, band="Alto", category="advertising", mechanism="pixel", entity="Microsoft",
                    party="third_party", list_matches=[], analyzer_version=VERSION,
                    reasons=[{"signal": "id_sync", "weight": 25, "level": "EVIDENCIA", "evidence_ref": ids[seq], "detail": "valor compartido"}],
                ))
            session.add_all([
                ScanRedirect(job_id=job_id, chain_index=0, hop_index=0, request_seq=1, url=f"https://px.ads.linkedin.com/collect?pid=123&uid={ID}", status=302),
                ScanRedirect(job_id=job_id, chain_index=0, hop_index=1, request_seq=2, url=f"https://www.linkedin.com/sync/{ID}", status=200),
            ])
            for source, name, value, identifier_like in (("query", "uid", ID, True), ("query", "pid", "123", False),
                                                         ("cookie", "li_sugr", ID, False), ("set_cookie", "bcookie", f"{ID}; Path=/", False),
                                                         ("query", "email", EMAIL, False)):
                await session.execute(
                    text("INSERT INTO parameters (job_id, request_id, source, name, value, value_truncated, category, shapes, length, entropy, "
                         "identifier_like, encoding_chain) VALUES (:job, :rid, :source, :name, :value, false, NULL, '[]', :length, 3.0, :like, '[]')"),
                    {"job": job_id, "rid": ids[1], "source": source, "name": name, "value": value, "length": len(value), "like": identifier_like},
                )
            await session.execute(
                text("INSERT INTO decoded_values (job_id, request_id, source, name, path, raw_value, decoded_value, decoded_truncated, encoding_chain, confidence) "
                     "VALUES (:job, :rid, 'query', 'uid', '', :raw, :decoded, false, '[\"json\"]', 0.9)"),
                {"job": job_id, "rid": ids[1], "raw": json.dumps({"user": ID}), "decoded": json.dumps({"user": ID})},
            )
            await session.execute(
                text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                     "VALUES (:job, :v, 'listas-abc', '[]', 41, 'Moderado', '[]', '[]', '{}', '{}', false, 5)"),
                {"job": job_id, "v": VERSION},
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM report_files WHERE subject_id = :id"), {"id": job_id})
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id), ids
    client.portal.call(cleanup)


def test_request_detail_is_masked_by_default(client, id_scan):
    job_id, ids = id_scan
    body = client.get(f"/api/scans/{job_id}/requests/{ids[1]}").json()
    assert body["masked"] is True
    assert ID not in json.dumps(body) and EMAIL not in json.dumps(body), "ningún valor completo con forma de identificador"
    # URL, origen y ruta: el host se conserva.
    assert body["url"] == f"https://px.ads.linkedin.com/collect?pid=123&uid={MASKED_ID}" and body["host"] == "px.ads.linkedin.com"
    assert body["frame_url"] == f"http://site.example/?ref={MASKED_ID}"
    # Tabla de parámetros y cookies (recibidas y enviadas).
    values = {(row["source"], row["name"]): row["value"] for row in body["parameters"]}
    assert values[("query", "uid")] == MASKED_ID and values[("query", "pid")] == "123"
    assert values[("cookie", "li_sugr")] == MASKED_ID and values[("set_cookie", "bcookie")] == f"{MASKED_ID}; Path=/"
    assert values[("query", "email")] == "juan…[22 caracteres]"
    # Cabeceras: solo lo que tiene forma de ID.
    request_headers = {header["name"]: header["value"] for header in body["request_headers"]}
    response_headers = {header["name"]: header["value"] for header in body["response_headers"]}
    assert request_headers == {"accept": "image/avif,image/webp,*/*", "cookie": f"li_sugr={MASKED_ID}; lang=es-cl"}
    assert response_headers["set-cookie"] == f"bcookie={MASKED_ID}; Path=/; Secure" and response_headers["content-type"] == "image/gif"
    assert response_headers["location"] == f"https://www.linkedin.com/sync/{MASKED_ID}"
    # Cadena de redirección y decodificaciones.
    assert [(hop["url"], hop["location"]) for hop in body["redirect_chain"]] == [
        (f"https://px.ads.linkedin.com/collect?pid=123&uid={MASKED_ID}", f"https://www.linkedin.com/sync/{MASKED_ID}"),
        (f"https://www.linkedin.com/sync/{MASKED_ID}", None),
    ]
    assert body["decoded_values"][0]["decoded_value"] == json.dumps({"user": MASKED_ID}, ensure_ascii=False)


def test_reveal_shows_the_full_values(client, id_scan):
    job_id, ids = id_scan
    body = client.get(f"/api/scans/{job_id}/requests/{ids[1]}?reveal=true").json()
    assert body["masked"] is False
    assert body["url"].endswith(f"uid={ID}") and body["redirect_chain"][0]["location"] == f"https://www.linkedin.com/sync/{ID}"
    assert {row["name"]: row["value"] for row in body["parameters"]}["li_sugr"] == ID
    assert {header["name"]: header["value"] for header in body["request_headers"]}["cookie"] == f"li_sugr={ID}; lang=es-cl"


def test_brand_is_reported_next_to_the_owner(client, id_scan):
    job_id, ids = id_scan
    body = client.get(f"/api/scans/{job_id}/requests/{ids[1]}").json()
    # La organización (la que agrupa y decide «misma organización») no cambia; la marca va aparte.
    assert body["entity"] == "Microsoft" and body["brand"] == "LinkedIn"
    assert [(hop["entity"], hop["brand"]) for hop in body["redirect_chain"]] == [("Microsoft", "LinkedIn")] * 2
    listed = client.get(f"/api/scans/{job_id}/requests").json()["items"]
    assert [(item["seq"], item["brand"]) for item in listed] == [(0, None), (1, "LinkedIn"), (2, "LinkedIn")]
    trackers = client.get(f"/api/scans/{job_id}/trackers").json()["entities"]
    assert [(group["entity"], group["brand"]) for group in trackers] == [("Microsoft", "LinkedIn")]
    domains = {row["domain"]: row["brand"] for row in client.get(f"/api/scans/{job_id}/domains").json()["domains"]}
    assert domains == {"site.example": None, "linkedin.com": "LinkedIn"}


def test_export_shows_brand_and_owner_and_keeps_the_schema(client, id_scan):
    job_id, _ = id_scan
    report = client.get(f"/api/scans/{job_id}/report").json()
    # El JSON del reporte no cambia de forma (schema 1.11.0): la marca es solo presentación del HTML/PDF.
    assert report["schema_version"] == "1.11.0" and report["trackers"][0]["entity"] == "Microsoft" and "brand" not in report["trackers"][0]
    assert client.post(f"/api/scans/{job_id}/export").status_code == 202
    html = client.get(f"/api/scans/{job_id}/export/html").text
    assert "LinkedIn (Microsoft)" in html and ID not in html
