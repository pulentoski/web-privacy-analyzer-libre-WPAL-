"""Reportes exportables, destinos y CNAME (F8): enmascarado, sha256, marca y resolutor acotado."""

import asyncio
import hashlib
import json
import re
import uuid

import pytest
from sqlalchemy import delete, text

from app import cname as cname_module
from app.cname import CnameResolver, NotInCapture, cloaking_target
from app.config import get_settings
from app.db import SessionLocal
from app.masking import mask_group_report, mask_report, mask_text, mask_url, mask_value
from app.models import Job, RequestAnalysis
from app.report_html import Brand, executive_summary, load_brand, render_group_report, render_scan_report
from app.routes.analysis import LEGAL_NOTICE
from app.routes.reports import group_validator
from tests.factories import _request
from tests.test_analysis_api import VERSION, analyzed_scan  # noqa: F401  (fixture)

SECRET = "usr-7f3a9c21d4e5f60718293a4b5c6d7e8f"
PATH_ID = "3f9a8b7c-6d5e-4f3a-8b1c-0123456789ab"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


# --- Enmascarado (criterio 7) ---


def test_mask_value_keeps_prefix_and_length():
    assert mask_value(SECRET) == f"usr-…[{len(SECRET)} caracteres]"
    assert mask_value("corto") == "corto" and mask_value("12345678") == "12345678"
    assert mask_value(None) is None


def test_mask_url_masks_query_and_fragment_but_not_host_or_path():
    masked = mask_url(f"https://t.example/collect/v2?uid={SECRET}&v=2&flag#{SECRET}")
    assert masked.startswith("https://t.example/collect/v2?uid=usr-…[36 caracteres]&v=2&flag#usr-…[36 caracteres]")
    assert SECRET not in masked
    assert mask_url("https://t.example/sin-query") == "https://t.example/sin-query"
    assert mask_url(None) is None


@pytest.mark.parametrize(
    "url, expected",
    [
        # Segmentos con forma de ID: se enmascaran (prefijo + largo) y se conserva la extensión.
        ("https://t.example/u/3f9a8b7c-6d5e-4f3a-8b1c-0123456789ab/pixel.gif", "https://t.example/u/3f9a…[36 caracteres]/pixel.gif"),
        ("https://cdn.example/static/app.3f9a8b7c6d5e4f3a2b1c.js", "https://cdn.example/static/app.…[24 caracteres].js"),
        ("https://t.example/p/1234567890123/img", "https://t.example/p/1234…[13 caracteres]/img"),
        ("https://t.example/sync/guXhH0v-XMxlzmbTwqkaT4i5", "https://t.example/sync/guXh…[24 caracteres]"),
        ("https://x.example/a8f3k2m9x7q1w5e4r6t8y2u3/x", "https://x.example/a8f3…[24 caracteres]/x"),
        ("https://x.example/user/juan.perez@example.com/profile", "https://x.example/user/juan…[22 caracteres]/profile"),
        ("https://x.example/user/juan.perez%40example.com", "https://x.example/user/juan…[24 caracteres]"),
        ("t.tracker.example/p/0123456789abcdef0123.gif", "t.tracker.example/p/0123…[20 caracteres].gif"),
        ("(inline o eval en https://shop.example/item/1005006123456789.html)", "(inline o eval en https://shop.example/item/1005…[16 caracteres].html)"),
        # Ruta y query a la vez.
        ("https://x.example/s/0123456789abcdef?uid=abcdefghijkl", "https://x.example/s/0123…[16 caracteres]?uid=abcd…[12 caracteres]"),
        # Lo legible no se toca: slugs, fechas, nombres de archivo, rutas de API.
        ("https://news.example/2026/10/07/oferta-de-verano-2026-10-07-en-santiago.html", None),
        ("https://x.example/wp-content/uploads/2026/10/imagen-de-portada-1024x768.jpg", None),
        ("https://x.example/js/MyComponentBundleLoaderV2Final.js", None),
        ("https://x.example/api/v2/collect", None),
        ("https://x.example/gtag/js", None),
        ("https://x.example/", None),
        ("site.example", None),
    ],
)
def test_mask_url_masks_id_shaped_path_segments(url, expected):
    assert mask_url(url) == (url if expected is None else expected)
    # El host nunca se enmascara.
    assert "example" in mask_url(url)


def test_mask_text_masks_urls_quoted_inside_a_claim():
    claim = "Lo leyó: https://a.example/s/3f9a8b7c6d5e4f3a2b1c0d9e.js, y (inline o eval en https://b.example/x?id=123456789012)."
    assert mask_text(claim) == "Lo leyó: https://a.example/s/3f9a…[24 caracteres].js, y (inline o eval en https://b.example/x?id=1234…[12 caracteres])."
    assert mask_text("Sin direcciones.") == "Sin direcciones." and mask_text(None) is None


@pytest.fixture(scope="module")
def secret_scan(client):
    """Scan analizado cuyo tracker lleva un identificador largo en la URL, más un intento de inyección en un hallazgo."""
    job_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url=f"http://site.example/?session={SECRET}", status="completed", analysis_status="completed",
                            result={"final_url": f"http://site.example/?session={SECRET}", "http_status": 200, "title": "T", "capture": {"truncated": False}}))
            await session.flush()
            requests = [
                _request(job_id, 0, resource_type="document", is_navigation=True),
                _request(job_id, 1, host="t.tracker.example", registrable_domain="tracker.example", third_party=True,
                         url=f"http://t.tracker.example/u/{PATH_ID}/p.gif?uid={SECRET}&v=1"),
                _request(job_id, 2, host="blocked.example", registrable_domain="blocked.example", third_party=True, blocked_by_proxy=True, response_status=403),
            ]
            session.add_all(requests)
            await session.flush()
            ids = {request.seq: request.id for request in requests}
            session.add(RequestAnalysis(
                job_id=job_id, request_id=ids[1], score=80, band="Alto", category="analytics", mechanism="pixel", entity="Tracker Corp", list_matches=[],
                reasons=[{"signal": "id_sync", "weight": 25, "level": "EVIDENCIA", "evidence_ref": ids[1], "detail": "valor compartido con otra organización"}], analyzer_version=VERSION,
            ))
            await session.flush()
            await session.execute(
                text("INSERT INTO findings (job_id, type, level, claim, evidence_refs, details, analyzer_version) VALUES "
                     "(:job, 'id_sync', 'EVIDENCIA', :claim, CAST(:refs AS jsonb), '{}', :v)"),
                {"job": job_id, "claim": "Valor <script>window.__XSS=1</script> enviado a 2 dominios.", "refs": json.dumps([ids[1]]), "v": VERSION},
            )
            await session.execute(
                text("INSERT INTO site_analysis (job_id, analyzer_version, lists_version, lists, score, band, breakdown, data_categories, mechanisms, summary, partial, duration_ms) "
                     "VALUES (:job, :v, 'listas-abc', '[]', 41, 'Moderado', '[]', '[]', '{}', CAST(:summary AS jsonb), false, 5)"),
                {"job": job_id, "v": VERSION, "summary": json.dumps({"trackers": 1, "consent": {
                    "user_interaction": False,
                    "tcf": {"present": True, "cmp_id": 28, "cmp_name": "OneTrust LLC", "cmp_version": 7, "cmp_status": "loaded", "display_status": "hidden",
                            "gdpr_applies": False, "event_status": "tcloaded", "has_tc_string": True, "purposes_granted": 0, "purposes_total": 0},
                    "consent_mode": {"requests": 2, "states": {"G111": 2}, "by_signal": {"ad_storage": {"granted": 2}, "analytics_storage": {"granted": 2}}, "sources": {"gcs": 2, "gcd_only": 0}},
                }})},
            )
            # El proxy conectó a una IP pública para el tracker; el sitio propio resolvió a una privada.
            await session.execute(
                text("INSERT INTO scan_destinations (job_id, host, ip, connections) VALUES (:job, 't.tracker.example', '8.8.8.8', 3), (:job, 'site.example', '10.1.2.3', 2), (:job, 'blocked.example', '', 1)"),
                {"job": job_id},
            )
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM report_files WHERE subject_id = :id"), {"id": job_id})
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id)
    client.portal.call(cleanup)


def test_mask_report_leaves_no_full_identifier(client, secret_scan):
    report = client.get(f"/api/scans/{secret_scan}/report").json()
    assert SECRET in json.dumps(report) and report["masked"] is False
    masked = mask_report(report)
    assert SECRET not in json.dumps(masked) and masked["masked"] is True
    assert masked["trackers"][0]["requests"][0]["url"] == "http://t.tracker.example/u/3f9a…[36 caracteres]/p.gif?uid=usr-…[36 caracteres]&v=1"
    assert PATH_ID not in json.dumps(masked) and PATH_ID in json.dumps(report)
    assert report["trackers"][0]["requests"][0]["url"].endswith(f"uid={SECRET}&v=1"), "mask_report no debe modificar el original"


def test_export_is_masked_by_default_and_sha256_matches_the_json(client, secret_scan):
    response = client.post(f"/api/scans/{secret_scan}/export")
    assert response.status_code == 202, response.text
    status = response.json()
    assert status["masked"] is True and status["reveal"] is False
    assert status["files"]["json"]["status"] == status["files"]["html"]["status"] == "ready"
    assert status["files"]["pdf"]["status"] in ("pending", "rendering", "ready")

    exported = client.get(f"/api/scans/{secret_scan}/export/json")
    assert exported.status_code == 200
    digest = hashlib.sha256(exported.content).hexdigest()
    assert digest == status["sha256"] == exported.headers["x-report-sha256"]
    assert exported.headers["content-disposition"] == f'attachment; filename="reporte-{secret_scan}.json"'
    assert SECRET not in exported.text and PATH_ID not in exported.text
    assert exported.json()["masked"] is True and exported.json()["schema_version"] == "1.10.0"

    page = client.get(f"/api/scans/{secret_scan}/export/html")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert page.headers["x-report-sha256"] == digest and "sandbox" in page.headers["content-security-policy"]
    html = page.text
    # El sha256 impreso en el documento es el del JSON descargable.
    assert re.search(r'data-sha256="([0-9a-f]{64})"', html).group(1) == digest and html.count(digest) == 2
    assert SECRET not in html and PATH_ID not in html and "usr-…[36 caracteres]" in html and "/u/3f9a…[36 caracteres]/p.gif" in html
    assert "enmascarados" in html

    assert client.get(f"/api/scans/{secret_scan}/export").json()["sha256"] == digest


def test_reveal_is_explicit_and_is_a_separate_snapshot(client, secret_scan):
    masked = client.post(f"/api/scans/{secret_scan}/export", json={"reveal": False}).json()
    revealed = client.post(f"/api/scans/{secret_scan}/export", json={"reveal": True}).json()
    assert revealed["masked"] is False and revealed["sha256"] != masked["sha256"]
    full = client.get(f"/api/scans/{secret_scan}/export/html?reveal=true")
    assert SECRET in full.text and "muestra los valores completos" in full.text
    assert full.headers["content-disposition"].endswith(f'reporte-{secret_scan}-completo.html"')
    # La instantánea enmascarada sigue intacta.
    again = client.get(f"/api/scans/{secret_scan}/export/html")
    assert SECRET not in again.text and again.headers["x-report-sha256"] == masked["sha256"]
    assert client.post(f"/api/scans/{secret_scan}/export", json={"reveal": True, "otro": 1}).status_code == 422


def test_html_has_both_levels_and_the_mandatory_blocks(client, secret_scan):
    client.post(f"/api/scans/{secret_scan}/export")
    html = client.get(f"/api/scans/{secret_scan}/export/html").text
    for needle in (
        "Resumen ejecutivo", "Resultados", "Relevancia", "Recomendaciones",
        "Anexo técnico", "Metodología", "Hallazgos", "por organización", "Destinos por país", "Fingerprinting",
        "Consentimiento: TCF y Consent Mode", "Limitaciones", "Leyenda de niveles de evidencia", "Versiones", "Atribuciones",
        "IP Geolocation by DB-IP", "CC-BY-4.0", "No constituye asesoría legal", "http://site.example/", VERSION, "listas-abc", "DB-IP Lite",
        "OneTrust LLC", "gdprApplies", "G111", "Tracker Corp",
    ):
        assert needle in html, needle
    assert html.count("No constituye asesoría legal") == 2  # al inicio y al final
    for name in ("EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO"):
        assert f"lvl-{name}" in html
    # Texto capturado: siempre escapado, y el documento no trae scripts ni recursos externos.
    assert "<script" not in html and "&lt;script&gt;window.__XSS=1&lt;/script&gt;" in html
    assert not re.search(r'(?:src|href)="(?!data:)', html) and "default-src 'none'" in html
    # Trato de usted, sin tuteo.
    summary = html[html.index("Resumen ejecutivo"):html.index("Anexo técnico")]
    assert "su sitio" in summary and not re.search(r"\b(tú|tu|tus|te|ti|tienes|puedes|debes|quieres)\b", summary, re.I)


def test_executive_summary_has_three_to_five_recommendations(client, secret_scan, analyzed_scan):  # noqa: F811
    for job_id in (secret_scan, analyzed_scan[0]):
        report = client.get(f"/api/scans/{job_id}/report").json()
        summary = executive_summary(report)
        assert 3 <= len(summary["recommendations"]) <= 5 and len(set(summary["recommendations"])) == len(summary["recommendations"])
        assert summary["found"] and summary["why"]
    empty = executive_summary({"capture": {"total_requests": 1, "third_party": 0}, "site": {"exposure_score": 0, "band": "Bajo"}})
    assert 3 <= len(empty["recommendations"]) <= 5


def test_pdf_is_not_served_until_rendered_and_unknown_exports_are_404(client, secret_scan, analyzed_scan):  # noqa: F811
    async def reset():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM report_files WHERE subject_id = :id"), {"id": uuid.UUID(analyzed_scan[0])})
            await session.commit()

    client.portal.call(reset)
    missing = client.get(f"/api/scans/{analyzed_scan[0]}/export/pdf")
    assert missing.status_code == 404 and missing.json()["error_code"] == "EXPORT_NOT_FOUND"
    assert client.get(f"/api/scans/{analyzed_scan[0]}/export").status_code == 404
    assert client.get(f"/api/scans/{secret_scan}/export/exe").status_code == 422
    assert client.post(f"/api/scans/{uuid.uuid4()}/export").status_code == 404

    async def freeze():
        async with SessionLocal() as session:
            await session.execute(text("UPDATE report_files SET status = 'rendering', data = NULL, sha256 = 'congelado-por-el-test' WHERE subject_id = :id AND kind = 'pdf'"), {"id": uuid.UUID(secret_scan)})
            await session.commit()

    client.post(f"/api/scans/{secret_scan}/export")
    # Con otro sha256 el worker (que está vivo en este stack) ya no puede completar esta fila.
    client.portal.call(freeze)
    pending = client.get(f"/api/scans/{secret_scan}/export/pdf")
    assert pending.status_code == 409 and pending.json()["error_code"] == "EXPORT_NOT_READY"


def test_export_before_analysis_is_rejected(client, scan):
    response = client.post(f"/api/scans/{scan}/export")
    assert response.status_code == 409 and response.json()["error_code"] == "ANALYSIS_NOT_READY"


# --- Marca configurable ---


def test_brand_from_environment_or_from_a_directory_outside_the_repo(tmp_path):
    # v1.2: sin marca configurada, la del proyecto (su logo y su nombre).
    assert load_brand("", str(tmp_path)).name == "Web Privacy & Tracker Analyzer"
    assert load_brand("  Consultora Ñandú  ", str(tmp_path / "no-existe")) == Brand(name="Consultora Ñandú")
    (tmp_path / "nombre.txt").write_text("Estudio Demo\nsegunda línea\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(PNG)
    brand = load_brand("", str(tmp_path))
    assert brand.name == "Estudio Demo" and brand.logo_data_uri.startswith("data:image/png;base64,")
    assert load_brand("Otro", str(tmp_path)).name == "Otro", "la variable de entorno manda sobre el archivo"
    # Un archivo que dice ser PNG pero no lo es, o demasiado grande, no se incrusta.
    (tmp_path / "logo.png").write_bytes(b"<svg onload=alert(1)>")
    assert load_brand("", str(tmp_path)).logo_data_uri == ""
    (tmp_path / "logo.png").write_bytes(PNG + b"\x00" * 400_000)
    assert load_brand("", str(tmp_path)).logo_data_uri == ""


def test_header_is_neutral_without_brand_and_branded_with_it(client, secret_scan):
    report = mask_report(client.get(f"/api/scans/{secret_scan}/report").json())
    neutral = render_scan_report(report, "0" * 64)
    assert 'class="brand"' not in neutral and "<img" not in neutral
    assert neutral.index("<body>") + len("<body>") == neutral.index("<h1>Reporte de privacidad del sitio web</h1>")
    branded = render_scan_report(report, "0" * 64, Brand(name="Estudio <b>Demo</b>", logo_data_uri="data:image/png;base64,AAAA"))
    assert 'class="brand"' in branded and "Estudio &lt;b&gt;Demo&lt;/b&gt;" in branded and '<img src="data:image/png;base64,AAAA"' in branded
    # v1.2: sin marca configurada en el stack, el reporte exportado lleva el logo y el nombre del proyecto.
    settings = get_settings()
    default = load_brand("", settings.report_brand_dir)
    if not settings.report_brand_name and default.name == "Web Privacy & Tracker Analyzer":
        client.post(f"/api/scans/{secret_scan}/export")
        exported = client.get(f"/api/scans/{secret_scan}/export/html").text
        assert 'class="brand"' in exported and "Web Privacy &amp; Tracker Analyzer" in exported
        assert f'<img src="{default.logo_data_uri}"' in exported and default.logo_data_uri.startswith("data:image/png;base64,")
        # El reporte sigue siendo autocontenido: el logo va incrustado, sin recursos externos.
        assert "http://" not in exported.split('class="brand"')[1].split("</div>")[0]


# --- Destinos: IP, ASN y país, o "no_disponible" con motivo (criterio 4) ---


@pytest.mark.needs_stack  # necesita la base de IP (DB-IP, no versionada); se omite en CI.
def test_every_domain_has_ip_intel_or_a_reason(client, secret_scan, analyzed_scan):  # noqa: F811
    body = client.get(f"/api/scans/{secret_scan}/destinations").json()
    assert body["has_proxy_log"] is True and body["attribution"]["text"] == "IP Geolocation by DB-IP"
    assert "aproximada" in body["location_note"]
    domains = {domain["domain"]: domain for domain in body["domains"]}
    assert set(domains) == {"site.example", "tracker.example", "blocked.example"}
    for domain in domains.values():
        if domain["ips"]:
            assert domain["ip_status"] == "observada" and domain["ip_reason"] is None
            for ip in domain["ips"]:
                if ip["applies"]:
                    assert all(isinstance(ip[key], str) and ip[key] for key in ("asn", "organization", "country", "country_code"))
                else:
                    assert ip["note"].startswith("no aplica")
        else:
            assert domain["ip_status"] == "no_disponible" and domain["ip_reason"]
    public = domains["tracker.example"]["ips"][0]
    assert public["ip"] == "8.8.8.8" and re.fullmatch(r"AS\d+", public["asn"]) and public["country_code"] == "US"
    assert domains["site.example"]["ips"][0]["applies"] is False, "una IP privada no se geolocaliza"
    assert domains["blocked.example"]["ip_reason"].startswith("El proxy no completó la conexión")
    assert [country["country_code"] for country in body["countries"]] == ["US"] and body["countries"][0]["third_party_domains"] == 1
    # Dueño del dominio y red de la IP: fuentes distintas, se muestran ambas sin escoger.
    assert domains["tracker.example"]["entity"] == "Tracker Corp" and domains["tracker.example"]["network_organizations"]
    assert domains["tracker.example"]["sources_differ"] is True

    # Un scan sin log del proxy lo dice, en vez de inventar una IP.
    old = client.get(f"/api/scans/{analyzed_scan[0]}/destinations").json()
    assert old["has_proxy_log"] is False and old["countries"] == []
    assert all(domain["ips"] == [] and "anterior al registro" in domain["ip_reason"] for domain in old["domains"])


# --- CNAME cloaking y resolutor acotado (criterio 5) ---


def run(coroutine):
    return asyncio.run(coroutine)


def test_resolver_rejects_hostnames_outside_the_capture(monkeypatch):
    calls = []
    monkeypatch.setattr(CnameResolver, "_lookup", staticmethod(lambda host: calls.append(host) or ["alias.cdn.example"]))
    resolver = CnameResolver()
    capture = {"www.site.example", "metrics.site.example"}
    for outsider in ("evil.example", "169.254.169.254", "localhost", "db", "api", "metadata.google.internal", "", "WWW.SITE.EXAMPLE.evil.example"):
        with pytest.raises(NotInCapture):
            run(resolver.resolve(outsider, capture))
    assert calls == [], "no se consultó el DNS por ningún hostname ajeno a la captura"
    assert run(resolver.resolve("metrics.site.example", capture)) == ("resolved", ["alias.cdn.example"])
    assert calls == ["metrics.site.example"]


def test_resolver_never_looks_up_ips_or_single_labels_even_if_captured(monkeypatch):
    calls = []
    monkeypatch.setattr(CnameResolver, "_lookup", staticmethod(lambda host: calls.append(host) or []))
    resolver = CnameResolver()
    weird = {"10.0.0.5", "169.254.169.254", "localhost", "db", "[::1]", "a b.example", "x.example:22", "-bad.example", "ejemplo.123"}
    for host in weird:
        assert run(resolver.resolve(host, weird)) == ("skipped", []), host
    assert calls == []


def test_resolver_only_queries_dns_and_never_connects(monkeypatch):
    """El resolutor no abre conexiones: su única primitiva de red es una consulta de nombres."""
    import inspect
    import socket

    source = inspect.getsource(cname_module)
    assert "gethostbyname_ex" in source
    for forbidden in ("connect(", "urlopen", "httpx", "requests.", "create_connection", "open_connection"):
        assert forbidden not in source, forbidden
    opened = []
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: opened.append(a) or (_ for _ in ()).throw(AssertionError("conexión")))
    monkeypatch.setattr(CnameResolver, "_lookup", staticmethod(lambda host: ["x.omtrdc.net"]))
    assert run(CnameResolver().resolve("m.site.example", {"m.site.example"})) == ("resolved", ["x.omtrdc.net"])
    assert opened == []


def test_resolver_has_timeout_cache_rate_limit_and_per_scan_cap(monkeypatch):
    import time

    calls = []

    def slow(host):
        calls.append(host)
        if host.startswith("slow"):
            time.sleep(1.0)
        return ["t.example"]

    monkeypatch.setattr(CnameResolver, "_lookup", staticmethod(slow))
    monkeypatch.setattr(cname_module, "TIMEOUT_S", 0.2)
    resolver = CnameResolver()
    hosts = {"slow.site.example", "a.site.example"}
    assert run(resolver.resolve("slow.site.example", hosts)) == ("error", [])
    # Caché: ni el acierto ni el error se vuelven a consultar.
    assert run(resolver.resolve("a.site.example", hosts)) == run(resolver.resolve("a.site.example", hosts)) == ("resolved", ["t.example"])
    assert run(resolver.resolve("slow.site.example", hosts)) == ("error", [])
    assert calls == ["slow.site.example", "a.site.example"]

    # Tope por scan.
    many = [f"h{index:03d}.site.example" for index in range(80)]
    resolved = run(CnameResolver().resolve_all(many, set(many)))
    assert len(resolved) == cname_module.MAX_HOSTS_PER_SCAN

    # Rate limit global del proceso: pasado el cupo, se omite sin consultar.
    monkeypatch.setattr(cname_module, "RATE_LIMIT", 3)
    limited, calls[:] = CnameResolver(), []
    results = [run(limited.resolve(host, set(many))) for host in many[:6]]
    assert [status for status, _ in results] == ["resolved"] * 3 + ["skipped"] * 3 and len(calls) == 3


def test_cloaking_target_ignores_aliases_inside_the_site():
    targets = {"omtrdc.net": "Adobe (Analytics)"}
    assert cloaking_target(["site.example.sc.omtrdc.net"], "site.example", targets) == ("site.example.sc.omtrdc.net", "omtrdc.net", "Adobe (Analytics)")
    assert cloaking_target(["cdn.site.example"], "site.example", targets) is None
    assert cloaking_target(["notomtrdc.net"], "site.example", targets) is None
    assert cloaking_target([], "site.example", targets) is None


@pytest.fixture(scope="module")
def cloaked_scan(client):
    """Captura con un subdominio propio que en el DNS (simulado) de fixtures es un alias del tracker."""
    assert get_settings().allow_fixtures, "requiere ALLOW_FIXTURES=1 (stack de test)"
    job_id = uuid.uuid4()
    ids = {}

    async def insert():
        async with SessionLocal() as session:
            session.add(Job(id=job_id, url="http://site.fixtures.test/f8/", status="completed", analysis_status="completed", result={"capture": {}}))
            await session.flush()
            requests = [
                _request(job_id, 0, host="site.fixtures.test", registrable_domain="site.fixtures.test", resource_type="document", is_navigation=True),
                _request(job_id, 1, host="metrics.site.fixtures.test", registrable_domain="site.fixtures.test"),
                _request(job_id, 2, host="tracker-a.fixtures.test", registrable_domain="tracker-a.fixtures.test", third_party=True),
            ]
            session.add_all(requests)
            await session.flush()
            ids.update({request.seq: request.id for request in requests})
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(delete(Job).where(Job.id == job_id))
            await session.commit()

    client.portal.call(insert)
    yield str(job_id), ids
    client.portal.call(cleanup)


def test_cname_cloaking_is_detected_with_evidence_and_no_hostname_input(client, cloaked_scan):
    job_id, ids = cloaked_scan
    cloaking = client.get(f"/api/scans/{job_id}/destinations").json()["cname_cloaking"]
    assert cloaking["first_party_subdomains"] == 1 and cloaking["checked_hosts"] == 1
    (finding,) = cloaking["findings"]
    assert finding["host"] == "metrics.site.fixtures.test" and finding["cname_chain"] == ["tracker-a.fixtures.test"]
    assert finding["target_domain"] == "tracker-a.fixtures.test" and finding["organization"] == "Tracker A (fixture)"
    assert finding["level"] == "EVIDENCIA" and finding["evidence_refs"] == [ids[1]]
    assert finding["inference_level"] == "INFERENCIA" and finding["inference"]

    async def stored():
        async with SessionLocal() as session:
            return [tuple(row) for row in await session.execute(text("SELECT host, status FROM scan_cnames WHERE job_id = :id"), {"id": uuid.UUID(job_id)})]

    # Solo se resolvió el subdominio propio: ni el dominio raíz ni el tercero.
    assert client.portal.call(stored) == [("metrics.site.fixtures.test", "resolved")]
    # Ningún endpoint acepta un hostname: los parámetros extra se ignoran y no cambian lo resuelto.
    client.get(f"/api/scans/{job_id}/destinations?host=169.254.169.254&hostname=db&resolve=evil.example")
    assert client.portal.call(stored) == [("metrics.site.fixtures.test", "resolved")]


# --- Reporte de un grupo de Privacy Test ---


GROUP_REPORT = {
    "schema_version": "group-1.0.0", "generated_at": "2026-10-07T12:00:00+00:00",
    "group": {"group_id": "g", "url": "http://site.example/", "created_at": "2026-10-07T11:00:00+00:00",
              "config": {"scenarios": ["sin_interaccion", "rechazar"], "profiles": ["real"], "runs": 2}, "progress": {"done": 4, "total": 4, "failed": 0}},
    "scans": [{"job_id": "j1", "scenario": "rechazar", "profile": "real", "run": 1, "status": "completed", "exposure_score": 40, "band": "Bajo-moderado"}],
    "result": {
        "cells": [{"key": "rechazar|real", "scenario": "rechazar", "profile": "real", "runs": 2, "completed": 2,
                   "requests": {"median": 10, "min": 9, "max": 11, "values": [9, 11]}, "third_party_domains": None, "tracker_requests": None,
                   "tracker_domains": [{"domain": "tracker.example", "entity": "Tracker Corp", "appeared": 1, "of": 2}]}],
        "tracker_differences": [],
        "consent": {"cmp": "onetrust", "banner_detected_runs": 4, "runs": 4, "not_applicable": False, "scenarios": [],
                    "findings": {"pre_consent": {"level": "EVIDENCIA", "claim": "Antes de interactuar.", "runs": 4, "items": [
                                     {"resource": "t.tracker.example/p.gif", "entity": "Tracker Corp", "runs": 4, "of": 4, "evidence": [{"job_id": "j1", "request_id": 7}]}]},
                                 "post_reject": {"level": "EVIDENCIA", "claim": "Después de rechazar.", "runs": 2, "items": [
                                     {"resource": "t.tracker.example/<img src=x onerror=1>", "entity": None, "runs": 2, "of": 2, "evidence": [{"job_id": "j1", "request_id": 9}]}]},
                                 "only_after_accept": {"level": "EVIDENCIA", "claim": "Solo tras aceptar.", "runs": 0, "items": []}},
                    "note": "No es un juicio."},
        "profiles": None,
        "persistent_ids": {"total": 1, "note": "Nota.", "items": [{"level": "EVIDENCIA", "claim": "El mismo valor (abc123…(40 caracteres)) se envió.",
                                                                  "inference": "Depende de la IP.", "inference_level": "INFERENCIA", "evidence": [{"job_id": "j1", "request_id": 3}]}]},
        "limitations": ["Cambiar el perfil no cambia la IP."],
    },
    "versions": {"analyzer": "9.9.9", "lists": "abc", "ip_database": "DB-IP Lite 2026-10", "cmp_list": "1"},
    "attributions": [{"source": "DB-IP Lite (país y ASN)", "license": "CC-BY-4.0", "text": "IP Geolocation by DB-IP", "url": "https://db-ip.com", "noncommercial": False}],
    "evidence_levels": {"EVIDENCIA": "Hecho observado."}, "legal_notice": LEGAL_NOTICE, "masked": True, "limitations": ["Cambiar el perfil no cambia la IP."],
}


def test_group_report_html_and_schema():
    assert list(group_validator().iter_errors(GROUP_REPORT)) == []
    broken = json.loads(json.dumps(GROUP_REPORT))
    del broken["result"]["persistent_ids"]["items"][0]["evidence"]
    assert list(group_validator().iter_errors(broken)), "un hallazgo sin evidencia no pasa el schema"
    html = render_group_report(GROUP_REPORT, "a" * 64)
    for needle in ("Reporte de análisis con opciones avanzadas", "Resumen ejecutivo", "Anexo técnico", "mediana y rango", "10 (rango 9–11)", "1 de 2", "Después de rechazar.",
                   "scan j1 #9", "Valores repetidos entre corridas limpias", "IP Geolocation by DB-IP", "No constituye asesoría legal", "a" * 64, "9.9.9"):
        assert needle in html, needle
    assert "<img" not in html and "&lt;img src=x onerror=1&gt;" in html
    assert not re.search(r"\ban[oó]nim[oa]s?\b", html, re.I) and "no afirma anonimato" in html


def test_group_export_endpoints(client):
    unknown = client.post(f"/api/privacy/test/{uuid.uuid4()}/export")
    assert unknown.status_code == 404 and unknown.json()["error_code"] == "TEST_NOT_FOUND"
    group_id = uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            await session.execute(text("INSERT INTO test_groups (id, url, config) VALUES (:id, :url, CAST(:config AS jsonb))"),
                                  {"id": group_id, "url": f"http://site.example/?s={SECRET}", "config": json.dumps({"scenarios": ["sin_interaccion"], "profiles": ["real"], "runs": 2})})
            for run_number in (1, 2):
                # "running" y no "queued": el worker de este stack está vivo y tomaría un job encolado.
                job = Job(url="http://site.example/", status="completed", analysis_status="completed" if run_number == 1 else "running",
                          options={"scenario": "sin_interaccion", "profile": "real", "run": run_number}, result={})
                session.add(job)
                await session.flush()
                await session.execute(text("UPDATE jobs SET group_id = :group WHERE id = :id"), {"group": group_id, "id": job.id})
            await session.commit()

    async def finish():
        async with SessionLocal() as session:
            await session.execute(text("UPDATE jobs SET analysis_status = 'failed' WHERE group_id = :group AND analysis_status = 'running'"), {"group": group_id})
            await session.commit()

    async def cleanup():
        async with SessionLocal() as session:
            await session.execute(text("DELETE FROM report_files WHERE subject_id = :id"), {"id": group_id})
            await session.execute(text("DELETE FROM jobs WHERE group_id = :id"), {"id": group_id})
            await session.execute(text("DELETE FROM test_groups WHERE id = :id"), {"id": group_id})
            await session.commit()

    client.portal.call(insert)
    try:
        running = client.post(f"/api/privacy/test/{group_id}/export")
        assert running.status_code == 409 and running.json()["error_code"] == "TEST_NOT_READY"
        client.portal.call(finish)
        status = client.post(f"/api/privacy/test/{group_id}/export")
        assert status.status_code == 202, status.text
        exported = client.get(f"/api/privacy/test/{group_id}/export/json")
        assert hashlib.sha256(exported.content).hexdigest() == status.json()["sha256"]
        report = exported.json()
        assert report["schema_version"] == "group-1.0.0" and report["masked"] is True and SECRET not in exported.text
        assert [scan["exposure_score"] for scan in report["scans"]] == ["no_disponible", "no_disponible"]
        html = client.get(f"/api/privacy/test/{group_id}/export/html")
        assert html.headers["content-disposition"] == f'attachment; filename="reporte-grupo-{group_id}.html"'
        assert status.json()["sha256"] in html.text and "Reporte de análisis con opciones avanzadas" in html.text and SECRET not in html.text
    finally:
        client.portal.call(cleanup)
