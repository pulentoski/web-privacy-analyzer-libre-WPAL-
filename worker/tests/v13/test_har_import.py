"""v1.3: captura a partir de un HAR importado, fuga de búsqueda y ola de sincronización.

Capturas sintéticas en memoria (sin red). El payload tiene la forma que deja la api después de
validar y depurar el archivo (api/app/har_import.py).
"""

import json

import pytest

from app import har_capture
from app.analyzer.config import load_config
from app.analyzer.decoding import decode
from app.analyzer.engine import analyze
from app.config import settings

PAGE = "https://www.tienda-sintetica.example/buscar?q=zapatillas+rojas"
XSS = "<img src=x onerror=alert('har-xss')>"
SYNC_URLS = [
    "https://frame.syncer-uno.example/syncframe?origin=tienda",
    "https://sync.socio-a.example/sync?partner=1",
    "https://rtb.socio-b.example/csync/abc",
    "https://cm.socio-c.example/cookiematching?id=1",
    "https://px.socio-d.example/usersync/x",
]


class Lists:
    version, sources, license_profile = "test", [], "no_comercial"

    def entity(self, domain):
        return {"tienda-sintetica.example": "Tienda", "tienda-cdn.example": "Tienda"}.get(domain, "no_disponible")

    def match(self, request, source_host):
        return []


@pytest.fixture(scope="module")
def config():
    return load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


def entry(url, second, *, resource_type="image", status=200, error=None, request_headers=None, response_headers=None, post=None, ip="203.0.113.10"):
    return {
        "ts": f"2026-01-15T10:00:{second:06.3f}+00:00", "method": "POST" if post else "GET", "url": url, "url_truncated": False,
        "http_version": "HTTP/2", "request_headers": request_headers or [], "post_data": {"text": post, "size": len(post), "truncated": False, "mime": "text/plain"} if post else None,
        "status": status, "response_headers": response_headers, "mime": "image/gif", "resource_type": resource_type,
        "initiator": {"type": "script", "url": "https://www.tienda-sintetica.example/app.js"}, "error": error, "server_ip": ip, "time_ms": 12.5,
        "sizes": {"responseBodySize": 10},
    }


def payload(extra=()):
    return {
        "page_url": PAGE,
        "entries": [
            entry(PAGE, 0, resource_type="document",
                  request_headers=[{"name": "Cookie", "value": "", "redacted": True, "length": 22}, {"name": "User-Agent", "value": XSS}],
                  response_headers=[{"name": "Set-Cookie", "value": "", "redacted": True, "length": 40}]),
            entry("https://img.tienda-cdn.example/logo.png", 0.1),
            entry("https://stats.medidor-uno.example/collect?q=zapatillas%20rojas&v=1", 0.4, resource_type="ping"),
            entry("https://ads.bloqueado-uno.example/ad.js", 0.6, resource_type="script", status=None, error="net::ERR_BLOCKED_BY_CLIENT", ip=None),
            entry("https://ads.bloqueado-dos.example/p.gif", 0.7, status=None, error="net::ERR_BLOCKED_BY_CLIENT", ip=None),
            *[entry(url, 1 + index / 10) for index, url in enumerate(SYNC_URLS)],
            *extra,
        ],
        "meta": {"load": {"id": "page:0"}, "blocked_by_client": 2, "sensitive_removed": {"cookie": 1, "set_cookie": 1, "authorization": 0, "cookie_objects": 0}},
    }


def loaded(result, capture):
    """La captura tal como la lee el analizador desde la base (worker/app/analysis.py)."""
    requests = [
        {"request_id": 100 + r["seq"], "seq": r["seq"], "method": r["method"], "url": r["url"], "host": r["host"], "resource_type": r["resource_type"],
         "is_navigation": r["is_navigation"], "query_params": r["query_params"], "request_headers": r["request_headers"],
         "response_headers": r["response_headers"], "post_data": r["post_data"], "sizes": r["sizes"], "mime_type": r["mime_type"],
         "third_party": r["third_party"], "registrable_domain": r["registrable_domain"], "response_status": r["response_status"],
         "initiator_script": (r["initiator"] or {}).get("script_url"), "ts": r["ts"].timestamp(), "failure_text": r["failure_text"]}
        for r in capture["requests"]
    ]
    return {"start_url": PAGE, "page_url": result["final_url"], "fingerprinting": capture["fingerprinting"], "tcf": None, "consent": None,
            "title": result["title"], "http_status": result["http_status"], "source": result["source"], "requests": requests,
            "visit_ts": None, "cookies": [], "storage": [], "websockets": []}


def build(extra=()):
    return har_capture.build_capture(payload(extra), max_requests=1500, max_body_bytes=65536)


def test_capture_has_the_shape_of_a_scan_and_declares_what_a_har_lacks():
    result, capture = build()
    assert result["source"] == "har_import" and result["final_url"] == PAGE and result["http_status"] == 200 and result["title"] is None
    assert result["import"]["blocked_by_client"] == 2
    assert capture["end_reason"] == "har_import" and capture["truncated"] is False and len(capture["requests"]) == 10
    # Sin instrumentación ni snapshot: None/vacío, no «cero llamadas».
    assert capture["fingerprinting"] is None and capture["cookies"] == [] and capture["storage"] == [] and capture["websockets"] == []
    document, cdn, third = capture["requests"][0], capture["requests"][1], capture["requests"][2]
    assert document["is_navigation"] and document["third_party"] is False and document["registrable_domain"] == "tienda-sintetica.example"
    assert cdn["third_party"] is True and third["registrable_domain"] == "medidor-uno.example" and third["query_params"] == [["q", "zapatillas%20rojas"], ["v", "1"]]
    assert [r["seq"] for r in capture["requests"]] == list(range(10))
    blocked = [r for r in capture["requests"] if r["failure_text"] == "net::ERR_BLOCKED_BY_CLIENT"]
    assert len(blocked) == 2 and all(r["response_status"] is None and r["blocked_by_proxy"] is False for r in blocked)
    assert {"host": "www.tienda-sintetica.example", "ip": "203.0.113.10", "connections": 1} in capture["destinations"]
    assert not any(d["host"].startswith("ads.") for d in capture["destinations"])


def test_sensitive_headers_keep_only_name_and_length():
    _, capture = build()
    headers = capture["requests"][0]["request_headers"]
    assert headers[0] == {"name": "Cookie", "value": "", "redacted": True, "length": 22}
    assert headers[1] == {"name": "User-Agent", "value": XSS}  # texto tal cual: se muestra, no se interpreta
    assert capture["requests"][0]["response_headers"] == [{"name": "Set-Cookie", "value": "", "redacted": True, "length": 40}]


@pytest.mark.parametrize("bad", [None, [], {"entries": []}, {"page_url": PAGE}, {"page_url": 5, "entries": []}, {"page_url": "", "entries": []}])
def test_invalid_payload_is_rejected(bad):
    with pytest.raises(har_capture.InvalidImport):
        har_capture.build_capture(bad, max_requests=10, max_body_bytes=100)


def test_untrusted_entries_are_bounded_and_filtered():
    extra = [
        {"ts": "no-es-fecha", "url": "https://x.example/"}, "texto", {"ts": "2026-01-15T10:00:05+00:00", "url": "javascript:alert(1)"},
        entry("https://largo.example/" + "a" * 20000, 6, post="x" * 500),
        {**entry("https://tipos.example/", 7), "status": "200", "request_headers": "no-lista", "sizes": {"a": "b"}, "resource_type": {"x": 1}},
    ]
    _, capture = har_capture.build_capture(payload(extra), max_requests=1500, max_body_bytes=100)
    assert len(capture["requests"]) == 12
    long_request, typed = capture["requests"][10], capture["requests"][11]
    assert len(long_request["url"]) == 8192 and long_request["post_data"]["truncated"] is True and len(long_request["post_data"]["data"]) == 100
    assert typed["response_status"] is None and typed["request_headers"] == [] and typed["sizes"] is None and typed["resource_type"] == "image"
    _, truncated = har_capture.build_capture(payload(), max_requests=4, max_body_bytes=100)
    assert len(truncated["requests"]) == 4 and truncated["truncated"] is True


def test_same_analyzer_runs_on_the_imported_capture(config):
    analysis = analyze(loaded(*build()), Lists(), config)
    summary = analysis["site"]["summary"]
    assert summary["source"] == "har_import" and summary["blocked_by_client"] == 2
    assert analysis["fingerprinting"]["instrumented"] is False
    # Terceros por organización: el CDN del mismo dueño no cuenta.
    assert summary["parties"]["same_org_domains"] == ["tienda-cdn.example"] and "tienda-cdn.example" not in summary["parties"]["third_party_domains"]
    # Captura del navegador real: la alerta de navegador automatizado no aplica.
    assert summary["blocking"]["blocked"] is False
    kinds = {finding["type"] for finding in analysis["findings"]}
    assert {"search_leak", "sync_wave", "third_party_set_cookie"} - kinds == {"third_party_set_cookie"}  # el Set-Cookie es del propio sitio
    assert all(finding["level"] and finding["evidence_refs"] for finding in analysis["findings"])


def test_search_term_sent_to_another_domain_is_a_finding_with_evidence(config):
    analysis = analyze(loaded(*build()), Lists(), config)
    leaks = [finding for finding in analysis["findings"] if finding["type"] == "search_leak"]
    assert len(leaks) == 1
    leak = leaks[0]
    assert leak["level"] == "EVIDENCIA" and leak["evidence_refs"] == [102]
    assert leak["details"] == {"domain": "medidor-uno.example", "host": "stats.medidor-uno.example", "term": "zapatillas rojas",
                               "parameter": "q", "party": "third_party", "rule": "nombre"}
    assert "«zapatillas rojas»" in leak["claim"] and "stats.medidor-uno.example (tercero)" in leak["claim"]
    assert analysis["site"]["summary"]["search_leaks"] == [{"host": "stats.medidor-uno.example", "domain": "medidor-uno.example",
                                                            "term": "zapatillas rojas", "parameter": "q", "party": "third_party"}]


def test_search_terms_ignore_identifiers_numbers_and_the_page_host(config):
    extra = [
        entry("https://a.otro.example/c?q=a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", 3),   # identificador, no texto
        entry("https://b.otro.example/c?k=12345&search=true&query=ab", 3.1),        # número, booleano, muy corto
        entry("https://www.tienda-sintetica.example/api?keywords=botas+azules", 3.2),  # mismo host de la página
        entry("https://c.otro.example/c?keywords=botas+azules&search=" + XSS.replace(" ", "%20"), 3.3),
    ]
    analysis = analyze(loaded(*build(extra)), Lists(), config)
    terms = sorted((f["details"]["host"], f["details"]["term"]) for f in analysis["findings"] if f["type"] == "search_leak")
    assert terms == [("c.otro.example", XSS), ("c.otro.example", "botas azules"), ("stats.medidor-uno.example", "zapatillas rojas")]


def test_contextual_search_telemetry_nested_in_a_double_encoded_body(config):
    """Telemetría tipo aplus: el término va en otro parámetro, dentro de un query doblemente codificado."""
    gokey = "exp_type%3Dsearch_door%26exp_page_area%3Dzapatillas%20rojas%26track%3Dmid%253Dabc"
    other = "exp_type%3Dpoplayer%26exp_page_area%3DsearchInput"
    extra = [
        entry("https://aplus.tienda-sintetica.example/stat", 3, resource_type="ping", post=json.dumps({"gmkey": "EXP", "gokey": gokey})),
        entry("https://aplus.tienda-sintetica.example/stat", 3.1, resource_type="ping", post=json.dumps({"gmkey": "EXP", "gokey": other})),
    ]
    analysis = analyze(loaded(*build(extra)), Lists(), config)
    leaks = [f for f in analysis["findings"] if f["type"] == "search_leak" and f["details"]["host"].startswith("aplus.")]
    assert len(leaks) == 1
    assert leaks[0]["details"]["term"] == "zapatillas rojas" and leaks[0]["details"]["parameter"] == "exp_page_area"
    assert leaks[0]["details"]["rule"] == "contexto" and leaks[0]["details"]["party"] == "first_party" and leaks[0]["level"] == "EVIDENCIA"
    assert "otro host del propio sitio" in leaks[0]["claim"]


def test_sync_wave_names_requests_organizations_and_initiator(config):
    analysis = analyze(loaded(*build()), Lists(), config)
    wave = analysis["site"]["summary"]["sync_wave"]
    assert wave == {"available": True, "detected": True, "requests": 5, "organizations": 5, "initiator": "frame.syncer-uno.example",
                    "domains": ["socio-a.example", "socio-b.example", "socio-c.example", "socio-d.example", "syncer-uno.example"], "duration_ms": 400}
    finding = next(f for f in analysis["findings"] if f["type"] == "sync_wave")
    assert finding["level"] == "EVIDENCIA" and finding["evidence_refs"] == [105, 106, 107, 108, 109]
    assert "iniciada por frame.syncer-uno.example" in finding["claim"]


def test_no_wave_when_sync_requests_are_few_spread_out_or_untimed(config):
    capture = loaded(*build())
    few = {**capture, "requests": capture["requests"][:7]}
    assert analyze(few, Lists(), config)["site"]["summary"]["sync_wave"]["detected"] is False
    spread = {**capture, "requests": [{**r, "ts": r["ts"] + index * 10} for index, r in enumerate(capture["requests"])]}
    assert analyze(spread, Lists(), config)["site"]["summary"]["sync_wave"]["detected"] is False
    # Capturas antiguas sin hora: no se inventa «sin ola».
    untimed = {**capture, "requests": [{key: value for key, value in r.items() if key != "ts"} for r in capture["requests"]]}
    wave = analyze(untimed, Lists(), config)["site"]["summary"]["sync_wave"]
    assert wave["available"] is False and wave["detected"] is False


def test_query_with_spaces_in_values_is_split_but_plain_text_is_not():
    results = decode("q=cartas pokemon&p=1")
    assert results and results[0].encoding_chain == ("query",) and list(results[0].structure) == [["q", "cartas pokemon"], ["p", "1"]]
    assert decode("a = b") == [] and decode("nota=hola mundo") == []
