"""Análisis del sitio de fixtures contra su ground truth (manifest.json)."""

import json
import math
import time

import pytest

from app.analyzer import ANALYZER_VERSION
from app.analyzer.engine import analyze, prepare_capture
from tests.helpers import find

LEVELS = {"EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO"}
BANDS = ["Bajo", "Posible", "Moderado", "Alto", "Muy alto"]


def analyzed(analysis, capture, host, path, method="GET"):
    request = find(capture, host, path, method)
    return next(item for item in analysis["requests"] if item["request_id"] == request["seq"])


def request_id(capture, host, path, method="GET"):
    return find(capture, host, path, method)["seq"]


# --- Criterios 2 y 3: bandas esperadas ---


def test_every_labelled_case_is_in_its_expected_band(analysis, capture, manifest):
    labelled = [expected for expected in manifest["requests"] if "expected_band" in expected]
    assert len(labelled) == len(manifest["requests"]) >= 21
    wrong = []
    for expected in labelled:
        item = analyzed(analysis, capture, expected["host"], expected["path"], expected["method"])
        if item["band"] != expected["expected_band"]:
            wrong.append((expected["name"], expected["expected_band"], item["band"], item["score"]))
    assert not wrong, f"(caso, esperada, obtenida, score): {wrong}"


def test_clean_cdn_assets_and_first_party_metrics_are_low(analysis, capture, manifest):
    by_name = {expected["name"]: expected for expected in manifest["requests"]}
    for name in manifest["analysis"]["low_band_assets"]:
        expected = by_name[name]
        item = analyzed(analysis, capture, expected["host"], expected["path"], expected["method"])
        assert item["band"] == "Bajo", (name, item["score"], item["reasons"])
    # Third-party por sí solo no hace tracker.
    logo = analyzed(analysis, capture, "cdn-b.fixtures.test", "/logo.png")
    assert logo["third_party"] is True and logo["score"] == 0 and logo["category"] == "third-party"


def test_bands_match_scores(analysis, analyzer_resources):
    config = analyzer_resources[1]
    limits = [(band["name"], band["max"]) for band in config.bands]
    assert limits == [("Bajo", 20), ("Posible", 40), ("Moderado", 60), ("Alto", 80), ("Muy alto", 100)]
    assert [config.band(score) for score in (0, 20, 21, 40, 41, 60, 61, 80, 81, 100)] == [
        "Bajo", "Bajo", "Posible", "Posible", "Moderado", "Moderado", "Alto", "Alto", "Muy alto", "Muy alto",
    ]
    for item in analysis["requests"]:
        assert 0 <= item["score"] <= 100 and item["band"] == config.band(item["score"])


# --- Criterio 4: sincronización ---


def test_id_sync_is_evidence_with_refs_to_both_requests(analysis, capture, manifest):
    expected = manifest["analysis"]["id_sync"]
    findings = [f for f in analysis["findings"] if f["type"] == "id_sync"]
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding["level"] == "EVIDENCIA"
    assert finding["details"]["domains"] == expected["domains"]
    for request in expected["requests"]:
        assert request_id(capture, request["host"], request["path"]) in finding["evidence_refs"]
    # El claim no reproduce el identificador completo.
    assert expected["value"] not in finding["claim"]
    sync = analyzed(analysis, capture, "cdn-b.fixtures.test", "/sync.gif")
    assert "id_sync" in [reason["signal"] for reason in sync["reasons"]]
    assert sync["category"] == "cross-site"


def test_persistent_id_matches_cookie(analysis, manifest):
    expected = manifest["analysis"]["persistent_id"]
    findings = [f for f in analysis["findings"] if f["type"] == "persistent_id"]
    assert sorted(f["details"]["domain"] for f in findings) == expected["recipients"]
    assert all(f["level"] == "EVIDENCIA" and expected["cookie"] in f["claim"] for f in findings)


# --- Criterio 5: fuga de URL ---


def test_url_leak_is_evidence(analysis, capture, manifest):
    expected = manifest["analysis"]["url_leak"]
    findings = [f for f in analysis["findings"] if f["type"] == "url_leak"]
    assert len(findings) == 1
    assert findings[0]["level"] == "EVIDENCIA" and findings[0]["details"]["parameter"] == expected["parameter"]
    assert findings[0]["evidence_refs"] == [request_id(capture, expected["host"], expected["path"])]
    leak = analyzed(analysis, capture, expected["host"], expected["path"])
    assert "url_leak" in [reason["signal"] for reason in leak["reasons"]]


# --- Criterio 6: decodificación ---


def test_jwt_is_decoded_with_raw_value_intact(analysis, capture, manifest):
    expected = manifest["analysis"]["jwt"]
    rid = request_id(capture, expected["host"], expected["path"])
    rows = [d for d in analysis["decoded_values"] if d["request_id"] == rid and d["name"] == expected["parameter"]]
    assert [row["encoding_chain"] for row in rows] == [expected["encoding_chain"]]
    assert rows[0]["raw_value"] == expected["raw_value"]
    assert json.loads(rows[0]["decoded_value"])["payload"] == expected["payload"]
    # ...y el parámetro original sigue tal como viajó.
    original = [p for p in analysis["parameters"] if p["request_id"] == rid and p["source"] == "query"]
    assert [(p["name"], p["value"]) for p in original] == [(expected["parameter"], expected["raw_value"])]
    assert "jwt" in original[0]["shapes"]


def test_base64_json_post_is_decoded_with_raw_value_intact(analysis, capture, manifest):
    expected = manifest["analysis"]["base64_json"]
    request = find(capture, expected["host"], expected["path"], "POST")
    rows = [d for d in analysis["decoded_values"] if d["request_id"] == request["seq"] and d["source"] == "post_body"]
    assert [row["encoding_chain"] for row in rows] == [["base64"], expected["encoding_chain"]]
    assert json.loads(rows[1]["decoded_value"]) == expected["decoded"]
    assert all(row["raw_value"] == request["post_data"]["data"] for row in rows)
    derived = {p["name"]: p for p in analysis["parameters"] if p["request_id"] == request["seq"]}
    assert derived["user.id"]["value"] == expected["decoded"]["user"]["id"]
    assert derived["user.id"]["category"] == "identity" and derived["user.id"]["encoding_chain"] == ["base64", "json"]


# --- Criterio 7: razones ---


def test_every_score_is_explained(analysis, flood_analysis, analyzer_resources):
    signals = analyzer_resources[1].scoring["signals"]
    for result in (analysis, flood_analysis):
        for item in result["requests"]:
            if item["score"] > 20:
                assert item["reasons"], item
            assert item["score"] == max(0, min(100, sum(reason["weight"] for reason in item["reasons"])))
            for reason in item["reasons"]:
                assert reason["evidence_ref"] == item["request_id"]
                assert reason["level"] in LEVELS and reason["detail"]
                # El peso sale de data/scoring.yaml, no del código.
                assert reason["weight"] == signals[reason["signal"]]["weight"]
                assert reason["level"] == signals[reason["signal"]]["level"]


def test_every_finding_has_level_and_evidence(analysis):
    assert analysis["findings"]
    valid_ids = {item["request_id"] for item in analysis["requests"]}
    for finding in analysis["findings"]:
        assert finding["level"] in LEVELS and finding["claim"]
        assert finding["evidence_refs"] and set(finding["evidence_refs"]) <= valid_ids
    for item in analysis["site"]["data_categories"]:
        assert item["status"] in {"observado", "inferido", "potencial"}
        assert item["evidence_refs"] and set(item["evidence_refs"]) <= valid_ids
    assert {f["level"] for f in analysis["findings"]} >= {"EVIDENCIA", "INFERENCIA"}


# --- Criterio 8: ningún hallazgo EVIDENCIA afirma identidad personal ---

# Lo que un hallazgo EVIDENCIA no puede decir: de quién es un dato o qué persona hay detrás.
FORBIDDEN_IN_EVIDENCE = (
    "persona", "personal", "identidad", "identifica a", "identificó a", "identificado como", "usuario real",
    "nombre real", "su nombre", "su correo", "su email", "su dirección", "pertenece a", "es de un usuario",
    "datos privados", "dueño", "titular", "víctima", "rastrea a", "espía",
)


def synthetic_capture():
    """Captura hostil: valores con forma de dato personal enviados a un tercero y repetidos en cookies."""
    email, rut, name = "juan.perez@example.com", "12.345.678-9", "Juan Pérez González"
    uid = "c0ffee1234567890c0ffee1234567890"

    def request(seq, host, domain, query, third_party=True):
        return {
            "request_id": seq, "seq": seq, "method": "GET", "url": f"https://{host}/c", "host": host,
            "resource_type": "image", "is_navigation": False, "query_params": query,
            "request_headers": [{"name": "user-agent", "value": "x"}, {"name": "referer", "value": "https://site.example/"}],
            "response_headers": [{"name": "set-cookie", "value": f"u={uid}"}], "post_data": None,
            "sizes": {"responseBodySize": 43}, "mime_type": "image/gif", "third_party": third_party,
            "registrable_domain": domain,
        }

    return {
        "start_url": "https://site.example/perfil/juan-perez", "page_url": "https://site.example/perfil/juan-perez",
        "requests": [
            {**request(0, "site.example", "site.example", [], False), "resource_type": "document", "is_navigation": True},
            request(1, "t.tracker.example", "tracker.example",
                    [["email", email], ["name", name], ["rut", rut], ["uid", uid], ["em", email],
                     ["dl", "https%3A%2F%2Fsite.example%2Fperfil%2Fjuan-perez"], ["lat", "-33.4489"], ["lon", "-70.6693"]]),
            request(2, "s.sync.example", "sync.example", [["puid", uid], ["user_email", email], ["fullName", name]]),
        ],
        "cookies": [{"name": "user_email", "value": email, "domain": "site.example"},
                    {"name": "uid", "value": uid, "domain": "site.example"}],
        "storage": [{"storage_type": "local", "key": "profile_name", "value": name, "origin": "https://site.example"}],
        "websockets": [],
    }


@pytest.fixture(scope="module")
def synthetic_analysis(analyzer_resources):
    lists, config = analyzer_resources
    return analyze(synthetic_capture(), lists, config)


def test_evidence_claims_never_assert_personal_identity(analysis, synthetic_analysis):
    checked = 0
    for result in (analysis, synthetic_analysis):
        for finding in result["findings"]:
            if finding["level"] != "EVIDENCIA":
                continue
            checked += 1
            claim = finding["claim"].lower()
            for term in FORBIDDEN_IN_EVIDENCE:
                assert term not in claim, f"claim EVIDENCIA con «{term}»: {finding['claim']}"
        for item in result["site"]["data_categories"]:
            if item["status"] == "observado":
                for term in FORBIDDEN_IN_EVIDENCE:
                    assert term not in item["item"].lower(), item
    assert checked >= 8


def test_personal_looking_values_are_not_echoed_or_upgraded(synthetic_analysis):
    findings = synthetic_analysis["findings"]
    claims = " ".join(finding["claim"] for finding in findings)
    # Ni el correo, ni el nombre, ni el RUT aparecen en ningún claim.
    for secret in ("juan.perez@example.com", "Juan Pérez", "12.345.678-9"):
        assert secret not in claims
    # Lo observable sí se detecta como EVIDENCIA...
    assert {f["type"] for f in findings if f["level"] == "EVIDENCIA"} >= {"id_sync", "persistent_id", "url_leak"}
    # ...pero la forma de email es solo POSIBLE, y un valor con esa forma nunca cuenta como identificador.
    email = [f for f in findings if f["type"] == "email_shape"]
    assert email and all(f["level"] == "POSIBLE" for f in email)
    assert not [f for f in findings if f["level"] == "EVIDENCIA" and "correo" in f["claim"].lower()]
    statuses = {(item["category"], item["status"]) for item in synthetic_analysis["site"]["data_categories"]}
    assert ("LOCATION", "inferido") in statuses and ("LOCATION", "observado") not in statuses


# --- Sitio ---


def test_site_exposure_score_is_the_documented_formula(analysis, analyzer_resources):
    site, config = analysis["site"], analyzer_resources[1]
    spec = config.scoring["site_exposure"]
    assert sum(component["cap"] for component in spec.values()) == 100
    assert [item["component"] for item in site["breakdown"]] == list(spec)
    for item in site["breakdown"]:
        cap, k = spec[item["component"]]["cap"], spec[item["component"]]["k"]
        assert item["points"] == round(cap * (1 - math.exp(-item["count"] / k)), 2) < cap
    assert site["score"] == math.floor(sum(item["points"] for item in site["breakdown"]))
    counts = {item["component"]: item["count"] for item in site["breakdown"]}
    assert counts == {"tracker_domains": 2, "id_sync": 1, "url_leak_recipients": 1, "persistent_id_recipients": 2,
                      "third_party_domains": 2, "stored_items": 4, "fp_scripts": 0, "fp_exfiltration": 0,
                      "first_party_telemetry": 1}  # v1.3.4: el sitio de fixtures tiene un endpoint de eventos propio
    assert site["band"] == config.band(site["score"])
    assert site["mechanisms"]["websocket"] == 1 and site["mechanisms"]["pixel"] >= 4 and site["mechanisms"]["beacon"] == 1


def test_site_exposure_score_never_saturates(analyzer_resources):
    """Con cantidades absurdas el score se acerca a 100 pero no llega, y sigue siendo monótono."""
    lists, config = analyzer_resources
    scores = []
    for domains in (0, 1, 5, 50, 400):
        capture = synthetic_capture()
        base = capture["requests"][1]
        capture["requests"] = capture["requests"][:1] + [
            {**base, "request_id": i + 1, "seq": i + 1, "host": f"t.tracker{i}.example", "registrable_domain": f"tracker{i}.example",
             "url": f"https://t.tracker{i}.example/c"}
            for i in range(domains)
        ]
        capture["cookies"] = capture["cookies"] * (domains + 1)
        scores.append(analyze(capture, lists, config)["site"]["score"])
    assert scores == sorted(scores) and scores[0] < scores[1] < scores[2] < scores[3]
    assert scores[-1] <= 99


def test_analysis_metadata(analysis):
    assert analysis["analyzer_version"] == ANALYZER_VERSION and analysis["partial"] is False
    assert {source["id"] for source in analysis["lists"]} >= {"easylist", "easyprivacy", "test-fixtures"}
    entity_map = [source for source in analysis["lists"] if source["id"] == "entity_map"]
    assert entity_map and entity_map[0]["noncommercial"] is True
    assert {item["entity"] for item in analysis["requests"]} == {"no_disponible"}  # fixtures: sin entidad, no inventada


def test_analysis_is_deterministic_and_does_not_mutate_the_capture(capture, outcome, manifest, analyzer_resources):
    lists, config = analyzer_resources
    prepared = prepare_capture(capture, start_url=manifest["page"], page_url=outcome.result["final_url"])
    before = json.dumps(prepared, default=str, sort_keys=True)
    first = analyze(prepared, lists, config)
    second = analyze(prepared, lists, config)
    assert json.dumps(prepared, default=str, sort_keys=True) == before
    first.pop("duration_ms"), second.pop("duration_ms")
    assert first == second


# --- Criterio 11: rendimiento ---


def test_flood_analysis_is_fast(flood_scan, manifest, analyzer_resources):
    lists, config = analyzer_resources
    outcome, _ = flood_scan
    prepared = prepare_capture(outcome.capture, start_url=manifest["flood"]["page"], page_url=outcome.result["final_url"])
    assert len(prepared["requests"]) == 1500
    started = time.monotonic()
    result = analyze(prepared, lists, config)
    elapsed = time.monotonic() - started
    assert elapsed < 30, f"{elapsed:.1f}s"
    assert len(result["requests"]) == 1500 and result["partial"] is False
    assert result["site"]["summary"]["trackers"] == 0


def test_deadline_marks_the_analysis_as_partial(capture, outcome, manifest, analyzer_resources):
    lists, config = analyzer_resources
    prepared = prepare_capture(capture, start_url=manifest["page"], page_url=outcome.result["final_url"])
    result = analyze(prepared, lists, config, deadline_s=-1)
    # Sin tiempo no se inventa nada: todas las requests salen, sin parámetros, y queda marcado.
    assert result["partial"] is True and result["parameters"] == []
    assert len(result["requests"]) == len(prepared["requests"])


def test_same_value_across_domains_of_one_entity_is_not_sync(analyzer_resources):
    lists, config = analyzer_resources
    assert lists.entity("google-analytics.com") == lists.entity("doubleclick.net") != "no_disponible"
    capture = synthetic_capture()
    # Un identificador de visitante. (Hasta F9 este test usaba un ID de medición de Google,
    # "G-…": desde F10 eso es una constante del sitio y no cuenta como sincronización; lo
    # comprueba el final de este test y tests/f10/test_shared_constants.py.)
    property_id = "9f2c7a41d8e34b6fa1c0e5d2b8f1a6c3"
    capture["requests"] = capture["requests"][:1] + [
        {**capture["requests"][1], "request_id": 1, "seq": 1, "host": "www.google-analytics.com",
         "registrable_domain": "google-analytics.com", "query_params": [["tid", property_id]]},
        {**capture["requests"][1], "request_id": 2, "seq": 2, "host": "stats.doubleclick.net",
         "registrable_domain": "doubleclick.net", "query_params": [["tid", property_id]]},
    ]
    capture["cookies"], capture["storage"] = [], []
    same_owner = analyze(capture, lists, config)
    assert not [f for f in same_owner["findings"] if f["type"] == "id_sync"]
    # El mismo valor hacia un dominio de OTRA organización sí cuenta.
    capture["requests"].append({**capture["requests"][1], "request_id": 3, "seq": 3, "host": "x.otro-dueno.example",
                                "registrable_domain": "otro-dueno.example", "query_params": [["id", property_id]]})
    other_owner = analyze(capture, lists, config)
    sync = [f for f in other_owner["findings"] if f["type"] == "id_sync"]
    assert len(sync) == 1 and sync[0]["details"]["owners"] == 2 and sync[0]["evidence_refs"] == [1, 2, 3]
    # El ID de medición del sitio, aunque llegue a dos organizaciones, no es un identificador del visitante.
    for request in capture["requests"][1:]:
        request["query_params"] = [[request["query_params"][0][0], "G-FEN1ABCD234"]]
    constant = analyze(capture, lists, config)
    assert not [f for f in constant["findings"] if f["type"] == "id_sync"]
    # Desde v1.2 se reconoce antes, como ID de cuenta del sitio (data/account_ids.yaml): se informa aparte
    # y ya ni siquiera entra al cruce (por eso no figura entre los valores compartidos descartados).
    summary = constant["site"]["summary"]
    assert [(item["rule"], item["value"]) for item in summary["account_ids"]] == [("ga_measurement_id", "G-FEN1ABCD234")]
    assert summary["shared_values_excluded"]["by_reason"] == {}
