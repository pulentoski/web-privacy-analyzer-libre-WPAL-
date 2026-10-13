"""Instrumentación de fingerprinting contra la página de fixtures (criterios 1 y 4-9 de F4)."""

import json

import pytest
from playwright.async_api import async_playwright

from app.browser.fp_monitor import KNOWN_APIS, FingerprintMonitor
from app.browser.launcher import launch_browser, new_context
from tests.helpers import find, run_async

FORBIDDEN_CLAIMS = ("fingerprinting confirmado", "confirmado", "confirma", "persona", "identidad", "identifica a", "rastrea a", "espía")


def calls_of(capture, script_url):
    return {c["api"]: c for c in capture["fingerprinting"]["calls"] if c["script_url"] == script_url}


def findings_of(analysis, script_url):
    return {f["heuristic"]: f for f in analysis["fingerprinting"]["findings"] if f["script_url"] == script_url}


def analyzed(analysis, capture, host, path, method="GET"):
    request = find(capture, host, path, method)
    return next(item for item in analysis["requests"] if item["request_id"] == request["seq"])


def test_scan_completes_and_instrumentation_reports(fp_scan):
    outcome, _ = fp_scan
    assert outcome.error is None, outcome.error
    fingerprinting = outcome.capture["fingerprinting"]
    assert fingerprinting["truncated"] is False and fingerprinting["rejected"] == 0
    assert fingerprinting["messages"] > 0
    # Todo lo que la página dice tener disponible está en el catálogo cerrado del worker.
    assert set(fingerprinting["available"]) <= KNOWN_APIS and len(fingerprinting["available"]) >= 40


# --- Criterio 4: detección y atribución ---


def test_each_technique_is_detected_and_attributed_to_its_script(fp_analysis, manifest):
    for name, expected in manifest["fingerprinting"]["scripts"].items():
        found = findings_of(fp_analysis, expected["url"])
        assert sorted(h for h in found if h != "exfiltration") == expected["heuristics"], name
        script = next((s for s in fp_analysis["fingerprinting"]["scripts"] if s["script_url"] == expected["url"]), None)
        assert script is not None, f"{name}: sin llamadas registradas"
        assert script["fingerprinting_inferred"] is expected["fingerprinting_inferred"], name
    # Las seis técnicas pedidas, cada una en el script que la ejecuta.
    technique_script = {f["heuristic"]: f["script_url"] for f in fp_analysis["fingerprinting"]["findings"]}
    scripts = manifest["fingerprinting"]["scripts"]
    assert technique_script["canvas_fingerprinting"] == scripts["fp"]["url"]
    assert technique_script["audio_fingerprinting"] == scripts["fp"]["url"]
    assert technique_script["webgl_fingerprinting"] == scripts["fp"]["url"]
    assert technique_script["property_sweep"] == scripts["fp"]["url"]
    assert technique_script["font_enumeration"] == scripts["fonts"]["url"]
    assert technique_script["webrtc_ip_discovery"] == scripts["webrtc"]["url"]


def test_levels_of_fingerprinting_findings(fp_analysis, manifest):
    fp = findings_of(fp_analysis, manifest["fingerprinting"]["scripts"]["fp"]["url"])
    # Leer el renderer es un hecho observado; que sea fingerprinting es una inferencia.
    assert fp["webgl_unmasked_read"]["level"] == "EVIDENCIA"
    for heuristic in ("webgl_fingerprinting", "canvas_fingerprinting", "audio_fingerprinting", "property_sweep"):
        assert fp[heuristic]["level"] == "INFERENCIA", heuristic
    for finding in fp_analysis["fingerprinting"]["findings"]:
        assert finding["call_refs"] or finding["request_refs"]
        assert finding["level"] in {"EVIDENCIA", "INFERENCIA"}
        for term in FORBIDDEN_CLAIMS:
            assert term not in finding["claim"].lower(), finding["claim"]
    webrtc = findings_of(fp_analysis, manifest["fingerprinting"]["scripts"]["webrtc"]["url"])["webrtc_ip_discovery"]
    assert webrtc["details"]["blocked_by_policy"] is True


def test_raw_calls_of_the_fp_script(fp_capture, manifest):
    calls = calls_of(fp_capture, manifest["fingerprinting"]["scripts"]["fp"]["url"])
    read = calls["canvas.toDataURL"]["details"]["reads"][0]
    assert (read["canvas_width"], read["canvas_height"], read["text_written"]) == (240, 60, True) and read["colors"] >= 2
    # Del canvas y del audio solo queda hash y longitud, nunca el contenido.
    assert len(read["sha256"]) == 64 and read["length"] > 1000 and set(read) == {
        "kind", "sha256", "length", "canvas_width", "canvas_height", "read_width", "read_height", "text_written", "colors"}
    audio = calls["audio.getChannelData"]["details"]["reads"][0]
    assert audio["kind"] == "audio" and len(audio["sha256"]) == 64 and audio["length"] == 4410 * 4
    assert calls["webgl.UNMASKED_RENDERER_WEBGL"]["details"]["value"]
    assert calls["navigator.userAgent"]["details"]["value"].startswith("Mozilla/5.0")
    fonts = calls_of(fp_capture, manifest["fingerprinting"]["scripts"]["fonts"]["url"])
    assert fonts["canvas.measureText"]["count"] == 60
    assert fonts["canvas.measureText"]["details"]["distinct_fonts"] == manifest["fingerprinting"]["scripts"]["fonts"]["distinct_fonts"]


# --- Criterio 5: exfiltración ---


def test_exfiltration_is_evidence_with_refs_to_call_and_request(fp_analysis, fp_capture, manifest):
    expected = manifest["fingerprinting"]["exfiltration"]
    request_id = find(fp_capture, expected["host"], expected["path"])["seq"]
    script = manifest["fingerprinting"]["scripts"]["fp"]["url"]
    calls = fp_analysis  # las llamadas en memoria usan su índice como call_id
    by_api = {
        f["details"]["api"]: f for f in fp_analysis["fingerprinting"]["findings"]
        if f["heuristic"] == "exfiltration" and f["details"]["form"] in ("valor", "sha256 del contenido leído")
    }
    prepared_calls = {
        (c["api"], c["script_url"]): index for index, c in enumerate(fp_capture["fingerprinting"]["calls"])
    }
    for value in expected["values"]:
        finding = by_api[value["api"]]
        assert finding["level"] == "EVIDENCIA"
        assert finding["details"]["parameter"] == value["parameter"] and finding["details"]["form"] == value["form"]
        assert finding["request_refs"] == [request_id]
        assert finding["call_refs"] == [prepared_calls[(value["api"], script)]]
        assert finding["script_url"] == script
    assert calls["fingerprinting"]["truncated"] is False
    item = analyzed(fp_analysis, fp_capture, expected["host"], expected["path"])
    assert "fp_exfiltration" in [reason["signal"] for reason in item["reasons"]]


def test_attribute_states(fp_analysis, manifest):
    states = {a["attribute"]: a for a in fp_analysis["fingerprinting"]["attributes"]}
    for attribute, status in manifest["fingerprinting"]["attributes"].items():
        assert states[attribute]["status"] == status, attribute
    assert {a["status"] for a in states.values()} <= {"NO_DISPONIBLE", "DISPONIBLE", "UTILIZADO", "OBSERVADO"}
    renderer = states["webgl_renderer"]
    assert renderer["value"] and renderer["call_refs"] and renderer["request_refs"]
    # El contenido del canvas nunca se guarda como valor.
    assert states["canvas"]["value"] is None and states["audio"]["value"] is None


def test_expected_bands_of_the_fingerprinting_page(fp_analysis, fp_capture, manifest):
    wrong = []
    for expected in manifest["fingerprinting"]["expected_bands"]:
        item = analyzed(fp_analysis, fp_capture, expected["host"], expected["path"], expected.get("method", "GET"))
        if item["band"] != expected["expected_band"]:
            wrong.append((expected["path"], expected["expected_band"], item["band"], item["score"]))
    assert not wrong, f"(caso, esperada, obtenida, score): {wrong}"
    beacon = analyzed(fp_analysis, fp_capture, "tracker-a.fixtures.test", "/fp-beacon", "POST")
    assert "fp_script_initiator" in [reason["signal"] for reason in beacon["reasons"]]
    counts = {item["component"]: item["count"] for item in fp_analysis["site"]["breakdown"]}
    assert counts["fp_scripts"] == 3 and counts["fp_exfiltration"] >= 2


# --- Criterio 6: usos benignos ---


def test_benign_canvas_use_is_not_fingerprinting(fp_scan, fp_analysis, manifest):
    outcome, _ = fp_scan
    benign = manifest["fingerprinting"]["scripts"]["benign"]["url"]
    calls = calls_of(outcome.capture, benign)
    assert findings_of(fp_analysis, benign) == {}
    assert benign not in fp_analysis["site"]["summary"]["fingerprinting_scripts"]
    # El gráfico escribió texto y 4 colores, pero nunca se leyó.
    assert calls["canvas.fillText"]["count"] == 4 and "canvas.toDataURL" not in calls
    # La animación corrió completa (5 s) y cada lectura se contó...
    done = find(outcome.capture, "site.fixtures.test", "/fp/animation-done")
    frames = int(dict(done["query_params"])["frames"])
    assert frames >= 100 and calls["canvas.getImageData"]["count"] == frames
    # ...en UNA fila agregada, sin detalle por llamada y sin truncar ni saturar el canal.
    assert calls["canvas.getImageData"]["details"] == {}
    fingerprinting = outcome.capture["fingerprinting"]
    assert fingerprinting["truncated"] is False and fingerprinting["rejected"] == 0
    assert fingerprinting["messages"] < 60 and len(fingerprinting["calls"]) < 80
    # El scan no se degradó: terminó por inactividad de red, no por timeout.
    assert outcome.capture["end_reason"] == "network_idle" and outcome.capture["duration_ms"] < 20000


# --- Criterio 7: abuso del binding ---


def test_binding_abuse_fails_and_forges_nothing(fp_scan, fp_analysis, manifest):
    outcome, reports = fp_scan
    marker = manifest["fingerprinting"]["forged_marker"]
    assert len(reports) == 1, "el script hostil no llegó a reportar"
    report = reports[0]
    # No logró llamar a nada, no encontró el canal y no interceptó ni token ni nombre.
    assert report["calls"] == 0 and report["leaked"] == []
    assert [name for name in report["found"] if "playwright" in name.lower() or "__pw" in name] == []
    fingerprinting = outcome.capture["fingerprinting"]
    assert fingerprinting["rejected"] == 0  # ni siquiera llegó un evento inválido
    dumped = json.dumps(fingerprinting) + json.dumps(fp_analysis["fingerprinting"])
    assert marker not in dumped and "FORGED-RENDERER" not in dumped
    # Sus llamadas reales quedan atribuidas a él, aunque fabricó Error.prepareStackTrace.
    abuse = calls_of(outcome.capture, manifest["fingerprinting"]["scripts"]["abuse"]["url"])
    assert abuse["canvas.toDataURL"]["count"] == 1 and abuse["navigator.userAgent"]["count"] == 1
    # Lo que envió con las primitivas envenenadas (JSON.stringify, toJSON, push) llegó íntegro.
    assert abuse["navigator.platform"]["count"] == 1 and abuse["screen.width"]["count"] == 1


class FakeFrame:
    url = "http://site.example/"


FORGED = "http://evil.example/forged.js"


def monitor_with(*messages):
    monitor = FingerprintMonitor(context=None)
    for message in messages:
        monitor._on_message({"frame": FakeFrame()}, *message)
    return monitor


def valid(monitor, **overrides):
    return json.dumps({"t": monitor._token, "c": [["canvas.toDataURL", FORGED, 1]], "f": [], "v": [], "d": [], "x": False, **overrides})


def test_monitor_requires_the_secret_token():
    monitor = FingerprintMonitor(context=None)
    for token in ("", "x", "0" * 48, None, 123, monitor._token[:-1], monitor._token + "0"):
        payload = json.loads(valid(monitor))
        payload["t"] = token
        monitor._on_message({"frame": FakeFrame()}, json.dumps(payload))
    result = monitor.result()
    assert result["calls"] == [] and result["rejected"] == 7 and result["messages"] == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"c": [["api.inventada", FORGED, 1]]},
        {"c": [["canvas.toDataURL", FORGED, 0]]},
        {"c": [["canvas.toDataURL", FORGED, -5]]},
        {"c": [["canvas.toDataURL", FORGED, 10**12]]},
        {"c": [["canvas.toDataURL", FORGED, 1.5]]},
        {"c": [["canvas.toDataURL", FORGED, True]]},
        {"c": [["canvas.toDataURL", "x" * 5000, 1]]},
        {"c": [["canvas.toDataURL", 7, 1]]},
        {"c": [["canvas.toDataURL", FORGED]]},
        {"c": "no-lista"},
        {"c": [["canvas.toDataURL", FORGED, 1]] * 5000},
        {"v": [["navigator.userAgent", FORGED, "v" * 1000]]},
        {"v": [["navigator.userAgent", FORGED, {"objeto": 1}]]},
        {"f": [[FORGED, 100000]]},
        {"d": [{"k": "canvas", "a": "canvas.toDataURL", "s": FORGED}]},
        {"d": [{"k": "otro", "a": "canvas.toDataURL", "s": FORGED, "h": None, "l": 1}]},
        {"d": [{"k": "audio", "a": "audio.getChannelData", "s": FORGED, "h": "no-es-hash", "l": 1}]},
        {"d": [{"k": "audio", "a": "audio.getChannelData", "s": FORGED, "h": "zz" * 32, "l": 1}]},
        {"d": [{"k": "canvas", "a": "canvas.toDataURL", "s": FORGED, "cw": 10**9, "ch": 1, "rw": 1, "rh": 1, "tx": True, "nc": 1, "h": None, "l": 1}]},
        {"d": [{"k": "canvas", "a": "canvas.toDataURL", "s": FORGED, "cw": 1, "ch": 1, "rw": 1, "rh": 1, "tx": "si", "nc": 1, "h": None, "l": 1}]},
        {"d": [{"k": "audio", "a": "audio.getChannelData", "s": FORGED, "h": None, "l": 1, "extra": "campo"}]},
        {"a": ["api.inventada"]},
        {"campo_extra": 1},
    ],
)
def test_monitor_rejects_malformed_events_entirely(overrides):
    monitor = FingerprintMonitor(context=None)
    monitor._on_message({"frame": FakeFrame()}, valid(monitor, **overrides))
    result = monitor.result()
    # Un lote con un solo campo inválido se descarta completo: nada parcial llega a los resultados.
    assert result["calls"] == [] and result["rejected"] == 1 and result["messages"] == 0


@pytest.mark.parametrize("args", [(), (1,), (None,), ({"t": "x"},), ("{", ), ("[]",), ("null",), ("a", "b"), ("x" * 200000,), ('{"t":' * 50000,)])
def test_monitor_rejects_garbage_arguments(args):
    monitor = monitor_with(args)
    assert monitor.result()["calls"] == [] and monitor.result()["rejected"] == 1


def test_monitor_rate_limit_and_row_cap():
    monitor = FingerprintMonitor(context=None)
    for _ in range(500):  # ráfaga: muy por encima del rate limit
        monitor._on_message({"frame": FakeFrame()}, valid(monitor))
    result = monitor.result()
    assert result["messages"] <= 45 and result["rejected"] >= 455 and result["truncated"] is True
    assert result["calls"][0]["count"] == result["messages"]
    # Tope de filas (api, script, frame) distintas.
    monitor = FingerprintMonitor(context=None)
    monitor._tokens = 10**9
    for batch in range(12):
        counts = [["canvas.toDataURL", f"http://x.example/{batch}-{i}.js", 1] for i in range(400)]
        monitor._on_message({"frame": FakeFrame()}, valid(monitor, c=counts))
    result = monitor.result()
    assert len(result["calls"]) == 2000 and result["truncated"] is True


def test_monitor_accepts_a_valid_event_and_uses_the_trusted_frame_url():
    monitor = FingerprintMonitor(context=None)
    detail = {"k": "canvas", "a": "canvas.toDataURL", "s": "http://a/x.js", "cw": 200, "ch": 50, "rw": 200, "rh": 50,
              "tx": True, "nc": 2, "h": "ab" * 32, "l": 1234}
    monitor._on_message(
        {"frame": FakeFrame()},
        valid(monitor, c=[["canvas.toDataURL", "http://a/x.js", 3]], v=[["navigator.userAgent", "http://a/x.js", "UA"]],
              f=[["http://a/x.js", 61]], d=[detail], a=["canvas.toDataURL", "canvas.toDataURL"]),
    )
    result = monitor.result()
    rows = {row["api"]: row for row in result["calls"]}
    assert result["rejected"] == 0 and result["available"] == ["canvas.toDataURL"]
    assert rows["canvas.toDataURL"]["count"] == 3 and rows["canvas.toDataURL"]["details"]["reads"][0]["sha256"] == "ab" * 32
    assert rows["navigator.userAgent"]["details"] == {"value": "UA"}
    assert rows["canvas.measureText"]["details"] == {"distinct_fonts": 61}
    # La URL del frame la pone Playwright, no la página.
    assert {row["frame_url"] for row in result["calls"]} == {"http://site.example/"}


# --- Criterios 8 y 9: valores de retorno idénticos y apariencia nativa ---


@pytest.fixture(scope="module")
def probes(manifest):
    async def collect():
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright)
            try:
                results = []
                for instrumented in (False, True):
                    context = await new_context(browser)
                    monitor = None
                    if instrumented:
                        monitor = FingerprintMonitor(context)
                        await monitor.install()
                    page = await context.new_page()
                    await page.goto(manifest["fingerprinting"]["probe_page"])
                    results.append(await page.evaluate("__probe()"))
                    if monitor:
                        await page.wait_for_timeout(800)
                        results.append(monitor.result())
                    await context.close()
                return results
            finally:
                await browser.close()

    return run_async(collect())


def test_return_values_are_identical_with_and_without_instrumentation(probes):
    plain, instrumented, _ = probes
    assert set(plain) == set(instrumented)
    different = [key for key in plain if plain[key] != instrumented[key]]
    assert different == [], {key: (plain[key], instrumented[key]) for key in different}
    # La sonda realmente ejercitó las APIs (no se comparan dos vacíos).
    assert plain["dataUrl"].startswith("data:image/png;base64,") and len(plain["imageData"]) > 1000
    assert isinstance(plain["webgl"], list) and plain["webgl"][1] and isinstance(plain["audio"], list)
    assert plain["navigator"][0].startswith("Mozilla/5.0") and plain["errors"][0].startswith("TypeError")
    # Ningún global delata la instrumentación (XRWebGLBinding es una API nativa del navegador).
    assert instrumented["ownKeys"][2] == plain["ownKeys"][2] == "XRWebGLBinding"


def test_the_instrumented_probe_was_really_instrumented(probes):
    _, _, recorded = probes
    apis = {call["api"] for call in recorded["calls"]}
    assert {"canvas.toDataURL", "canvas.getImageData", "canvas.measureText", "webgl.UNMASKED_RENDERER_WEBGL",
            "audio.getChannelData", "webrtc.RTCPeerConnection", "navigator.userAgent", "screen.width",
            "intl.timeZone", "window.matchMedia", "fonts.check"} <= apis
    assert recorded["rejected"] == 0


def test_wrapped_functions_look_native(probes):
    plain, instrumented, _ = probes
    assert len(instrumented["functions"]) >= 35
    for name, (via_prototype, via_method, fn_name, length, kind, has_prototype, as_string) in instrumented["functions"].items():
        assert "[native code]" in via_prototype, name
        assert via_prototype == via_method == as_string, name
        assert via_prototype.startswith("function ") and kind == "function", name
        # Idéntico, carácter a carácter, a la función sin envolver.
        assert plain["functions"][name] == [via_prototype, via_method, fn_name, length, kind, has_prototype, as_string], name
    assert instrumented["functions"]["toDataURL"][0] == "function toDataURL() { [native code] }"
    assert instrumented["functions"]["functionToString"][0] == "function toString() { [native code] }"
    assert instrumented["functions"]["userAgentGet"][0] == "function get userAgent() { [native code] }"


# --- Criterio 1: Referer ---


def test_referer_exposure_is_classified_from_the_header_actually_sent(fp_analysis, fp_capture, manifest):
    page = manifest["fingerprinting"]["page"]
    for expected in manifest["fingerprinting"]["referer"]:
        request = find(fp_capture, expected["host"], expected["path"])
        sent = [h["value"] for h in request["request_headers"] if h["name"].lower() == "referer"]
        item = analyzed(fp_analysis, fp_capture, expected["host"], expected["path"])
        assert item["referer"] == expected["exposure"], expected["label"]
        assert sent == {"full_url": [page], "origin_only": ["http://site.fixtures.test/"], "absent": []}[expected["exposure"]]
    findings = [f for f in fp_analysis["findings"] if f["type"] == "referer_leak"]
    assert len(findings) == 1 and findings[0]["level"] == "EVIDENCIA"
    full = find(fp_capture, "tracker-a.fixtures.test", "/ref-full.gif")
    assert findings[0]["evidence_refs"] == [full["seq"]] and findings[0]["details"]["domain"] == "tracker-a.fixtures.test"
    reasons = analyzed(fp_analysis, fp_capture, "tracker-a.fixtures.test", "/ref-full.gif")["reasons"]
    assert "referer_full_url" in [reason["signal"] for reason in reasons]
    # El Referer queda además como una fuente más en la tabla de parámetros.
    sources = [p for p in fp_analysis["parameters"] if p["source"] == "referer" and p["request_id"] == full["seq"]]
    assert [p["value"] for p in sources] == [page] and "url" in sources[0]["shapes"]
    # Las requests first-party no se clasifican.
    assert analyzed(fp_analysis, fp_capture, "site.fixtures.test", "/static/fp/benign.js")["referer"] is None
    assert fp_analysis["site"]["summary"]["referer"]["full_url"] == 1


def test_calls_without_script_url_are_attributed_to_their_frame(analyzer_resources):
    """Código evaluado (eval, new Function) no tiene URL: se atribuye al documento del frame."""
    from app.analyzer.engine import analyze

    lists, config = analyzer_resources
    frame = "https://ads.example/runner.html?x=1#y"
    capture = {
        "start_url": "https://site.example/", "page_url": "https://site.example/", "requests": [], "cookies": [],
        "storage": [], "websockets": [],
        "fingerprinting": {"available": [], "truncated": False, "calls": [
            {"call_id": 1, "api": "webgl.UNMASKED_RENDERER_WEBGL", "script_url": "", "frame_url": frame, "count": 1,
             "details": {"value": "ANGLE (GPU de prueba)"}},
            {"call_id": 2, "api": "navigator.userAgent", "script_url": "", "frame_url": "", "count": 1, "details": {}},
        ]},
    }
    result = analyze(capture, lists, config)["fingerprinting"]
    label = "(inline o eval en https://ads.example/runner.html)"
    assert {f["script_url"] for f in result["findings"]} == {label}
    assert {s["script_url"]: s["fingerprinting_inferred"] for s in result["scripts"]} == {label: True, "": False}


def test_a_value_contained_in_another_matched_value_is_not_a_separate_exfiltration(analyzer_resources):
    from app.analyzer.engine import analyze

    lists, config = analyzer_resources
    agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/153.0.0.0 Safari/537.36"
    request = {
        "request_id": 1, "seq": 1, "method": "GET", "url": "https://t.tracker.example/c", "host": "t.tracker.example",
        "resource_type": "image", "is_navigation": False, "query_params": [["ua", agent]], "request_headers": [],
        "response_headers": [], "post_data": None, "sizes": None, "mime_type": None, "third_party": True,
        "registrable_domain": "tracker.example",
    }
    calls = [
        {"call_id": 1, "api": "navigator.userAgent", "script_url": "https://t.tracker.example/t.js", "frame_url": "", "count": 1, "details": {"value": agent}},
        {"call_id": 2, "api": "navigator.platform", "script_url": "https://t.tracker.example/t.js", "frame_url": "", "count": 1, "details": {"value": "Linux x86_64"}},
    ]
    capture = {"start_url": "https://site.example/", "page_url": "https://site.example/", "requests": [request], "cookies": [],
               "storage": [], "websockets": [], "fingerprinting": {"available": [], "truncated": False, "calls": calls}}
    found = [f["details"]["api"] for f in analyze(capture, lists, config)["fingerprinting"]["findings"] if f["heuristic"] == "exfiltration"]
    assert found == ["navigator.userAgent"]
    # Si la plataforma viaja por su cuenta, sí cuenta.
    request["query_params"] = [["ua", agent], ["plat", "Linux x86_64"]]
    found = sorted(f["details"]["api"] for f in analyze(capture, lists, config)["fingerprinting"]["findings"] if f["heuristic"] == "exfiltration")
    assert found == ["navigator.platform", "navigator.userAgent"]
