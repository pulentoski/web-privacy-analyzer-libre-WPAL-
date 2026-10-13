"""Perfiles de emulación y detector de inconsistencias (criterios 4 y 5 de F7)."""

import pytest

from app.analyzer.consistency import check
from app.browser import profiles
from app.browser.capture import run_scan
from app.browser.launcher import CHROMIUM_ARGS, PROXY_BYPASS
from tests.helpers import fixtures_call, run_async

PROBE_PAGE = "http://site.fixtures.test/fp/probe"


@pytest.fixture(scope="module")
def rules():
    return profiles.consistency_rules()


@pytest.fixture(scope="module")
def scans(manifest):
    """Un scan por perfil (y uno real), con sondeo, y lo que recibió el servidor en cada uno."""
    names = [profiles.REAL, *manifest["privacy_test"]["profiles"]["coherent"], manifest["privacy_test"]["profiles"]["incoherent"]]
    out = {}
    for name in names:
        fixtures_call("/__reset", "POST")
        outcome = run_async(run_scan(PROBE_PAGE, profile_name=name, probe=True))
        assert outcome.error is None, (name, outcome.error)
        out[name] = (outcome, fixtures_call("/__received")["requests"])
    return out


def test_real_browser_has_no_inconsistencies(scans):
    info = scans[profiles.REAL][0].result["profile"]
    assert info["name"] == "real" and info["inconsistencies"] == []
    assert info["js"]["webdriver"] is False and info["js"]["artifacts"] == []


def test_each_coherent_profile_has_zero_inconsistencies(scans, manifest):
    for name in manifest["privacy_test"]["profiles"]["coherent"]:
        info = scans[name][0].result["profile"]
        assert info["declared_coherent"] is True
        assert info["inconsistencies"] == [], (name, info["inconsistencies"])
        assert info["js"]["artifacts"] == [], name  # la emulación no deja rastro visible a un script


def test_incoherent_profile_is_detected(scans, manifest):
    expected = manifest["privacy_test"]["profiles"]
    info = scans[expected["incoherent"]][0].result["profile"]
    found = {item["rule"]: item for item in info["inconsistencies"]}
    print("\nInconsistencias del perfil incoherente:")
    for item in info["inconsistencies"]:
        print(f"  [{item['level']}] {item['rule']}: {item['title']} -> {item['observed']}")
    assert set(expected["incoherent_expected_rules"]) <= set(found)
    systems = found["os_mismatch"]["observed"]
    assert "windows" in systems["User-Agent (JavaScript)"] and "macos" in systems["navigator.platform"] and "linux" in systems["GPU (WebGL)"]
    assert "America/Santiago → CL" in found["timezone_vs_locale"]["observed"]["zona horaria"]
    for item in info["inconsistencies"]:
        # Los valores son lo observado; que sea detectable es una inferencia.
        assert item["level"] == "EVIDENCIA" and item["inference_level"] == "INFERENCIA" and item["observed"]
        assert "detectable" in item["inference"]


def test_headers_and_javascript_agree_in_every_profile(scans):
    """Lo que recibe el servidor y lo que lee un script son el mismo navegador."""
    for name, (outcome, received) in scans.items():
        info = outcome.result["profile"]
        js, headers = info["js"], info["headers"]
        document = next(entry for entry in received if entry["path"] == "/fp/probe")
        # Cabeceras capturadas == cabeceras que llegaron al servidor.
        assert headers["user-agent"] == document["user_agent"], name
        assert headers["sec-ch-ua-platform"] == document["sec_ch_ua_platform"], name
        assert headers["sec-ch-ua-mobile"] == document["sec_ch_ua_mobile"], name
        # JavaScript == cabeceras.
        assert js["user_agent"] == headers["user-agent"], name
        assert f'"{js["ua_ch"]["platform"]}"' == headers["sec-ch-ua-platform"], name
        assert ("?1" if js["ua_ch"]["mobile"] else "?0") == headers["sec-ch-ua-mobile"], name
        assert headers["accept-language"].split(",")[0].split(";")[0] == js["languages"][0], name
        # Todas las requests de la visita (incluidos subrecursos) llevan el mismo User-Agent.
        assert {entry["user_agent"] for entry in received} == {js["user_agent"]}, name
        major = js["user_agent"].split("Chrome/")[1].split(".")[0]
        assert f"Chromium {major}" in js["ua_ch"]["brands"] and f'"Chromium";v="{major}"' in headers["sec-ch-ua"], name
        assert "Headless" not in js["user_agent"]


def test_profile_values_are_applied(scans):
    windows = scans["windows-chrome-es-cl"][0].result["profile"]["js"]
    assert "Windows NT 10.0" in windows["user_agent"] and windows["platform"] == "Win32"
    assert windows["ua_ch"]["platform"] == "Windows" and windows["ua_ch"]["platform_version"] == "15.0.0"
    assert windows["timezone"] == "America/Santiago" and windows["languages"][0] == "es-CL"
    assert windows["screen"] == [1366, 768] and windows["hardware_concurrency"] == 8 and windows["device_memory"] == 8
    assert "Direct3D11" in windows["webgl_renderer"]
    android = scans["android-chrome-es-cl"][0].result["profile"]["js"]
    assert android["ua_ch"]["mobile"] is True and android["max_touch_points"] == 5 and android["ua_ch"]["model"] == "Pixel 8"
    assert android["screen"] == [412, 915] and "Mobile Safari" in android["user_agent"]
    mac = scans["macos-chrome-es-cl"][0].result["profile"]["js"]
    assert mac["platform"] == "MacIntel" and mac["device_pixel_ratio"] == 2 and "Apple" in mac["webgl_renderer"]


def test_instrumentation_records_the_emulated_values(manifest):
    """Orden de los init scripts: el perfil va antes, así la instrumentación ve lo mismo que el sitio."""
    outcome = run_async(run_scan(manifest["fingerprinting"]["page"], profile_name="windows-chrome-es-cl"))
    script = manifest["fingerprinting"]["scripts"]["fp"]["url"]
    read = {call["api"]: call["details"].get("value") for call in outcome.capture["fingerprinting"]["calls"] if call["script_url"] == script}
    assert read["navigator.platform"] == "Win32"
    assert "Windows NT" in read["navigator.userAgent"]
    assert "Direct3D11" in read["webgl.UNMASKED_RENDERER_WEBGL"]
    assert read["intl.timeZone"] == "America/Santiago" and read["screen.width"] == "1366"
    # Y el valor emulado es el que sale hacia el tracker del fixture.
    collect = next(r for r in outcome.capture["requests"] if r["path"] == "/fp-collect.gif")
    assert "Direct3D11" in dict(collect["query_params"])["r"]


def test_what_a_profile_does_not_change(scans):
    real = scans[profiles.REAL][0].result["profile"]["js"]
    windows = scans["windows-chrome-es-cl"][0].result["profile"]["js"]
    # La huella de canvas la produce el equipo real: el perfil no la toca.
    assert real["canvas_hash"] and real["canvas_hash"] == windows["canvas_hash"]


def test_unknown_profile_is_rejected():
    for name in ("no-existe", "../../etc/passwd", "", "REAL", "x" * 80):
        with pytest.raises(profiles.UnknownProfile):
            profiles.load_profile(name)


def test_browser_own_traffic_is_disabled_by_configuration():
    joined = " ".join(CHROMIUM_ARGS)
    for flag in ("--no-pings", "--disable-domain-reliability", "--gaia-url=http://blackhole.invalid", "--component-updater=url-source=http://blackhole.invalid"):
        assert flag in joined
    # El único host fuera del proxy es uno que no puede resolver.
    assert PROXY_BYPASS == "<-loopback>;blackhole.invalid"


# --- Reglas, sin navegador ---

BASE_JS = {"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0 Safari/537.36", "platform": "Win32",
           "ua_ch": {"platform": "Windows", "mobile": False}, "languages": ["es-CL", "es"], "timezone": "America/Santiago",
           "screen": [1366, 768], "max_touch_points": 0, "webgl_renderer": "ANGLE (Intel, Direct3D11)", "webdriver": False, "artifacts": []}
BASE_HEADERS = {"user-agent": BASE_JS["user_agent"], "accept-language": "es-CL,es;q=0.9", "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-mobile": "?0"}


def rules_of(js_changes=None, header_changes=None, rules=None):
    return {item["rule"] for item in check({**BASE_JS, **(js_changes or {})}, {**BASE_HEADERS, **(header_changes or {})}, rules)}


def test_consistency_rules(rules):
    assert rules_of(rules=rules) == set()
    assert rules_of({"platform": "MacIntel"}, rules=rules) == {"os_mismatch"}
    assert rules_of({"webgl_renderer": "llvmpipe (LLVM 15)"}, rules=rules) == {"os_mismatch"}
    assert rules_of(header_changes={"sec-ch-ua-platform": '"Linux"'}, rules=rules) == {"os_mismatch"}
    assert rules_of(header_changes={"user-agent": "otro"}, rules=rules) == {"ua_js_vs_header"}
    assert rules_of({"languages": ["en-US"]}, {"accept-language": "en-US"}, rules=rules) == {"timezone_vs_locale"}
    assert rules_of({"languages": ["en-US"]}, rules=rules) == {"language_js_vs_header", "timezone_vs_locale"}
    assert rules_of({"ua_ch": {"platform": "Windows", "mobile": True}}, rules=rules) >= {"mobile_mismatch", "mobile_without_touch"}
    assert rules_of({"webdriver": True}, rules=rules) == {"webdriver_flag"}
    assert rules_of({"artifacts": ["navigator.platform: toString no nativo"]}, rules=rules) == {"spoofing_artifact"}
    # Render por software no delata sistema; zona sin país conocido no se evalúa.
    assert rules_of({"webgl_renderer": "ANGLE (Google, Vulkan (SwiftShader Device))", "timezone": "UTC", "languages": ["en-US"]}, {"accept-language": "en-US"}, rules=rules) == set()


def test_consistency_tolerates_missing_data(rules):
    assert check(None, None, rules) == []
    assert check({}, {}, rules) == []
    assert check({"languages": None, "screen": None, "ua_ch": None}, {"accept-language": None}, rules) == []
