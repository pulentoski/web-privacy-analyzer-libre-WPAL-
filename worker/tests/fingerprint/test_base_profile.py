"""Perfil base (ADR 008): el worker no se presenta como bot. Verificado desde el sitio de fixtures."""

from tests.helpers import fixtures_call


def values_read_by(capture, script_url):
    return {c["api"]: c["details"].get("value") for c in capture["fingerprinting"]["calls"] if c["script_url"] == script_url}


def test_user_agent_seen_by_the_server_is_not_headless(fp_scan):
    received = fixtures_call("/__received")["requests"]
    assert received
    agents = {entry["user_agent"] for entry in received}
    assert len(agents) == 1, agents
    agent = agents.pop()
    assert "Headless" not in agent and "headless" not in agent.lower()
    assert agent.startswith("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
    # Client Hints coherentes con ese User-Agent: misma versión mayor y sin marca de headless.
    major = agent.split("Chrome/")[1].split(".")[0]
    hints = {entry["sec_ch_ua"] for entry in received if entry["sec_ch_ua"]}
    assert hints and all(f'"Chromium";v="{major}"' in hint and "Headless" not in hint for hint in hints), hints


def test_what_a_script_reads_is_coherent_and_not_automated(fp_scan, manifest):
    outcome, _ = fp_scan
    seen = values_read_by(outcome.capture, manifest["fingerprinting"]["scripts"]["fp"]["url"])
    received = fixtures_call("/__received")["requests"]
    # Lo que lee JavaScript es lo mismo que viaja en la cabecera.
    assert seen["navigator.userAgent"] == received[0]["user_agent"]
    assert "Headless" not in seen["navigator.userAgent"]
    assert seen["navigator.webdriver"] == "false"
    assert seen["navigator.platform"] == "Linux x86_64"
    # Pantalla y ventana reales del display virtual, no un viewport emulado igual a la pantalla.
    assert (seen["screen.width"], seen["screen.height"]) == ("1920", "1080")
    assert seen["screen.colorDepth"] == "24"
