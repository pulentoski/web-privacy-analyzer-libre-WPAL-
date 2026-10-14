"""v1.4.2: registro de interacción con el navegador real — la instrumentación registra quién escucha, el fixture
envía coordenadas y desplazamiento, y en una captura interactiva los envíos se correlacionan con la interacción."""

import asyncio
import time
import uuid

import pytest

from app.analyzer.engine import analyze, prepare_capture
from app.browser.capture import run_scan
from app.interactive import InteractiveSession
from tests.helpers import SITE, run_async

PAGE = SITE + "/interact/"
LISTENER = "http://tracker-a.fixtures.test/static/interact/interact.js"
QR = SITE + "/static/interact/qrcode.min.js"


@pytest.fixture(scope="module")
def session_analysis(analyzer_resources):
    async def scenario():
        interactions = []
        session = InteractiveSession(PAGE, proxy_user=f"scan-{uuid.uuid4()}", password="abc12345")
        try:
            assert await session.open() is None
            page = session.context.pages[0]
            await page.wait_for_load_state("load")
            await asyncio.sleep(2.5)  # separa la carga de la página de la primera interacción
            for _ in range(3):
                interactions.append({"ts": time.time(), "kind": "click"})
                await page.click("#buy")
                await asyncio.sleep(2.6)
            interactions.append({"ts": time.time(), "kind": "scroll"})
            await page.mouse.wheel(0, 600)
            await asyncio.sleep(2.6)
            # El clic en el campo también es interacción: dispara su envío y un desplazamiento (foco). Sin registrarlo,
            # esos envíos caían justo antes de la marca de la tecla y contaban como «ritmo normal» (carrera, v1.4.5).
            interactions.append({"ts": time.time(), "kind": "click"})
            await page.click("#note")
            await asyncio.sleep(0.3)
            interactions.append({"ts": time.time(), "kind": "key"})
            await page.keyboard.type("hola", delay=20)
            await asyncio.sleep(2.6)
            outcome = await session.collect("user_stop")
        finally:
            await session.destroy()
        outcome.result["interactive"]["interactions"] = interactions
        return outcome

    outcome = run_async(scenario())
    lists, config = analyzer_resources
    prepared = prepare_capture(outcome.capture, start_url=PAGE, page_url=outcome.result["final_url"], result=outcome.result)
    prepared["source"] = "interactive"
    return outcome, analyze(prepared, lists, config)


def fp_findings(analysis, heuristic):
    return [f for f in analysis["fingerprinting"]["findings"] if f["heuristic"] == heuristic]


def test_instrumentation_records_which_scripts_listen_to_interaction(session_analysis):
    outcome, analysis = session_analysis
    apis = {(call["api"], call["script_url"]) for call in outcome.capture["fingerprinting"]["calls"]}
    for event in ("click", "scroll", "mousemove", "keydown", "visibilitychange"):
        assert (f"events.{event}", LISTENER) in apis, event
    [listener] = [f for f in fp_findings(analysis, "interaction_listener") if f["script_url"] == LISTENER]
    assert listener["level"] == "EVIDENCIA" and listener["details"]["events"] == ["click", "mousemove", "scroll", "keydown", "visibilitychange"]
    assert listener["call_refs"] and "el propósito" in listener["claim"]
    # Lo que se guarda es el tipo de evento y el script: ningún detalle del evento.
    assert all(call["details"] == {} for call in outcome.capture["fingerprinting"]["calls"] if call["api"].startswith("events."))


def test_interaction_data_in_payloads_is_found_by_parameter_name(session_analysis):
    _, analysis = session_analysis
    payloads = {f["details"]["category"]: f for f in analysis["findings"] if f["type"] == "interaction_payload" and f["details"]["domain"] == "tracker-a.fixtures.test"}
    assert {"coordinates", "element", "dwell", "scroll", "event"} <= set(payloads)
    assert payloads["coordinates"]["details"]["parameters"] == ["clientx", "clienty"] and payloads["coordinates"]["level"] == "INFERENCIA"
    assert payloads["scroll"]["details"]["parameters"] == ["percent_scrolled"] and len(payloads["coordinates"]["evidence_refs"]) == 4  # tres clics en el botón y uno en el campo de texto


def test_sends_after_each_interaction_are_evidence_and_what_was_typed_is_not_kept(session_analysis):
    outcome, analysis = session_analysis
    sent = [f for f in analysis["findings"] if f["type"] == "interaction_sent"]
    assert len(sent) == 1 and sent[0]["level"] == "EVIDENCIA", str(analysis["site"]["summary"]["interaction"]["organizations"])
    details = sent[0]["details"]
    assert details["domain"] == "tracker-a.fixtures.test" and details["interactions"] == 6 and details["requests"] >= 6 and details["kinds"].keys() == {"click", "scroll", "key"}
    interaction = analysis["site"]["summary"]["interaction"]
    assert interaction["interactions"] == {"click": 4, "scroll": 1, "key": 1} and len(interaction["timeline"]) == 6
    assert all(entry["sends"] and not entry["navigation"] for entry in interaction["timeline"])
    # «hola» se tecleó en un campo: ni la captura de interacción ni el análisis lo contienen.
    assert "hola" not in str(interaction) and "hola" not in str(outcome.result["interactive"]["interactions"])


def test_known_library_canvas_and_inline_script_in_a_real_page(session_analysis):
    _, analysis = session_analysis
    assert [f["script_url"] for f in fp_findings(analysis, "canvas_read_benign")] == [QR]
    assert fp_findings(analysis, "canvas_fingerprinting") == []
    scripts = {script["script_url"]: script for script in analysis["fingerprinting"]["scripts"]}
    # El script inline de la página queda atribuido a su documento (su URL); las escuchas no cuentan como lecturas.
    assert {"navigator.userAgent", "screen.width"} <= {api["api"] for api in scripts[PAGE]["apis"]}
    assert LISTENER not in scripts and all(not api["api"].startswith("events.") for script in scripts.values() for api in script["apis"])


def test_a_normal_scan_records_listeners_but_has_no_user_interaction(analyzer_resources):
    outcome = run_async(run_scan(PAGE))
    lists, config = analyzer_resources
    analysis = analyze(prepare_capture(outcome.capture, start_url=PAGE, page_url=outcome.result["final_url"], result=outcome.result), lists, config)
    assert [f["script_url"] for f in fp_findings(analysis, "interaction_listener") if f["script_url"] == LISTENER] == [LISTENER]
    interaction = analysis["site"]["summary"]["interaction"]
    assert interaction["available"] is False and interaction["listener_scripts"] >= 1
    assert [f for f in analysis["findings"] if f["type"] == "interaction_sent"] == []
