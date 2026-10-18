"""v1.4.9 (docs/adr/036): bandas por /api/bands, puntaje por nivel, conteo de la lista en el detalle de una request,
Client Hints en el reporte (la solicitud nunca como recepción) y el límite de WebRTC."""

from app.bands import BANDS
from app.explain import explanations, glossary
from app.report_html import client_hints_sentences, score_levels_text
from app.routes.analysis import LIMITATIONS, WEBRTC_LIMITATION, limitations_for
from app.measurement import coverage_limitations
from app.routes.scans import score_by_level


def test_bands_endpoint_serves_scoring_yaml(client):
    data = client.get("/api/bands").json()
    assert [band["name"] for band in data["bands"]] == list(BANDS)
    assert data["bands"][1] == {"name": "Bajo-moderado", "max": 40} and data["tracker_min_band"] == "Moderado"


def test_score_by_level_sums_weights_and_flags_clamping():
    reasons = [{"weight": 40, "level": "EVIDENCIA"}, {"weight": 5, "level": "EVIDENCIA"}, {"weight": 15, "level": "INFERENCIA"},
               {"weight": -10, "level": "EVIDENCIA"}]
    assert score_by_level(reasons) == {"EVIDENCIA": 35, "INFERENCIA": 15, "POSIBLE": 0, "clamped": False}
    assert score_by_level([{"weight": 90, "level": "EVIDENCIA"}, {"weight": 30, "level": "INFERENCIA"}])["clamped"] is True
    assert score_by_level(None) is None


def test_list_match_count_in_request_detail_includes_this_request():
    finding = {"type": "list_match", "level": "EVIDENCIA", "details": {"list": "easyprivacy", "domain": "appier.net"},
               "evidence_refs": [1, 2, 3, 4, 5, 6, 7]}
    text = explanations().finding_phrase(finding, {"appier.net": "Appier"}, in_request=True)["text"]
    assert "(7 en esta visita, incluida esta)" in text
    assert "(7 requests en esta visita)" in explanations().finding_phrase(finding, {"appier.net": "Appier"})["text"]


def test_copied_cookie_of_an_analysis_1_16_is_only_a_match():
    # v1.4.10: el `copied_cookie` de los análisis 1.16.0 no registraba la lectura del script: se dice que el valor coincide.
    reasons = [{"signal": "persistent_id", "level": "EVIDENCIA", "weight": 20,
                "data": {"parameter": "siteuid", "stored_in": "la cookie «_atrk_siteuid»", "copied_cookie": "_atrk_siteuid"}}]
    text = explanations().request_phrase(reasons=reasons, entity="Appier", domain="appier.net", third_party=True)["text"]
    assert text == "Identificador persistente: el valor enviado a Appier coincide con la cookie «_atrk_siteuid»."


def test_client_hints_request_is_never_presented_as_reception():
    request_reason = [{"signal": "client_hints_request", "level": "EVIDENCIA", "weight": 3, "data": {"hints": ["Sec-CH-UA-Model"]}}]
    text = explanations().request_phrase(reasons=request_reason, entity="Appier", domain="appier.net", third_party=True)["text"]
    assert "no demuestra que los haya recibido" in text
    finding = {"type": "client_hints_requested", "level": "EVIDENCIA", "evidence_refs": [1],
               "details": {"organization": "Appier", "hints": ["Sec-CH-UA-Model"], "hosts": ["anylist.c.appier.net"]}}
    assert "no demuestra que los haya recibido" in explanations().finding_phrase(finding)["text"]
    five = {**finding, "details": {**finding["details"], "hints": ["Sec-CH-UA-Full-Version-List", "Sec-CH-UA-Model", "Sec-CH-UA-Arch",
                                                                   "Sec-CH-UA-Bitness", "Sec-CH-UA-Platform-Version"]}}
    assert "Sec-CH-UA-Platform-Version. El servidor" in explanations().finding_phrase(five)["text"]  # la lista no se corta
    summary = {"request_text": "El servidor pidió datos del navegador potencialmente útiles para identificarlo; esta solicitud no demuestra que los haya recibido.",
               "requests": [{"organization": "Appier", "hints": ["Sec-CH-UA-Model"], "sent": "no_observado", "sent_hints": []}],
               "sends": [], "delegation": {"label": "No determinado", "evidence": ["x"], "note": "Sin delegación detectada no prueba que el envío sea imposible."},
               "notes": ["condicionado por la configuración del navegador de captura"]}
    lines = client_hints_sentences(summary)
    assert "no demuestra que los haya recibido" in lines[0]
    assert not any("Envío" in line for line in lines)  # sin cabecera observada no hay frase de envío
    assert any(line.startswith("Delegación de Client Hints por el sitio: No determinado") for line in lines)


def test_score_levels_text():
    assert score_levels_text({"EVIDENCIA": 61.4, "INFERENCIA": 8.6}) == "Evidencia 61.4 + Inferencia 8.6"


def test_webrtc_limitation_only_when_the_page_created_connections():
    # v1.5.0: después de los fijos van los de la cobertura por contexto (data/coverage.yaml).
    fixed = LIMITATIONS + coverage_limitations()
    assert limitations_for({"findings": [{"heuristic": "webrtc_connection"}]}) == fixed + [WEBRTC_LIMITATION]
    assert limitations_for({"findings": [{"heuristic": "canvas_fingerprinting"}]}) == fixed
    assert limitations_for(None) == fixed
    assert "no tiene salida UDP" in WEBRTC_LIMITATION and "Un visitante real podría exponerlos" in WEBRTC_LIMITATION


def test_glossary_has_client_hints_and_redirect_chain():
    terms = {term["id"]: term for term in glossary().as_dict()["terms"]}
    for term_id in ("client_hints", "accept_ch", "delegacion_client_hints", "cadena_redireccion"):
        assert len(terms[term_id]["definition"]) > 60
    assert "no demuestra" in terms["accept_ch"]["definition"]
