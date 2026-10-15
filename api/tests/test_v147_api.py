"""v1.4.7 (docs/adr/034): las fugas hacia un CDN público nombran al CDN, no a la librería; frases de las cookies
clasificadas por la organización que las creó. Sin red ni stack."""

from app.explain import explanations

LIBRARY = "librería bootstrap-icons en CDN público (cdnjs)"
CDN = "CDN público cdnjs (Cloudflare)"


def finding(kind, level, details):
    return {"type": kind, "level": level, "claim": "detalle", "evidence_refs": {"requests": [1], "calls": []}, "details": details}


def test_referer_leak_names_the_cdn_even_if_the_map_has_a_library():
    # El mapa dominio → entidad de la api toma la de alguna request: puede ser la etiqueta de una librería.
    phrase = explanations().finding_phrase(finding("referer_leak", "EVIDENCIA", {"domain": "cloudflare.com", "recipient": CDN}),
                                           {"cloudflare.com": LIBRARY})
    assert phrase["text"] == f"Fuga por Referer: la cabecera Referer transmitió a {CDN} la URL completa de la página."
    assert phrase["companies"] == [CDN] and LIBRARY not in phrase["text"]
    url = explanations().finding_phrase(finding("url_leak", "EVIDENCIA", {"domain": "jsdelivr.net", "parameter": "page",
                                                                          "recipient": "CDN público jsDelivr (Prospect One)"}))
    assert "a CDN público jsDelivr (Prospect One) en el parámetro «page»" in url["text"]


def test_analyses_without_recipient_keep_the_previous_phrase():
    phrase = explanations().finding_phrase(finding("referer_leak", "EVIDENCIA", {"domain": "google.com"}), {"google.com": "Google"})
    assert phrase["text"] == "Fuga por Referer: la cabecera Referer transmitió a Google la URL completa de la página."


def test_request_phrase_names_the_cdn():
    reasons = [{"signal": "third_party", "level": "EVIDENCIA", "evidence_ref": 1},
               {"signal": "referer_full_url", "level": "EVIDENCIA", "evidence_ref": 1, "data": {"recipient": CDN}}]
    phrase = explanations().request_phrase(reasons=reasons, entity=LIBRARY, domain="cloudflare.com", third_party=True, party="third_party")
    assert phrase["signal"] == "referer_full_url" and CDN in phrase["text"] and LIBRARY not in phrase["text"]


def test_cookie_purpose_by_organization_phrase():
    explainer = explanations()
    phrase = explainer.finding_phrase(finding("cookie_purpose", "INFERENCIA", {
        "purpose": "publicidad", "label": "publicidad", "basis": "organizacion", "cookies": 2, "names": ["uid", "uuid2"],
        "organizations": ["Criteo"]}))
    assert phrase["generic"] is False and phrase["step"] == "etiquetado" and explainer.hedged(phrase["text"])
    assert phrase["text"] == ("Propósito de cookies (inferencia por la organización): 2 cookies tienen origen en una organización de "
                              "publicidad (uid, uuid2); es compatible con ese uso, pero no lo prueba.")
    functional = explainer.finding_phrase(finding("cookie_purpose_functional", "INFERENCIA", {
        "purpose": "funcional", "label": "funcional", "basis": "organizacion", "cookies": 1, "names": ["__cfruid"]}))
    assert functional["text"].startswith("Cookies funcionales (inferencia por la organización): 1 cookie tiene origen en una organización "
                                         "de CDN, antibot o seguridad (__cfruid)")
