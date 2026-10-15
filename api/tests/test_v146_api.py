"""v1.4.6 (docs/adr/033): frases y grupo de los hallazgos nuevos (identificador hacia una sola organización, propósito de
cookies) y tipo de servicio de UserWay. Sin red ni stack."""

from app.explain import explanations
from app.service_types import service_types

HOSTILE = '<img src=x onerror="window.__XSS=1">'


def finding(kind, level, details, refs=(1, 2)):
    return {"type": kind, "level": level, "claim": "detalle", "evidence_refs": {"requests": list(refs), "calls": []}, "details": details}


def test_identifier_to_one_organization_is_group_1_not_sync():
    explainer = explanations()
    phrase = explainer.finding_phrase(finding("persistent_id_org", "EVIDENCIA", {
        "domain": "userway.org", "organization": "UserWay", "stored_in": "el ítem «uw-uid» de localStorage"}))
    assert phrase["step"] == "etiquetado" and phrase["generic"] is False and phrase["companies"] == ["UserWay"]
    assert phrase["text"].startswith("Identificador persistente enviado a UserWay:")
    # Dueño desconocido: se nombra el dominio, no se inventa una organización.
    unknown = explainer.finding_phrase(finding("persistent_id_org", "EVIDENCIA", {"domain": "x.example", "organization": "no_disponible"}))
    assert unknown["text"].startswith("Identificador persistente enviado a x.example:")
    story = explainer.story([finding("persistent_id_org", "EVIDENCIA", {"domain": "userway.org", "organization": "UserWay"})], {}, {})
    by_id = {step["id"]: step for step in story["steps"]}
    assert by_id["etiquetado"]["count"] == 1 and by_id["identificador"]["count"] == 0
    assert by_id["etiquetado"]["number"] == 1 and by_id["identificador"]["number"] == 5


def test_sync_between_two_organizations_stays_in_group_5():
    story = explanations().story([finding("id_sync", "EVIDENCIA", {"domains": ["a.example", "b.example"], "owners": 2})],
                                 {"a.example": "A", "b.example": "B"}, {})
    assert {step["id"]: step["count"] for step in story["steps"]}["identificador"] == 1


def test_cookie_purpose_is_an_inference_by_name():
    explainer = explanations()
    phrase = explainer.finding_phrase(finding("cookie_purpose", "INFERENCIA", {
        "purpose": "analitica", "label": "analítica", "cookies": 2, "names": ["_ga", "_ga_ABC"]}))
    assert phrase["level"] == "INFERENCIA" and phrase["generic"] is False and phrase["step"] == "etiquetado"
    assert phrase["text"] == ("Propósito de cookies (inferencia por el nombre): 2 cookies tienen nombre de cookie de analítica "
                              "(_ga, _ga_ABC); es compatible con ese uso, pero no lo prueba.")
    assert explainer.hedged(phrase["text"])
    functional = explainer.finding_phrase(finding("cookie_purpose_functional", "INFERENCIA", {
        "purpose": "funcional", "label": "funcional", "cookies": 1, "names": ["PHPSESSID"]}))
    assert functional["step"] is None and functional["generic"] is False
    assert "1 cookie tiene nombre de cookie funcional (PHPSESSID)" in functional["text"] and "no suman al índice" in functional["text"]


def test_cookie_purpose_phrase_tolerates_hostile_or_missing_details():
    explainer = explanations()
    hostile = explainer.finding_phrase(finding("cookie_purpose", "INFERENCIA", {"label": "publicidad", "cookies": 1, "names": [HOSTILE, 3]}))
    # Texto plano: quien lo pinta lo escapa. Solo se aceptan nombres de texto.
    assert HOSTILE[:60] in hostile["text"] and "3" not in hostile["text"].split("(")[1].split(")")[0].split(", ")
    empty = explainer.finding_phrase(finding("cookie_purpose", "INFERENCIA", {}))
    assert empty["generic"] is True and empty["level"] == "INFERENCIA"


def test_userway_service_type():
    assert service_types().of(entity="UserWay", domain="userway.org") == {"type": "accessibility_widget", "label": "widget de accesibilidad"}
    assert service_types().of(entity="no_disponible", domain="userway.org")["type"] == "accessibility_widget"
