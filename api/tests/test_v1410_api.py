"""v1.4.10 (docs/adr/037): consent.banner_interaction (y lectura de los reportes con user_interaction), frases del linker de
Google (_gl) con el criterio que clasificó el destino, y la cookie que coincide frente a la que un script copió."""

from app.explain import explanations, glossary
from app.report_html import _consent_section
from app.routes.analysis import consent_section, report_validator

STORED = "la cookie «_atrk_siteuid»"


# --- 3. consentimiento ---

def test_old_reports_are_read_with_the_previous_name():
    assert consent_section({"tcf": None, "consent_mode": None, "user_interaction": True}) == \
        {"tcf": None, "consent_mode": None, "banner_interaction": True}
    assert consent_section({"tcf": None, "consent_mode": None, "user_interaction": False})["banner_interaction"] is False


def test_new_name_wins_and_missing_consent_is_false():
    assert consent_section({"tcf": None, "consent_mode": None, "banner_interaction": True})["banner_interaction"] is True
    assert consent_section(None) == {"tcf": None, "consent_mode": None, "banner_interaction": False}


def test_schema_requires_banner_interaction_and_rejects_the_old_name():
    consent = report_validator().schema["properties"]["consent"]
    assert "banner_interaction" in consent["required"] and "user_interaction" not in consent["properties"]
    assert consent["additionalProperties"] is False


def test_html_report_says_consent_notice_for_new_and_old_reports():
    for consent in ({"banner_interaction": True}, {"user_interaction": True}):
        html = _consent_section(consent)
        assert "Interacción con el aviso de consentimiento durante el scan: sí" in html and "con el banner" not in html


# --- 2. cookie: coincide / copió ---

def phrase(data):
    reasons = [{"signal": "persistent_id", "level": "EVIDENCIA", "weight": 20, "data": data}]
    return explanations().request_phrase(reasons=reasons, entity="Appier", domain="appier.net", third_party=True)["text"]


def test_cookie_match_phrase_without_recorded_read():
    text = phrase({"parameter": "siteuid", "stored_in": STORED, "matched_cookie": "_atrk_siteuid"})
    assert text == "Identificador persistente: el valor enviado a Appier coincide con la cookie «_atrk_siteuid»."


def test_cookie_copy_phrase_only_with_the_initiating_script_read():
    text = phrase({"parameter": "siteuid", "stored_in": STORED, "matched_cookie": "_atrk_siteuid",
                   "copied_by_script": "https://cdn.appier.net/tag.js"})
    assert "un script copió el valor de la cookie «_atrk_siteuid» en la URL o el cuerpo de la request a Appier" in text
    storage = phrase({"parameter": "u", "stored_in": "el ítem «uid» de localStorage", "copied_by_script": "https://x/t.js"})
    assert "copió el valor del ítem «uid» de localStorage" in storage


def test_persistent_id_org_finding_phrases():
    base = {"type": "persistent_id_org", "level": "EVIDENCIA", "evidence_refs": [1],
            "details": {"domain": "appier.net", "organization": "Appier", "stored_in": STORED}}
    assert "el valor enviado coincide con la cookie «_atrk_siteuid»" in explanations().finding_phrase(base)["text"]
    copied = {**base, "details": {**base["details"], "copied_by_script": "https://cdn.appier.net/tag.js"}}
    assert "un script copió el valor de la cookie «_atrk_siteuid»" in explanations().finding_phrase(copied)["text"]
    legacy = {**base, "details": {**base["details"], "copied_cookie": "_atrk_siteuid"}}
    assert "copió" not in explanations().finding_phrase(legacy)["text"]


# --- 4. linker de Google (_gl) ---

def linker_finding(kind, status, label, basis_label, organization):
    return {"type": kind, "level": "EVIDENCIA", "evidence_refs": [3],
            "details": {"domain": "reservas.example", "destination_host": "www.reservas.example", "source": "redirect",
                        "status": status, "status_label": label, "organization": organization, "basis_label": basis_label}}


def test_third_party_linker_phrase_names_the_criterion_and_never_claims_recognition():
    result = explanations().finding_phrase(linker_finding("gl_linker", "third_party", "Tercero", "mapa de entidades", "Reservas SpA"))
    assert not result["generic"] and result["step"] == "etiquetado" and result["companies"] == ["Reservas SpA"]
    assert "redirección a www.reservas.example" in result["text"] and "un tercero según mapa de entidades" in result["text"]
    assert "no muestra que el destino reconociera al visitante ni que se completara una atribución" in result["text"]


def test_non_third_party_linker_is_technical_list_only():
    for status, label, criterion, shown in (("same_org", "Misma organización", "alias de organización (org_aliases)", "misma organización"),
                                            ("unknown_org", "Organización no disponible", "dominio registrable", "Organización no disponible"),
                                            ("first_party", "Propio", "dominio registrable", "propio")):
        result = explanations().finding_phrase(linker_finding("gl_linker_info", status, label, criterion, "x"))
        assert result["step"] is None and not result["generic"] and result["companies"] == []
        assert f"destino {shown} según {criterion}, por lo que no suma al índice" in result["text"]


def test_linker_transfer_request_phrase():
    reasons = [{"signal": "linker_transfer", "level": "EVIDENCIA", "weight": 15, "data": {"organization": "Reservas SpA"}}]
    text = explanations().request_phrase(reasons=reasons, entity="Reservas SpA", domain="reservas.example", third_party=True)["text"]
    assert text.startswith("Linker de Google (_gl): la URL de la request llevó el parámetro _gl a Reservas SpA")


def test_glossary_has_google_linker():
    terms = {term["id"]: term for term in glossary().terms}
    assert "no demuestra que el destino lo haya usado para reconocer al visitante" in terms["google_linker"]["definition"]
    assert "google_linker" in glossary().panels["summary"]["terms"]
