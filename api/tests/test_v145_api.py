"""v1.4.5 (docs/adr/032): servicios de terceros sin señales de rastreo en el reporte, frases de los hallazgos nuevos,
catálogo de tipos de servicio y nota del recuadro que no cargó. Sin red ni stack."""

import pytest

from app.explain import explanations
from app.report_html import _error_frames_note, _third_party_services_section, executive_summary, third_party_services
from app.service_types import service_types

HOSTILE = '<img src=x onerror="window.__XSS=1">'


def report(services=None, **summary):
    if services is not None:
        summary["third_party_services"] = services
    return {"scan": {"source": "scan"}, "capture": {"total_requests": 12, "third_party": 9},
            "site": {"summary": summary, "exposure_score": 3, "band": "Bajo"}, "trackers": [], "findings": []}


def services(items, **extra):
    return {"level": "EVIDENCIA", "service_level": "INFERENCIA", "organizations": len({item["organization"] for item in items}),
            "requests": sum(item["requests"] for item in items), "items": items, "truncated": False, **extra}


def item(organization, service_type, label, hosts, requests, **extra):
    return {"organization": organization, "service_type": service_type, "service_label": label, "domains": hosts, "hosts": hosts,
            "requests": requests, "evidence_refs": [1, 2][:requests], "in_trackers": False, **extra}


LASERENA = [
    item("Google", "antifraud", "antifraude publicitario/antibot (verifica que el tráfico no sea automatizado)", ["www.google.com"], 4),
    item("OpenStreetMap Foundation", "maps", "mapas (mapas interactivos, teselas y geocodificación)", ["a.tile.openstreetmap.org"], 2),
    item("no_disponible", None, None, ["apis.munilaserena.cl"], 3),
]


# --- 1. sección del reporte ---


def test_report_lists_third_party_services_even_without_trackers():
    html = _third_party_services_section(report(services(LASERENA)))
    assert "<h3>Servicios de terceros sin señales de rastreo</h3>" in html
    assert "lvl-EVIDENCIA" in html and "(Inferencia)" in html
    for expected in ("Google", "OpenStreetMap Foundation", "mapas (mapas interactivos", "a.tile.openstreetmap.org", "request: #1, #2"):
        assert expected in html, expected
    # Dueño y giro desconocidos se dicen, no se inventan.
    assert "<td>no disponible</td>" in html and "tipo no identificado" in html and "no_disponible" not in html
    assert "reciben" not in html or "IP" in html


def test_report_says_so_when_there_are_none_and_stays_silent_for_older_analyses():
    assert "no hubo requests a terceros sin señales de rastreo" in _third_party_services_section(report(services([])))
    assert _third_party_services_section(report()) == "" and third_party_services(report()) is None
    assert _third_party_services_section(report({"items": "x"})) == ""


def test_report_section_escapes_everything_that_comes_from_the_capture():
    hostile = [item(HOSTILE, "maps", HOSTILE, [HOSTILE], 1, in_trackers=True)]
    html = _third_party_services_section(report(services(hostile)))
    assert "<img" not in html and "&lt;img src=x" in html and "(también en rastreadores)" in html


def test_executive_summary_mentions_the_services_and_what_they_receive():
    found = " ".join(executive_summary(report(services(LASERENA)))["found"])
    assert "No se observaron requests con señales suficientes de seguimiento" in found
    assert "Servicios de terceros sin señales de rastreo: 9 requests se dirigieron a 3 organizaciones" in found
    assert "(antifraude publicitario/antibot, mapas)" in found and "reciben la dirección IP y el navegador" in found
    assert "Servicios de terceros" not in " ".join(executive_summary(report(services([])))["found"])
    assert "Servicios de terceros" not in " ".join(executive_summary(report())["found"])


# --- 4. catálogo de tipos de servicio (misma fuente que el worker) ---


@pytest.mark.parametrize("entity, domain, url, expected", [
    ("Google", "maps.googleapis.com", "https://maps.googleapis.com/maps/api/js?key=x", "maps"),
    ("Google", "gstatic.com", "https://maps.gstatic.com/mapfiles/a.png", "maps"),
    ("Google", "fonts.googleapis.com", "https://fonts.googleapis.com/css?family=Roboto", "fonts"),
    ("Google", "ajax.googleapis.com", "https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js", "library_cdn"),
    ("Google", "gstatic.com", "https://www.gstatic.com/recaptcha/releases/x/recaptcha__es.js", "antifraud"),
    ("no_disponible", "weshareapp.io", "https://platform.weshareapp.io/widget.js", "share_widget"),
    ("no_disponible", "e-mailit.com", "https://www.e-mailit.com/widget/button.js", "share_widget"),
    ("OpenWeather", "openweathermap.org", "https://api.openweathermap.org/data/2.5/weather", "weather"),
    ("Prospect One", "jsdelivr.net", "https://cdn.jsdelivr.net/npm/x/x.js", "library_cdn"),
])
def test_service_catalog_of_v145(entity, domain, url, expected):
    assert service_types().of(entity=entity, domain=domain, urls=[url])["type"] == expected


def test_a_mixed_group_does_not_take_the_type_of_a_minority_url():
    urls = ["https://www.google-analytics.com/g/collect?tid=G-1", "https://www.googletagmanager.com/gtag/js?id=G-1",
            "https://maps.googleapis.com/maps/api/js/gen_204?x=1"]
    assert service_types().of(entity="Google", domain="doubleclick.net", urls=urls)["type"] == "advertising"
    assert service_types().of(entity="Google", domain="maps.googleapis.com", urls=urls[2:])["type"] == "maps"


# --- 6. recuadro que no cargó ---


def test_error_frame_note_only_when_observed():
    note = _error_frames_note(report(error_frames={"observed": True, "ignored_calls": 3}))
    assert "Un recuadro (iframe) de la página no cargó" in note and "chrome-error" not in note
    assert _error_frames_note(report(error_frames={"observed": False})) == "" and _error_frames_note(report()) == ""


# --- 7. frases de los hallazgos nuevos ---


def finding(kind, details, refs=(1, 2)):
    return {"type": kind, "level": "EVIDENCIA", "claim": "detalle", "evidence_refs": list(refs), "details": details}


def test_several_accounts_phrase():
    phrase = explanations().finding_phrase(finding("analytics_accounts", {
        "vendor": "Google Analytics", "accounts": ["G-AAAA1111", "G-BBBB2222", "UA-1234567-1"], "count": 3}))
    assert phrase["level"] == "EVIDENCIA" and phrase["generic"] is False and phrase["step"] is None
    assert phrase["text"] == ("Varias cuentas de analítica: los datos de la visita se enviaron a 3 cuentas de Google Analytics "
                              "(G-AAAA1111, G-BBBB2222, UA-1234567-1).")
    assert phrase["companies"] == ["Google Analytics"]


def test_discontinued_tag_phrase_is_informative():
    phrase = explanations().finding_phrase(finding("discontinued_tag", {
        "vendor": "Google Analytics", "service": "Universal Analytics", "accounts": ["UA-1234567-1"], "count": 1, "informative": True}))
    assert phrase["generic"] is False and phrase["step"] is None
    assert phrase["text"] == ("Etiqueta de un servicio descontinuado: el sitio aún carga 1 etiqueta de Universal Analytics "
                              "(UA-1234567-1). Nota informativa: ese servicio ya no procesa datos.")


def test_phrases_tolerate_hostile_or_missing_details():
    explainer = explanations()
    hostile = explainer.finding_phrase(finding("analytics_accounts", {"vendor": HOSTILE, "accounts": [HOSTILE, 7, None], "count": 2}))
    # La frase es texto plano: quien la pinta la escapa (React y report_html.e). Solo se aceptan IDs de texto.
    assert hostile["text"].endswith(f"2 cuentas de {HOSTILE} ({HOSTILE}).")
    empty = explainer.finding_phrase(finding("discontinued_tag", {}))
    assert empty["level"] == "EVIDENCIA" and isinstance(empty["text"], str) and empty["text"]
