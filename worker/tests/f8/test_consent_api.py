"""Consentimiento sin banner (F8): TCF por API y Google Consent Mode, contra el fixture /f8/."""

import json

import pytest

from app.analyzer import consent_mode
from app.analyzer.engine import analyze, prepare_capture
from app.browser.capture import run_scan
from tests.helpers import run_async

# (gdpr, gcs): cubre los dos casos TCF y los cuatro estados de gcs del manifest.
COMBINATIONS = [("0", "G111"), ("1", "G100"), ("0", "G110"), ("1", "G101")]


@pytest.fixture(scope="module")
def f8(manifest):
    return manifest["f8"]


@pytest.fixture(scope="module")
def scans(f8, analyzer_resources):
    lists, config = analyzer_resources
    out = {}
    for gdpr, gcs in COMBINATIONS:
        url = f"{f8['page']}?gdpr={gdpr}&gcs={gcs}"
        outcome = run_async(run_scan(url))
        assert outcome.error is None, outcome.error
        prepared = prepare_capture(outcome.capture, start_url=url, page_url=outcome.result["final_url"], result=outcome.result)
        out[(gdpr, gcs)] = (outcome, analyze(prepared, lists, config))
    return out


def findings(analysis, kind):
    return [finding for finding in analysis["findings"] if finding["type"] == kind]


# --- Criterio 1: TCF ---


def test_tcf_state_is_read_from_the_api_without_any_banner(scans, f8):
    for case in f8["tcf"]["cases"]:
        gdpr = case["query"][-1]
        outcome, analysis = next(value for key, value in scans.items() if key[0] == gdpr)
        assert outcome.result.get("consent") is None, "el fixture no tiene banner ni escenario de consentimiento"
        tcf = analysis["site"]["summary"]["consent"]["tcf"]
        assert tcf["present"] is True and tcf["gdpr_applies"] is case["gdpr_applies"]
        assert tcf["cmp_id"] == f8["tcf"]["cmp_id"] and tcf["cmp_name"] == f8["tcf"]["cmp_name"] and tcf["cmp_version"] == f8["tcf"]["cmp_version"]
        assert tcf["cmp_status"] == "loaded" and tcf["display_status"] == case["display_status"]
        assert tcf["has_tc_string"] is case["has_tc_string"]
        assert analysis["site"]["summary"]["consent"]["banner_interaction"] is False


def test_tcf_finding_is_evidence_with_references_and_no_legal_judgment(scans, f8):
    for (gdpr, _), (outcome, analysis) in scans.items():
        (finding,) = findings(analysis, "tcf_state")
        assert finding["level"] == "EVIDENCIA" and finding["evidence_refs"], finding
        assert f8["tcf"]["cmp_name"] in finding["claim"] and f"cmpId {f8['tcf']['cmp_id']}" in finding["claim"]
        assert f"gdprApplies={'true' if gdpr == '1' else 'false'}" in finding["claim"]
        lowered = finding["claim"].lower()
        for word in ("ilegal", "incumple", "infracción", "infringe", "viola", "rgpd", "gdpr exige", "cumplimiento"):
            assert word not in lowered, word


def test_the_consent_string_itself_is_never_stored(scans):
    for outcome, analysis in scans.values():
        stored = json.dumps(outcome.result) + json.dumps(analysis["site"]["summary"]) + json.dumps(analysis["findings"])
        assert "CPfixture" not in stored
        assert "tcString" not in stored and '"tc_string"' not in stored
        if outcome.result["tcf"]["tc_data"]["has_tc_string"]:
            assert outcome.result["tcf"]["tc_data"]["tc_string_length"] > 0


def test_page_without_tcf_is_reported_as_absent_not_as_unknown(outcome, manifest, analyzer_resources):
    """La página principal del fixture no define __tcfapi."""
    assert outcome.result["tcf"] == {"present": False}
    lists, config = analyzer_resources
    prepared = prepare_capture(outcome.capture, start_url=manifest["page"], page_url=outcome.result["final_url"], result=outcome.result)
    analysis = analyze(prepared, lists, config)
    assert analysis["site"]["summary"]["consent"]["tcf"] == {"present": False}
    assert findings(analysis, "tcf_state") == []


# --- Criterio 2: Consent Mode ---


@pytest.mark.parametrize(
    "value, expected",
    [
        ("G111", {"raw": "G111", "ad_storage": "granted", "analytics_storage": "granted"}),
        ("G100", {"raw": "G100", "ad_storage": "denied", "analytics_storage": "denied"}),
        ("G110", {"raw": "G110", "ad_storage": "granted", "analytics_storage": "denied"}),
        ("G101", {"raw": "G101", "ad_storage": "denied", "analytics_storage": "granted"}),
        ("G1--", {"raw": "G1--", "ad_storage": "no_definido", "analytics_storage": "no_definido"}),
        ("G1-1", {"raw": "G1-1", "ad_storage": "no_definido", "analytics_storage": "granted"}),
        ("G10-", {"raw": "G10-", "ad_storage": "denied", "analytics_storage": "no_definido"}),
        # Fuera de formato: no se interpreta.
        ("G211", None), ("G11", None), ("G1111", None), ("g111", None), ("G12x", None), ("", None), (None, None), (111, None), ("G1 1", None),
    ],
)
def test_gcs_table(value, expected):
    assert consent_mode.decode_gcs(value) == expected


@pytest.mark.parametrize(
    "value, ad, analytics",
    [("13t3t3t3t5", "granted", "granted"), ("13p3p3p3p5", "denied", "denied"), ("13t3p3t3t5", "granted", "denied"),
     ("13r3q3r3r5", "granted", "denied"), ("13l3l3l3l5", "no_definido", "no_definido")],
)
def test_gcd_is_decoded_but_marked_unofficial(value, ad, analytics):
    decoded = consent_mode.decode_gcd(value)
    assert decoded["official"] is False and decoded["ad_storage"] == ad and decoded["analytics_storage"] == analytics


@pytest.mark.parametrize("value", ["", "13t3t", "x3t3t3t3t5", "13z3z3z3z5", None, 5, "1" * 50])
def test_gcd_unknown_formats_are_not_interpreted(value):
    assert consent_mode.decode_gcd(value) is None


def test_gcs_prevails_over_gcd():
    entry = {"gcs": consent_mode.decode_gcs("G100"), "gcd": consent_mode.decode_gcd("13t3t3t3t5")}
    assert consent_mode.state_of(entry, "ad_storage") == "denied"
    assert consent_mode.state_of({"gcs": None, "gcd": consent_mode.decode_gcd("13t3t3t3t5")}, "ad_storage") == "granted"


def test_consent_mode_of_each_fixture_case(scans, f8):
    for case in f8["consent_mode"]["cases"]:
        outcome, analysis = next(value for key, value in scans.items() if key[1] == case["gcs"])
        sent = [request for request in outcome.capture["requests"] if request["host"] == f8["consent_mode"]["host"] and "gcs=" in request["url"]]
        assert len(sent) == 2, "el fixture envía una request de analítica y otra de publicidad"
        mode = analysis["site"]["summary"]["consent"]["consent_mode"]
        assert mode["requests"] == 2 and mode["states"] == {case["gcs"]: 2} and mode["sources"] == {"gcs": 2, "gcd_only": 0}
        assert mode["by_signal"] == {"ad_storage": {case["ad_storage"]: 2}, "analytics_storage": {case["analytics_storage"]: 2}}
        (state,) = findings(analysis, "consent_mode_state")
        assert state["level"] == "EVIDENCIA" and sorted(state["evidence_refs"]) == sorted(request["seq"] for request in sent)
        assert f"gcs={case['gcs']}" in state["claim"] and f"ad_storage={case['ad_storage']}" in state["claim"]
        granted = findings(analysis, "consent_mode_granted_without_interaction")
        assert sorted(finding["details"]["signal"] for finding in granted) == sorted(case["granted_without_interaction"])
        assert all(finding["level"] == "EVIDENCIA" and finding["evidence_refs"] and "sin interacción del usuario" in finding["claim"] for finding in granted)


def test_consent_mode_is_only_read_from_google_domains(analysis):
    """La página principal no habla con el "Google" del fixture usando gcs: no hay nada que informar."""
    assert analysis["site"]["summary"]["consent"]["consent_mode"] is None
    assert findings(analysis, "consent_mode_state") == []
