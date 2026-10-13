"""Escenarios de consentimiento contra el CMP del fixture (criterio 3 de F7)."""

import pytest

from app.browser.capture import run_scan
from tests.helpers import run_async


@pytest.fixture(scope="module")
def cmp(manifest):
    return manifest["privacy_test"]["cmp"]


@pytest.fixture(scope="module")
def runs(cmp):
    out = {}
    for scenario in ("sin_interaccion", "aceptar", "rechazar"):
        outcome = run_async(run_scan(cmp["page"], scenario=scenario))
        assert outcome.error is None, outcome.error
        out[scenario] = outcome
    return out


def tracker_paths(outcome, cmp, before=None, after=None):
    """Rutas pedidas al tracker del fixture, opcionalmente solo antes o solo después de una frontera."""
    return [
        request["path"] for request in outcome.capture["requests"]
        if request["host"] == cmp["host"] and (before is None or request["seq"] < before) and (after is None or request["seq"] >= after)
    ]


def test_banner_is_recognized_and_photographed(runs, cmp):
    for scenario, outcome in runs.items():
        consent = outcome.result["consent"]
        assert consent["banner_detected"] is True and consent["cmp"] == cmp["cmp"] and consent["tcfapi_present"] is True, scenario
        banners = [a for a in outcome.capture["artifacts"] if a["kind"] == "consent_banner"]
        assert len(banners) == 1 and banners[0]["mime"] == "image/jpeg" and banners[0]["data"][:3] == b"\xff\xd8\xff"
        assert 2000 < len(banners[0]["data"]) < 400_000 and consent["has_banner_image"] is True


def test_each_scenario_reaches_its_state(runs, cmp):
    for scenario, expected in cmp["expected"].items():
        consent = runs[scenario].result["consent"]
        assert consent["status"] == expected["status"], scenario
        assert sorted(tracker_paths(runs[scenario], cmp)) == sorted(expected["paths"]), scenario
        if "verified" in expected:
            assert consent["verified"] is expected["verified"] and consent["state"]["verified_by"] == "tcf"
            assert consent["state"]["banner_closed"] is True and "OptanonConsent" in consent["state"]["cmp_cookies"]
    assert runs["aceptar"].result["consent"]["state"]["tcf"]["purposes_granted"] == 10
    assert runs["rechazar"].result["consent"]["state"]["tcf"]["purposes_granted"] == 0
    assert runs["sin_interaccion"].result["consent"]["clicked"] is None


def test_pre_consent_accept_only_and_ignores_reject(runs, cmp):
    # Antes de cualquier interacción: en los tres escenarios, y sin clic en el primero.
    for scenario in ("aceptar", "rechazar"):
        boundary = runs[scenario].result["consent"]["interaction_seq"]
        assert tracker_paths(runs[scenario], cmp, before=boundary) == [cmp["pre_consent"]], scenario
    assert tracker_paths(runs["sin_interaccion"], cmp) == [cmp["pre_consent"]]
    # Solo tras aceptar.
    accept_after = tracker_paths(runs["aceptar"], cmp, after=runs["aceptar"].result["consent"]["interaction_seq"])
    assert cmp["accept_only"] in accept_after
    assert cmp["accept_only"] not in tracker_paths(runs["rechazar"], cmp) + tracker_paths(runs["sin_interaccion"], cmp)
    # Ignora el rechazo: aparece DESPUÉS de rechazar.
    reject_after = tracker_paths(runs["rechazar"], cmp, after=runs["rechazar"].result["consent"]["interaction_seq"])
    assert reject_after == [cmp["ignores_reject"]]


@pytest.mark.parametrize("scenario", ["sin_interaccion", "aceptar", "rechazar"])
def test_unrecognized_banner_is_not_applicable_and_nothing_is_clicked(cmp, scenario):
    outcome = run_async(run_scan(cmp["unknown_page"], scenario=scenario))
    consent = outcome.result["consent"]
    assert consent["status"] == "no_aplicable" and consent["banner_detected"] is False
    assert consent["clicked"] is None and consent["interaction_seq"] is None
    assert "No se reconoció" in consent["reason"] and "#onetrust-banner-sdk" in consent["evidence"]["selectors_tried"]
    # El banner propio tiene botones "Aceptar" y "Rechazar": pulsar cualquiera dispararía esta request.
    assert cmp["never"] not in tracker_paths(outcome, cmp)
    assert outcome.capture["artifacts"] == []


def test_scan_without_scenario_has_no_consent_section(cmp):
    outcome = run_async(run_scan(cmp["page"]))
    assert "consent" not in outcome.result and "profile" not in outcome.result
