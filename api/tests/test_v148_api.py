"""v1.4.8 (docs/adr/035): bandas desde data/scoring.yaml, scans fallidos («Sin medición») y parciales."""

import pathlib

import yaml

from app.bands import BANDS, TRACKER_BANDS
from app.config import get_settings
from app.failures import failure, net_error, partial_navigation


def test_bands_are_read_from_scoring_yaml():
    scoring = yaml.safe_load((pathlib.Path(get_settings().data_dir) / "scoring.yaml").read_text(encoding="utf-8"))
    assert BANDS == tuple(band["name"] for band in scoring["bands"])
    assert "Posible" not in BANDS and BANDS[1] == "Bajo-moderado"
    assert TRACKER_BANDS == BANDS[BANDS.index(scoring["tracker_min_band"]):]


def test_band_filter_rejects_the_old_band_name(client, scan):
    assert client.get(f"/api/scans/{scan}/requests", params={"band": "Posible"}).status_code == 422
    assert client.get(f"/api/scans/{scan}/requests", params={"band": "Bajo-moderado"}).status_code in (200, 409)


def test_failure_keeps_the_real_net_error_and_never_invents_one():
    assert failure("completed", None) is None
    got = failure("failed", {"error_code": "NAVIGATION_FAILED", "message": "Page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://x/"})
    assert got == {"error_code": "NAVIGATION_FAILED", "net_error": "net::ERR_CERT_AUTHORITY_INVALID",
                   "message": "Page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://x/"}
    assert net_error({"error_code": "NAVIGATION_TIMEOUT", "message": "La navegación superó el tiempo límite.", "net_error": None}) is None
    assert failure("failed", None)["error_code"] == "no_disponible"


def test_partial_navigation_is_validated():
    assert partial_navigation({"partial": {"requests": 5, "responses": True, "message": "x"}})["responses"] is None
    assert partial_navigation({}) is None and partial_navigation(None) is None
