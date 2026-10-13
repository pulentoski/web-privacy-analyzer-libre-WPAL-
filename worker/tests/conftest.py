"""Fixtures compartidas: scans del sitio de fixtures con Chromium y el proxy reales.

Requieren el stack de test: ALLOW_FIXTURES=1 en .env y
`docker compose --profile test up -d --build` (ver README).
"""

import urllib.error

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import analyze, prepare_capture
from app.analyzer.lists import FilterLists
from app.browser.capture import run_scan
from app.config import settings
from tests.helpers import fixtures_call, run_async


@pytest.fixture(scope="session")
def fixtures_site():
    assert settings.allow_fixtures, "Estos tests requieren ALLOW_FIXTURES=1 en .env (ver README, 'Tests de captura')"
    try:
        fixtures_call("/__health")
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            "El sitio de fixtures no responde a través del proxy. Levantar con "
            f"`docker compose --profile test up -d --build` y ALLOW_FIXTURES=1 ({exc})"
        ) from exc
    return fixtures_call("/manifest.json")


@pytest.fixture(scope="session")
def manifest(fixtures_site):
    return fixtures_site


@pytest.fixture(scope="session")
def page_scan(manifest):
    """Un scan de la página de prueba + lo que el servidor dice haber recibido."""
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(manifest["page"]))
    received = fixtures_call("/__received")["requests"]
    return outcome, received


@pytest.fixture(scope="session")
def outcome(page_scan):
    return page_scan[0]


@pytest.fixture(scope="session")
def capture(page_scan):
    return page_scan[0].capture


@pytest.fixture(scope="session")
def received(page_scan):
    return page_scan[1]


@pytest.fixture(scope="session")
def flood_scan(manifest, page_scan):
    # Depende de page_scan solo para no pisar su /__received.
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(manifest["flood"]["page"]))
    received = fixtures_call("/__received")["requests"]
    return outcome, received


# --- Analizador (F3) ---


@pytest.fixture(scope="session")
def analyzer_resources():
    """Listas y pesos reales de data/. Los motores adblock se usan solo desde este hilo."""
    return FilterLists(settings.data_dir, allow_fixtures=settings.allow_fixtures), load_config(settings.data_dir, allow_fixtures=settings.allow_fixtures)


@pytest.fixture(scope="session")
def analysis(outcome, capture, manifest, analyzer_resources):
    lists, config = analyzer_resources
    prepared = prepare_capture(capture, start_url=manifest["page"], page_url=outcome.result["final_url"])
    return analyze(prepared, lists, config)


@pytest.fixture(scope="session")
def flood_analysis(flood_scan, manifest, analyzer_resources):
    lists, config = analyzer_resources
    outcome, _ = flood_scan
    prepared = prepare_capture(outcome.capture, start_url=manifest["flood"]["page"], page_url=outcome.result["final_url"])
    return analyze(prepared, lists, config)


# --- Fingerprinting (F4) ---


@pytest.fixture(scope="session")
def fp_scan(manifest, page_scan):
    """Scan de la página de fingerprinting + lo que reportó su script hostil."""
    fixtures_call("/__reset", "POST")
    outcome = run_async(run_scan(manifest["fingerprinting"]["page"]))
    abuse = fixtures_call("/__abuse")["reports"]
    return outcome, abuse


@pytest.fixture(scope="session")
def fp_capture(fp_scan):
    return fp_scan[0].capture


@pytest.fixture(scope="session")
def fp_analysis(fp_scan, manifest, analyzer_resources):
    lists, config = analyzer_resources
    outcome, _ = fp_scan
    prepared = prepare_capture(
        outcome.capture, start_url=manifest["fingerprinting"]["page"], page_url=outcome.result["final_url"]
    )
    return analyze(prepared, lists, config)
