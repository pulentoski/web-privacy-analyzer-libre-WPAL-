"""Fixtures compartidas: scans del sitio de fixtures con Chromium y el proxy reales.

Requieren el stack de test: ALLOW_FIXTURES=1 en .env y
`docker compose --profile test up -d --build` (ver README).
"""

import os
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


# --- Selección de la suite unitaria para CI (WPA_UNIT_ONLY=1) ---
#
# El CI (.github/workflows/tests.yml) ejecuta solo las pruebas que NO necesitan el stack de test
# (Chromium, el proxy y el sitio de fixtures) ni los datos de terceros de ./data (listas de filtros,
# mapa de entidades, lista de CMP de IAB), que no se versionan. Con WPA_UNIT_ONLY=1 se deseleccionan:
#   - las que usan alguna fixture que exige ese stack o esos datos (lista de abajo), y
#   - las marcadas @pytest.mark.needs_stack (integración sin fixture propia, p. ej. las de listas).
# Sin la variable (uso normal dentro del stack) NO cambia nada: se ejecutan todas, como siempre.
_STACK_FIXTURES = frozenset({
    "fixtures_site", "manifest", "page_scan", "outcome", "capture", "received",
    "flood_scan", "flood_analysis", "analyzer_resources", "analysis",
    "fp_scan", "fp_capture", "fp_analysis", "login_capture",
    "canary", "playwright_instance", "browser", "direct_browser", "page", "direct_page",
})


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_stack: requiere el stack de test o los datos de ./data; se omite en CI (WPA_UNIT_ONLY=1).",
    )


def pytest_collection_modifyitems(config, items):
    if os.environ.get("WPA_UNIT_ONLY") != "1":
        return
    kept, deselected = [], []
    for item in items:
        needs = _STACK_FIXTURES.intersection(item.fixturenames) or item.get_closest_marker("needs_stack")
        (deselected if needs else kept).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept
