"""Perfil de licencias (F9, criterio 5): en modo comercial no se abren fuentes NC ni sin licencia."""

import pathlib

import pytest

from app.analyzer.config import load_config
from app.analyzer.engine import analyze, prepare_capture
from app.analyzer.lists import UNKNOWN_ENTITY, FilterLists
from app.config import _license_profile, settings


@pytest.fixture
def opened(monkeypatch):
    """Registra cada archivo de data/ que se lee."""
    paths: list[str] = []
    read_text, read_bytes = pathlib.Path.read_text, pathlib.Path.read_bytes

    def spy_text(self, *args, **kwargs):
        paths.append(str(self))
        return read_text(self, *args, **kwargs)

    def spy_bytes(self, *args, **kwargs):
        paths.append(str(self))
        return read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "read_text", spy_text)
    monkeypatch.setattr(pathlib.Path, "read_bytes", spy_bytes)
    return paths


def test_commercial_profile_never_opens_excluded_sources(opened):
    lists = FilterLists(settings.data_dir, allow_fixtures=True, license_profile="comercial")
    config = load_config(settings.data_dir, allow_fixtures=True, license_profile="comercial")
    ids = [source["id"] for source in lists.sources]
    assert ids == ["easylist", "easyprivacy", "companiesdb", "test-fixtures"]
    assert not any(source["noncommercial"] for source in lists.sources)
    assert lists.excluded == [{"id": "entity_map", "license": "CC-BY-NC-SA-4.0", "reason": "licencia no comercial"}]
    assert config.cmp_names == {}
    # Verificado en el sistema de archivos: ni el mapa de DuckDuckGo ni la lista de IAB se leyeron.
    assert not any(path.endswith("lists/entity_map.json") for path in opened), opened
    assert not any("iab" in path for path in opened), opened
    assert any(path.endswith("companiesdb/entity_map.json") for path in opened)


def test_default_profile_keeps_the_previous_sources(opened):
    lists = FilterLists(settings.data_dir, allow_fixtures=True)
    config = load_config(settings.data_dir, allow_fixtures=True)
    assert lists.license_profile == "no_comercial" and lists.excluded == []
    assert [source["id"] for source in lists.sources] == ["easylist", "easyprivacy", "entity_map", "test-fixtures"]
    assert config.cmp_names[28] == "OneTrust LLC"
    assert not any("companiesdb" in path for path in opened)


def test_profiles_give_different_list_versions_and_known_entities():
    default = FilterLists(settings.data_dir, allow_fixtures=True)
    commercial = FilterLists(settings.data_dir, allow_fixtures=True, license_profile="comercial")
    assert default.version != commercial.version
    for lists in (default, commercial):
        assert "Google" in lists.entity("doubleclick.net")
        assert lists.entity("dominio-que-no-existe.example") == UNKNOWN_ENTITY
        # Las listas de filtros son las mismas en ambos perfiles.
        request = {"url": "https://www.google-analytics.com/collect?v=1", "host": "www.google-analytics.com", "resource_type": "image", "third_party": True, "seq": 3}
        assert [match["list"] for match in lists.match(request, "site.example")]


def test_invalid_profile_is_rejected_at_startup():
    assert _license_profile("") == "no_comercial" and _license_profile(" COMERCIAL ") == "comercial"
    with pytest.raises(ValueError):
        _license_profile("gratis")
    with pytest.raises(ValueError):
        FilterLists(settings.data_dir, license_profile="gratis")


def test_analysis_records_its_profile_and_shows_only_the_cmp_number_in_commercial_mode(manifest):
    from app.browser.capture import run_scan
    from tests.helpers import run_async

    url = manifest["f8"]["page"] + "?gdpr=0"
    outcome = run_async(run_scan(url))
    assert outcome.error is None
    prepared = prepare_capture(outcome.capture, start_url=url, page_url=outcome.result["final_url"], result=outcome.result)
    expected = {"no_comercial": ("OneTrust LLC", "OneTrust LLC (cmpId 28)"), "comercial": ("no_disponible", "CMP 28")}
    for profile, (name, label) in expected.items():
        lists = FilterLists(settings.data_dir, allow_fixtures=True, license_profile=profile)
        config = load_config(settings.data_dir, allow_fixtures=True, license_profile=profile)
        analysis = analyze(prepared, lists, config)
        assert analysis["site"]["summary"]["license_profile"] == profile
        assert analysis["site"]["summary"]["consent"]["tcf"]["cmp_name"] == name
        (finding,) = [item for item in analysis["findings"] if item["type"] == "tcf_state"]
        assert label in finding["claim"] and ("OneTrust" in finding["claim"]) is (profile == "no_comercial")
        assert [source["id"] for source in analysis["lists"]] == [source["id"] for source in lists.sources]
