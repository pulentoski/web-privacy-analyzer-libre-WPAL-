"""F9: secretos que no se filtran, cascada de report_files, perfil de licencias y OpenAPI."""

import asyncio
import json
import logging
import uuid

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import Settings, get_settings
from app.db import SessionLocal, engine
from app.logging_setup import JsonFormatter
from app.models import Job
from app.report_html import render_scan_report
from tests.test_analysis_api import analyzed_scan  # noqa: F401  (fixture)
from app.routes.analysis import CMP_EXCLUDED, attributions, license_profile_of, report_validator

FAKE = "s3creto-de-prueba-9f2c7a"


def secrets() -> list[str]:
    settings = get_settings()
    return [value for value in (settings.postgres_password.get_secret_value(), settings.exposure_presenter_token.get_secret_value()) if value]


# --- Secretos (criterio 1) ---


def test_settings_never_show_secrets_in_repr_str_or_dumps():
    settings = get_settings()
    assert isinstance(settings.postgres_password, SecretStr) and isinstance(settings.exposure_presenter_token, SecretStr)
    rendered = [repr(settings), str(settings), f"{settings}", repr(settings.model_dump()), settings.model_dump_json(), repr(vars(settings))]
    assert secrets(), "el stack de test tiene al menos la contraseña de la base"
    for secret in secrets():
        for where in rendered:
            assert secret not in where
    assert "**********" in repr(settings)


def test_pytest_style_traceback_of_settings_is_masked():
    """Lo que pasó en F8: un traceback imprimió repr(Settings). Ahora ese repr no lleva el valor."""
    settings = Settings(postgres_user="u", postgres_password=FAKE, postgres_db="d", exposure_presenter_token=FAKE)
    try:
        assert settings.scan_rate_limit == -1, settings
    except AssertionError as error:
        assert FAKE not in str(error) and FAKE not in repr(error)
    assert FAKE not in repr(settings) and settings.postgres_password.get_secret_value() == FAKE


def test_validation_errors_do_not_echo_secrets():
    with pytest.raises(ValidationError) as caught:
        Settings(postgres_user="u", postgres_password=FAKE, postgres_db="d", exposure_presenter_token=FAKE, scan_rate_limit="no-es-un-numero")
    assert FAKE not in str(caught.value) and FAKE not in repr(caught.value) and FAKE not in json.dumps(caught.value.errors(), default=str)


def test_database_url_is_only_revealed_to_the_driver():
    settings = Settings(postgres_user="u", postgres_password=FAKE, postgres_db="d")
    assert FAKE in settings.database_url  # el driver la necesita
    for secret in secrets():
        assert secret not in repr(engine) and secret not in str(engine.url) and secret not in repr(engine.url)


def test_connection_errors_do_not_contain_the_password():
    settings = Settings(postgres_user="usuario-inexistente", postgres_password=FAKE, postgres_db="d", postgres_host="db")
    broken = create_async_engine(settings.database_url)

    async def connect():
        try:
            async with broken.connect():
                pass
        finally:
            await broken.dispose()

    with pytest.raises(Exception) as caught:
        asyncio.run(connect())
    assert FAKE not in str(caught.value) and FAKE not in repr(caught.value)


def test_logs_mask_secrets_even_if_settings_are_logged():
    settings = Settings(postgres_user="u", postgres_password=FAKE, postgres_db="d", exposure_presenter_token=FAKE)
    record = logging.LogRecord("app", logging.ERROR, __file__, 1, "config: %s", (settings,), None)
    record.settings = settings
    record.token = settings.exposure_presenter_token
    line = JsonFormatter().format(record)
    assert FAKE not in line and "**********" in line


def test_error_responses_do_not_leak_internals(client):
    """Un error inesperado que lleve la URL de la base en su mensaje no llega al cliente."""
    from app.db import get_session

    async def explode():
        # Valor ficticio: el mensaje de una excepción sí queda en el log del servidor.
        raise RuntimeError(f"fallo conectando con postgresql+asyncpg://u:{FAKE}@db/d")
        yield  # pragma: no cover

    client.app.dependency_overrides[get_session] = explode
    try:
        response = client.get("/api/scans")
    finally:
        client.app.dependency_overrides.pop(get_session)
    assert response.status_code == 500 and response.json()["error_code"] == "INTERNAL_ERROR"
    assert FAKE not in response.text and "postgresql" not in response.text and "RuntimeError" not in response.text
    assert client.get("/api/scans").status_code == 200


def test_wrong_presenter_token_is_rejected_without_echoing_the_real_one(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "exposure_presenter_token", SecretStr(FAKE))
    response = client.post("/api/exposure/purge", headers={"X-Presenter-Token": "otro"})
    assert response.status_code == 403 and FAKE not in response.text
    assert client.post("/api/exposure/purge", headers={"X-Presenter-Token": FAKE}).status_code == 200


# --- Cascada de report_files (criterio 3) ---


def test_report_files_are_deleted_with_their_scan_and_with_their_group(client):
    job_id, other_id, group_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    async def insert():
        async with SessionLocal() as session:
            session.add_all([Job(id=job_id, url="http://site.example/", status="failed"), Job(id=other_id, url="http://site.example/", status="failed")])
            await session.execute(text("INSERT INTO test_groups (id, url, config) VALUES (:id, 'http://site.example/', '{}')"), {"id": group_id})
            await session.flush()
            for subject_type, subject_id in (("scan", job_id), ("scan", other_id), ("group", group_id)):
                for kind, reveal in (("json", False), ("html", False), ("pdf", False), ("json", True)):
                    await session.execute(
                        text("INSERT INTO report_files (subject_type, subject_id, kind, reveal, sha256, status, data) VALUES (:t, :i, :k, :r, 'x', 'ready', 'x')"),
                        {"t": subject_type, "i": subject_id, "k": kind, "r": reveal},
                    )
            await session.commit()

    async def count(subject_id):
        async with SessionLocal() as session:
            return await session.scalar(text("SELECT count(*) FROM report_files WHERE subject_id = :id"), {"id": subject_id})

    async def delete(statement, subject_id):
        async with SessionLocal() as session:
            await session.execute(text(statement), {"id": subject_id})
            await session.commit()

    client.portal.call(insert)
    try:
        assert [client.portal.call(count, item) for item in (job_id, other_id, group_id)] == [4, 4, 4]
        client.portal.call(delete, "DELETE FROM jobs WHERE id = :id", job_id)
        # Solo los del scan borrado: ni los de otro scan ni los del grupo.
        assert [client.portal.call(count, item) for item in (job_id, other_id, group_id)] == [0, 4, 4]
        client.portal.call(delete, "DELETE FROM test_groups WHERE id = :id", group_id)
        assert [client.portal.call(count, item) for item in (job_id, other_id, group_id)] == [0, 4, 0]
    finally:
        client.portal.call(delete, "DELETE FROM jobs WHERE id = :id", other_id)
        client.portal.call(delete, "DELETE FROM test_groups WHERE id = :id", group_id)
    assert client.portal.call(count, other_id) == 0


def test_no_orphan_report_files_exist(client):
    async def orphans():
        async with SessionLocal() as session:
            return await session.scalar(text(
                "SELECT count(*) FROM report_files f WHERE (f.subject_type = 'scan' AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = f.subject_id)) "
                "OR (f.subject_type = 'group' AND NOT EXISTS (SELECT 1 FROM test_groups g WHERE g.id = f.subject_id))"))

    assert client.portal.call(orphans) == 0


# --- Perfil de licencias en el reporte (criterio 5) ---

LISTS = {
    "no_comercial": [{"id": "easylist", "license": "GPL-3.0-or-later OR CC-BY-SA-3.0", "noncommercial": False},
                     {"id": "entity_map", "license": "CC-BY-NC-SA-4.0", "noncommercial": True}],
    "comercial": [{"id": "easylist", "license": "GPL-3.0-or-later OR CC-BY-SA-3.0", "noncommercial": False},
                  {"id": "companiesdb", "license": "CC-BY-SA-4.0", "noncommercial": False}],
}


def test_attributions_follow_the_license_profile():
    commercial = attributions(LISTS["comercial"], "comercial")
    assert [item["source"] for item in commercial] == ["EasyList", "AdGuard companiesdb", "DB-IP Lite (país y ASN)"]
    assert not any(item["noncommercial"] for item in commercial) and not any("explícita" in item["license"] for item in commercial)
    default = attributions(LISTS["no_comercial"], "no_comercial")
    assert {"DuckDuckGo Tracker Radar", "Lista de CMP de IAB Europe"} <= {item["source"] for item in default}
    assert license_profile_of(None) == license_profile_of({}) == license_profile_of({"license_profile": "otro"}) == "no_comercial"
    assert license_profile_of({"license_profile": "comercial"}) == "comercial"


def test_report_states_its_license_profile(client, analyzed_scan):  # noqa: F811
    job_id = analyzed_scan[0]
    report = client.get(f"/api/scans/{job_id}/report").json()
    assert report["schema_version"] == "1.11.0" and report["license_profile"] in ("no_comercial", "comercial")
    assert list(report_validator().iter_errors(report)) == []
    assert list(report_validator().iter_errors({**report, "license_profile": "libre"}))
    assert list(report_validator().iter_errors({key: value for key, value in report.items() if key != "license_profile"}))
    commercial = {**report, "license_profile": "comercial", "attributions": attributions(LISTS["comercial"], "comercial"),
                  "versions": {**report["versions"], "cmp_list": CMP_EXCLUDED}}
    assert list(report_validator().iter_errors(commercial)) == []
    html = render_scan_report(commercial, "0" * 64)
    assert "Perfil de licencias de las fuentes: <strong>comercial</strong>" in html and "AdGuard companiesdb" in html
    assert "DuckDuckGo" not in html and "IAB Europe" not in html and CMP_EXCLUDED in html
    assert "Perfil de licencias de las fuentes: <strong>no comercial</strong>" in render_scan_report({**report, "license_profile": "no_comercial"}, "0" * 64)


# --- OpenAPI ---


def test_openapi_is_served_on_the_api_port(client):
    schema = client.get("/openapi.json")
    assert schema.status_code == 200 and schema.json()["info"]["version"] == "1.5.3"
    paths = schema.json()["paths"]
    for path in ("/health", "/api/scans", "/api/scans/{job_id}/report", "/api/scans/{job_id}/export", "/api/privacy/test"):
        assert path in paths, path
    assert client.get("/docs").status_code == 200
    for secret in secrets():
        assert secret not in schema.text
