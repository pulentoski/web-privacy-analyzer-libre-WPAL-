"""Tests contra la app real. Se ejecutan dentro del contenedor api, con la DB del stack."""


ERROR_KEYS = {"error_code", "message", "details", "stage", "timestamp"}


def test_health_shape(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "database", "worker"}
    assert body["database"] is True
    assert isinstance(body["worker"], bool)
    assert body["status"] == ("ok" if body["worker"] else "degraded")


def test_forbidden_url_is_rejected_with_error_format(client):
    response = client.post("/api/scans", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 400
    body = response.json()
    assert set(body) == ERROR_KEYS
    assert body["error_code"] == "IP_FORBIDDEN"
    assert body["stage"] == "url_validation"


def test_request_validation_error_format(client):
    response = client.post("/api/scans", json={})
    assert response.status_code == 422
    body = response.json()
    assert set(body) == ERROR_KEYS
    assert body["error_code"] == "REQUEST_INVALID"


def test_not_found_error_format(client):
    response = client.get("/no-existe")
    assert response.status_code == 404
    assert set(response.json()) == ERROR_KEYS


def test_unknown_job_error_format(client):
    response = client.get("/api/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert response.json()["error_code"] == "JOB_NOT_FOUND"


def test_malformed_job_id_error_format(client):
    response = client.get("/api/scans/not-a-uuid")
    assert response.status_code == 422
    assert set(response.json()) == ERROR_KEYS


def test_unexpected_error_has_no_stack_trace(client, monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("detalle interno secreto")

    monkeypatch.setattr("app.routes.scans.validate_url", boom)
    response = client.post("/api/scans", json={"url": "https://example.com"})
    assert response.status_code == 500
    body = response.json()
    assert set(body) == ERROR_KEYS
    assert body["error_code"] == "INTERNAL_ERROR"
    assert "secreto" not in response.text
    assert "Traceback" not in response.text
