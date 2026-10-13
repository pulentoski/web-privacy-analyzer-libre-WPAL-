"""Endpoints de captura (F2) contra la DB real, con filas insertadas por el test."""

import pytest


def test_scan_summary(client, scan):
    body = client.get(f"/api/scans/{scan}").json()
    assert body["status"] == "completed"
    assert body["summary"] == {
        "total_requests": 5,
        "by_resource_type": {"document": 1, "fetch": 1, "image": 3},
        "first_party": 2,
        "third_party": 3,
        "same_org": 0,
        "blocked_by_client": 0,
        "party_unknown": 0,
        "blocked": 1,
        "capture_truncated": True,
        "websockets": 0,
        "cookies": 0,
        "storage_items": 0,
        "redirect_chains": 1,
    }


def test_summary_of_scan_without_capture(client, empty_scan):
    summary = client.get(f"/api/scans/{empty_scan}").json()["summary"]
    assert summary["total_requests"] == 0 and summary["by_resource_type"] == {}
    # Sin dato del worker, truncated es desconocido (None), no false.
    assert summary["capture_truncated"] is None


def test_requests_pagination(client, scan):
    first = client.get(f"/api/scans/{scan}/requests", params={"page_size": 2}).json()
    assert (first["total"], first["page"], first["page_size"]) == (5, 1, 2)
    assert [item["seq"] for item in first["items"]] == [0, 1]
    last = client.get(f"/api/scans/{scan}/requests", params={"page_size": 2, "page": 3}).json()
    assert [item["seq"] for item in last["items"]] == [4]
    beyond = client.get(f"/api/scans/{scan}/requests", params={"page_size": 2, "page": 4}).json()
    assert beyond["items"] == [] and beyond["total"] == 5


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"resource_type": "image"}, [1, 2, 4]),
        ({"resource_type": "document"}, [0]),
        ({"third_party": "true"}, [2, 3, 4]),
        ({"third_party": "false"}, [0, 1]),
        ({"blocked": "true"}, [4]),
        ({"blocked": "false"}, [0, 1, 2, 3]),
        ({"third_party": "true", "blocked": "false", "resource_type": "image"}, [2]),
        ({"resource_type": "no-existe"}, []),
    ],
)
def test_requests_filters(client, scan, params, expected):
    body = client.get(f"/api/scans/{scan}/requests", params=params).json()
    assert [item["seq"] for item in body["items"]] == expected
    assert body["total"] == len(expected)


@pytest.mark.parametrize("params", [{"page": 0}, {"page_size": 0}, {"page_size": 201}, {"third_party": "quizas"}])
def test_requests_invalid_params(client, scan, params):
    response = client.get(f"/api/scans/{scan}/requests", params=params)
    assert response.status_code == 422
    assert response.json()["error_code"] == "REQUEST_INVALID"


def test_requests_of_unknown_scan(client):
    response = client.get("/api/scans/00000000-0000-0000-0000-000000000000/requests")
    assert response.status_code == 404
    assert response.json()["error_code"] == "JOB_NOT_FOUND"


def test_request_detail(client, scan):
    items = client.get(f"/api/scans/{scan}/requests", params={"resource_type": "fetch"}).json()["items"]
    detail = client.get(f"/api/scans/{scan}/requests/{items[0]['request_id']}").json()
    assert detail["seq"] == 3 and detail["method"] == "POST"
    # La query se devuelve cruda: orden y duplicados intactos.
    assert detail["query_params"] == [["a", "1"], ["a", "2"]]
    assert detail["post_data"] == {
        "data": "aGVsbG8=",
        "encoding": "utf8",
        "sha256": "ab" * 32,
        "size": 8,
        "truncated": False,
        "source": "playwright",
    }
    assert detail["initiator"]["script_url"] == "http://site.example/app.js"
    assert detail["redirected_from_seq"] == 2
    assert [(hop["hop"], hop["request_seq"], hop["status"]) for hop in detail["redirect_chain"]] == [(0, 2, 302), (1, 3, 200)]
    assert detail["request_headers"] == [{"name": "accept", "value": "*/*"}]


def test_request_detail_without_post_data_or_redirects(client, scan):
    items = client.get(f"/api/scans/{scan}/requests", params={"resource_type": "document"}).json()["items"]
    detail = client.get(f"/api/scans/{scan}/requests/{items[0]['request_id']}").json()
    assert detail["post_data"] is None
    assert detail["redirect_chain"] == []
    assert detail["is_navigation"] is True


def test_request_detail_not_found(client, scan):
    for request_id in ("999999999999", "0", "99999999999999999999999"):
        response = client.get(f"/api/scans/{scan}/requests/{request_id}")
        assert response.status_code == 404, request_id
        assert response.json()["error_code"] == "REQUEST_NOT_FOUND"


def test_request_detail_of_another_scan_is_not_exposed(client, scan, empty_scan):
    request_id = client.get(f"/api/scans/{scan}/requests").json()["items"][0]["request_id"]
    response = client.get(f"/api/scans/{empty_scan}/requests/{request_id}")
    assert response.status_code == 404
    assert response.json()["error_code"] == "REQUEST_NOT_FOUND"
