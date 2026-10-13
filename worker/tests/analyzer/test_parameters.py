"""Nombres, formas y extracción de parámetros."""

import pytest

from app.analyzer.parameters import extract, is_identifier_like, name_tokens, shannon_entropy, value_shapes


@pytest.fixture(scope="module")
def names(analyzer_resources):
    return analyzer_resources[1].names


@pytest.mark.parametrize(
    "name, expected",
    [
        ("uid", "identity"), ("user_id", "identity"), ("userId", "identity"), ("data.user.id", "identity"),
        ("partner_uid", "identity"), ("trackingId", "identity"), ("tracking_id", "identity"), ("_ga", "identity"), ("token.payload.sub", "identity"),
        ("sid", "session"), ("token", "session"), ("csrfToken", "session"),
        ("gclid", "advertising"), ("utm_source", "advertising"),
        ("page", "navigation"), ("dl", "navigation"), ("referrer", "navigation"),
        ("ts", "time"), ("sr", "device"), ("screenResolution", "device"), ("lat", "location"),
        ("x", None), ("color", None), ("i", None), ("", None),
    ],
)
def test_name_categories(names, name, expected):
    assert names.categorize(name) == expected


def test_name_tokens():
    assert name_tokens("userSessionId") == ["user", "session", "id"]
    assert name_tokens("utm_source") == ["utm", "source"]
    assert name_tokens("a.b[0]-c") == ["a", "b", "0", "c"]


@pytest.mark.parametrize(
    "value, shape",
    [
        ("3f2b8c1e-9d4a-4f6b-8a2c-1e5d7f9b0c3a", "uuid"),
        ("a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", "hex"),
        ("1790000000", "timestamp"), ("1790000000123", "timestamp"), ("12345", "numeric"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", "jwt"),
        ("192.168.1.10", "ip"), ("2001:db8::1", "ip"),
        ("https://example.com/a", "url"), ("https%3A%2F%2Fexample.com", "url"),
        ("alguien@example.com", "email"), ("alguien%40example.com", "email"),
        ("dGVzdC12YWx1ZS0xMjM0NTY3ODkw", "base64"), ("", "empty"),
    ],
)
def test_value_shapes(value, shape):
    assert shape in value_shapes(value)


@pytest.mark.parametrize("value", ["hola", "@", "a@b", "no es un email", "1.2", "999.999.999.999", "true"])
def test_value_shapes_negative(value):
    assert not {"email", "ip", "uuid", "jwt", "hex"} & set(value_shapes(value))


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e", True), ("usr-7f3a9c21d4", True), ("GA1.2.1234567890.1790000000", True),
        ("3f2b8c1e-9d4a-4f6b-8a2c-1e5d7f9b0c3a", True),
        ("true", False), ("es-CL", False), ("1790000000", False), ("https://example.com/", False),
        ("alguien@example.com", False), ("hola mundo cruel", False), ("aaaaaaaaaaaa", False), ("x" * 600, False),
    ],
)
def test_identifier_like(value, expected):
    assert is_identifier_like(value, value_shapes(value), shannon_entropy(value)) is expected


def test_extract_sources_and_derived_params(names):
    request = {
        "request_id": 7,
        "query_params": [["uid", "a3f9c2e1b7d44f6a"], ["page", "http%3A%2F%2Fsite.example%2Fx"], ["flag", None]],
        "request_headers": [{"name": "Cookie", "value": "sid=abc123; theme=dark"}, {"name": "content-type", "value": "application/x-www-form-urlencoded"}],
        "response_headers": [{"name": "Set-Cookie", "value": "tid=zzz999; Path=/; HttpOnly"}],
        "post_data": {"data": "email=alguien%40example.com&n=1", "encoding": "utf8", "size": 31},
    }
    params, decoded = extract(request, names)
    by_key = {(p.source, p.name): p for p in params}
    assert by_key[("query", "uid")].category == "identity" and by_key[("query", "uid")].identifier_like
    assert by_key[("query", "flag")].value == ""
    # El valor crudo se conserva y el decodificado es un parámetro derivado, con su cadena.
    assert by_key[("query", "page")].value == "http%3A%2F%2Fsite.example%2Fx"
    assert by_key[("query_decoded", "page")].value == "http://site.example/x"
    assert by_key[("query_decoded", "page")].encoding_chain == ("url",)
    assert "email" in by_key[("post_form", "email")].shapes
    assert by_key[("cookie", "sid")].category == "session" and ("cookie", "theme") in by_key
    assert by_key[("set_cookie", "tid")].value == "zzz999"
    assert all(p.request_id == 7 for p in params)
    assert [d["encoding_chain"] for d in decoded if d["name"] == "page"] == [["url"]]


def test_extract_tolerates_garbage(names):
    for request in (
        {"request_id": 1},
        {"request_id": 1, "query_params": "x", "request_headers": None, "post_data": "x"},
        {"request_id": 1, "query_params": [["a"], [1, 2], None, ["ok", "v"]], "post_data": {"data": None, "encoding": "utf8"}},
        {"request_id": 1, "query_params": [["k" * 5000, "v" * 100000]] * 400},
        {"request_id": 1, "post_data": {"data": "&=&&==&" * 1000, "encoding": "utf8"},
         "request_headers": [{"name": "content-type", "value": "application/x-www-form-urlencoded"}, "basura", {"name": "cookie"}]},
    ):
        params, decoded = extract(request, names)
        assert len(params) <= 150
