"""Límites y saneamiento de datos no confiables (sin navegador)."""

import base64
import hashlib

from app.browser.network_monitor import (
    MAX_HEADERS,
    MAX_HEADER_VALUE_CHARS,
    MAX_STACK_FRAMES,
    clean_headers,
    encode_body,
    normalize_initiator,
    split_url,
    text,
)
from app.browser.parties import is_third_party, registrable_domain


def test_text_is_storable_in_postgres():
    assert text("a\x00b", 10) == "ab"
    assert text("\ud800x", 10) == "?x"  # surrogate suelto: no es UTF-8 válido
    assert text("abcdef", 3) == "abc"
    assert text(123, 10) is None and text(None, 10) is None


def test_encode_body_utf8():
    body = encode_body(b'{"a":1}', 100)
    assert body == {
        "data": '{"a":1}',
        "encoding": "utf8",
        "size": 7,
        "sha256": hashlib.sha256(b'{"a":1}').hexdigest(),
        "truncated": False,
    }


def test_encode_body_truncates_but_hashes_everything():
    data = b"x" * 1000
    body = encode_body(data, 10)
    assert body["data"] == "x" * 10 and body["truncated"] is True
    assert body["size"] == 1000 and body["sha256"] == hashlib.sha256(data).hexdigest()


def test_encode_body_binary_is_base64():
    data = bytes(range(256))
    body = encode_body(data, 1000)
    assert body["encoding"] == "base64" and base64.b64decode(body["data"]) == data
    with_nul = encode_body(b"ab\x00cd", 100)
    assert with_nul["encoding"] == "base64"


def test_encode_body_truncation_inside_multibyte_char():
    data = "ññññ".encode()  # 2 bytes por carácter
    body = encode_body(data, 3)
    assert body["encoding"] == "utf8" and body["data"] == "ñ" and body["truncated"] is True


def test_split_url_keeps_raw_query_order_and_duplicates():
    parts = split_url("HTTP://Sub.Example.com:80/p%20a/th?b=2&a=1&b=%3D&flag&empty=&=x#frag")
    assert parts["scheme"] == "http" and parts["host"] == "sub.example.com"
    assert parts["path"] == "/p%20a/th"
    assert parts["query_params"] == [["b", "2"], ["a", "1"], ["b", "%3D"], ["flag", None], ["empty", ""], ["", "x"]]


def test_split_url_tolerates_garbage():
    assert split_url("http://[bad")["host"] is None
    assert split_url("")["query_params"] == []
    assert split_url("data:text/plain,hola")["host"] is None


def test_clean_headers_limits():
    headers = [{"name": f"h{i}", "value": "v" * 20000} for i in range(500)]
    cleaned = clean_headers(headers + ["no-dict", {"name": 1, "value": "x"}])
    assert len(cleaned) == MAX_HEADERS
    assert all(len(h["value"]) == MAX_HEADER_VALUE_CHARS for h in cleaned)
    assert clean_headers("no-list") == []
    # Duplicados y orden se conservan.
    assert clean_headers([{"name": "set-cookie", "value": "a"}, {"name": "set-cookie", "value": "b"}]) == [
        {"name": "set-cookie", "value": "a"},
        {"name": "set-cookie", "value": "b"},
    ]


def test_normalize_initiator_untrusted_shapes():
    assert normalize_initiator(None) is None
    assert normalize_initiator("script") is None
    weird = normalize_initiator({"type": 5, "stack": {"callFrames": "x", "parent": 3}})
    assert weird == {"type": None, "url": None, "line": None, "script_url": None, "stack": []}
    deep = {"callFrames": [{"functionName": "f", "url": "http://a/x.js", "lineNumber": 1, "columnNumber": 2}] * 100}
    assert len(normalize_initiator({"type": "script", "stack": deep})["stack"]) == MAX_STACK_FRAMES


def test_normalize_initiator_follows_async_parents():
    initiator = {
        "type": "script",
        "stack": {
            "callFrames": [],
            "parent": {"callFrames": [{"functionName": "later", "url": "http://a/app.js", "lineNumber": 7, "columnNumber": 0}]},
        },
    }
    result = normalize_initiator(initiator)
    assert result["script_url"] == "http://a/app.js"
    assert result["stack"] == [{"function": "later", "url": "http://a/app.js", "line": 7, "column": 0, "async": True}]


def test_registrable_domain_uses_bundled_psl():
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("user.github.io") == "user.github.io"  # sufijo privado de la PSL
    assert registrable_domain("EXAMPLE.com.") == "example.com"
    assert registrable_domain("93.184.215.14") == "93.184.215.14"
    assert registrable_domain("a.b.tld-inexistente") == "b.tld-inexistente"
    assert registrable_domain("") is None and registrable_domain(None) is None


def test_third_party_by_registrable_domain():
    first = {"example.com"}
    assert is_third_party("cdn.example.com", first) is False
    assert is_third_party("example.com", first) is False
    assert is_third_party("example.org", first) is True
    assert is_third_party("example.com.evil.net", first) is True
    assert is_third_party(None, first) is None
