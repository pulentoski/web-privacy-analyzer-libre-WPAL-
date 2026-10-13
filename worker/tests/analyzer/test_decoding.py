"""Decodificación: casos normales y entradas hostiles (criterios 6 y 12)."""

import base64
import gzip
import json
import time

import pytest

from app.analyzer import decoding
from app.analyzer.decoding import MAX_DEPTH, MAX_INPUT_CHARS, MAX_OUTPUT_CHARS, MAX_RESULTS, decode


def b64(data, urlsafe=False, padding=True) -> str:
    raw = data if isinstance(data, bytes) else data.encode()
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return out if padding else out.rstrip("=")


def chains(value):
    return [item.encoding_chain for item in decode(value)]


def test_base64_json_chain_and_raw_value_intact():
    payload = {"event": "pageview", "user": {"id": "usr-7f3a9c21d4"}}
    raw = b64(json.dumps(payload))
    original = str(raw)
    results = decode(raw)
    assert [r.encoding_chain for r in results] == [("base64",), ("base64", "json")]
    assert json.loads(results[1].decoded_value) == payload
    assert all(r.raw_value == original for r in results) and raw == original


@pytest.mark.parametrize("urlsafe", [False, True])
@pytest.mark.parametrize("padding", [False, True])
def test_base64_variants(urlsafe, padding):
    text = '{"q":"¿qué?>>>???","n":1}'  # produce + / (o - _) y relleno
    raw = b64(text, urlsafe=urlsafe, padding=padding)
    results = decode(raw)
    assert results[0].encoding_chain == ("base64",) and results[0].decoded_value == text


def test_jwt_header_and_payload_without_verifying_signature():
    header, payload = {"alg": "HS256", "typ": "JWT"}, {"sub": "usr-1", "iat": 1790000000}
    token = ".".join([b64(json.dumps(header), True, False), b64(json.dumps(payload), True, False), "firma-falsa"])
    results = decode(token)
    assert results[0].encoding_chain == ("jwt",)
    assert json.loads(results[0].decoded_value) == {"header": header, "payload": payload}
    assert results[0].raw_value == token


def test_url_encoding_and_nested_query():
    assert chains("https%3A%2F%2Fexample.com%2Fa%3Fb%3D1") == [("url",)]
    results = decode("a=1&u=https%3A%2F%2Fexample.com%2F&t=x")
    assert results[0].encoding_chain == ("url",)
    nested = decode("a%3D1%26b%3D2")
    assert [r.encoding_chain for r in nested] == [("url",), ("url", "query")]
    assert json.loads(nested[1].decoded_value) == [["a", "1"], ["b", "2"]]


def test_double_url_encoding_is_followed():
    results = decode("http%253A%252F%252Fexample.com")
    assert results[-1].encoding_chain == ("url", "url") and results[-1].decoded_value == "http://example.com"


def test_hex_text_and_gzip():
    assert decode("hola mundo".encode().hex())[0].encoding_chain == ("hex",)
    results = decode(b64(gzip.compress(b'{"a":"b"}')))
    assert [r.encoding_chain for r in results] == [("base64", "gzip"), ("base64", "gzip", "json")]


def test_nested_leaf_is_decoded_with_its_path():
    inner = b64(json.dumps({"uid": "abc"}))
    results = decode(json.dumps({"data": {"blob": inner}}))
    leaf = [r for r in results if r.path == "data.blob"]
    assert leaf and leaf[0].encoding_chain == ("json", "base64")


@pytest.mark.parametrize(
    "value",
    ["homepage", "deadbeefdeadbeef", "20261006123456", "true", "es-CL", "1280x720", "abc=", "", "a", "/path/to/x",
     "4142434445", "1234567890"],
)
def test_plain_values_are_not_decoded(value):
    assert decode(value) == []


@pytest.mark.parametrize("value", [None, 123, b"bytes", ["a"], {"a": 1}, 1.5])
def test_non_string_input(value):
    assert decode(value) == []


# --- Entradas hostiles: sin excepción y con los límites respetados ---


def test_giant_base64_is_bounded():
    raw = b64(b"A" * (MAX_INPUT_CHARS // 2))
    started = time.monotonic()
    results = decode(raw)
    assert time.monotonic() - started < 2
    assert results and all(len(r.decoded_value) <= MAX_OUTPUT_CHARS for r in results)
    assert results[0].truncated is True


def test_input_over_the_limit_is_not_processed():
    assert decode(b64(b"A" * MAX_INPUT_CHARS)) == []
    assert decode("%41" * MAX_INPUT_CHARS) == []


def test_deeply_nested_json_does_not_raise():
    started = time.monotonic()
    assert decode("[" * 30000 + "]" * 30000) == []  # RecursionError del parser, contenida
    deep = '{"a":' * 500 + '"x"' + "}" * 500
    results = decode(deep)
    assert time.monotonic() - started < 5
    assert all(len(r.decoded_value) <= MAX_OUTPUT_CHARS for r in results)


def test_encoding_depth_is_limited():
    value = '{"uid":"x1"}'
    for _ in range(10):
        value = b64(value)
    results = decode(value)
    assert results and max(len(r.encoding_chain) for r in results) <= MAX_DEPTH
    assert all(r.raw_value == value for r in results)


def test_result_count_is_limited():
    wide = json.dumps({f"k{i}": b64(json.dumps({"i": i, "pad": "x" * 10})) for i in range(500)})
    assert len(decode(wide)) <= MAX_RESULTS


@pytest.mark.parametrize(
    "value",
    [
        '{"a": ',
        '{"a": 1,}',
        "[1, 2",
        '{"a": NaN}',
        '{"\\ud800": "\\udfff"}',
        "{" * 100,
        '{"a":"' + "\\" * 1001 + '"}',
        "eyJ.eyJ.x",
        "eyJhbGciOiJIUzI1NiJ9..",
        "eyJ" + "A" * 5000 + "." + "B" * 5000 + ".c",
        "%" * 5000,
        "%zz%1%%%",
        "=" * 5000,
        "&" * 5000,
        "a=" * 5000,
        "=&=&=&=",
        "\x00" * 100,
        "\ud800" * 50,
        "A" * 65536,
        "====",
        "ab==cd==",
        "00" * 4000,
        "ff" * 4000,
    ],
)
def test_malformed_input_never_raises(value):
    results = decode(value)
    assert isinstance(results, list) and len(results) <= MAX_RESULTS
    assert all(len(r.decoded_value) <= MAX_OUTPUT_CHARS and len(r.encoding_chain) <= MAX_DEPTH + 1 for r in results)


def test_gzip_bomb_is_bounded():
    bomb = gzip.compress(b"0" * 20_000_000)  # ~20 KB comprimido -> 20 MB
    raw = b64(bomb)
    assert len(raw) <= MAX_INPUT_CHARS
    started = time.monotonic()
    results = decode(raw)
    assert time.monotonic() - started < 2
    assert all(len(r.decoded_value) <= MAX_OUTPUT_CHARS for r in results)


def test_a_failing_decoder_is_contained(monkeypatch):
    def boom(value):
        raise RuntimeError("decoder roto")

    monkeypatch.setattr(decoding, "_DECODERS", (boom, decoding._try_url))
    assert [r.encoding_chain for r in decode("a%20b")] == [("url",)]


def test_no_regex_in_decoder():
    # Garantía estructural: sin `re` no hay backtracking catastrófico posible.
    import inspect

    source = inspect.getsource(decoding)
    assert "import re" not in source and "re.compile" not in source


def test_numeric_ids_and_base64_padding_are_not_misread():
    # Un id numérico no es hexadecimal aunque todos sus dígitos lo sean.
    assert decode("4142434445") == []
    # Un Base64 con relleno, ya decodificado de URL, no es un query "clave==".
    padded = "AAECAwQFBgcICQoLDA0ODw=="  # 16 bytes binarios: no decodifica a texto
    assert decode(padded) == []
    encoded = decode("AAECAwQFBgcICQoLDA0ODw%3D%3D")
    assert [item.encoding_chain for item in encoded] == [("url",)]
    assert encoded[0].decoded_value == padded
