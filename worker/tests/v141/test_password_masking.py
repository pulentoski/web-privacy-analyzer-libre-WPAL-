"""v1.4.1: las credenciales escritas en una captura interactiva se enmascaran antes de guardar."""

import asyncio
import json
import uuid

import pytest

from app.browser.redact import is_sensitive, mark, redact_body
from app.interactive import InteractiveSession
from tests.helpers import SITE, run_async

USER = "ana@ejemplo.cl"
PASSWORD = "Sup3r-S3creta!ñ"
OTP = "654321"


# --- unidad ---


@pytest.mark.parametrize("name", ["password", "PASSWORD", "passwd", "pass", "pwd", "secret", "token", "otp", "pin", "cvv",
                                  "new_password", "currentPassword", "user[password]", "client_secret", "accessToken", "csrf-token", "card.cvv", "PIN2"])
def test_sensitive_names(name):
    assert is_sensitive(name)


@pytest.mark.parametrize("name", ["user", "email", "passenger", "compass", "shipping", "pinterest", "tokenizer", "opinion", "", None, 7, "q"])
def test_ordinary_names_are_left_alone(name):
    assert not is_sensitive(name)


def test_password_type_fields_are_masked_whatever_their_name():
    assert is_sensitive("clave", {"clave"}) and not is_sensitive("clave")


def test_form_body_keeps_only_name_and_length():
    body = b"user=ana%40ejemplo.cl&password=a+b%26c&otp=654321&vacio=&pwd=&next=%2Finicio"
    out, found = redact_body(body, "application/x-www-form-urlencoded; charset=UTF-8")
    assert out == b"user=ana%40ejemplo.cl&password=%5Benmascarado%3A5%5D&otp=%5Benmascarado%3A6%5D&vacio=&pwd=&next=%2Finicio"
    assert found == [{"name": "password", "length": 5}, {"name": "otp", "length": 6}]


def test_json_body_at_any_depth_and_truncated_json():
    body = json.dumps({"user": "ana", "password": "hunter2", "a": [{"pin": 1234, "ok": True, "token": None}], "meta": {"client_secret": "xyz", "secret": {"k": "v"}}})
    out, found = redact_body(body.encode(), "application/json")
    assert json.loads(out) == {"user": "ana", "password": mark(7), "a": [{"pin": mark(4), "ok": True, "token": None}], "meta": {"client_secret": mark(3), "secret": {"k": "v"}}}
    assert found == [{"name": "password", "length": 7}, {"name": "pin", "length": 4}, {"name": "client_secret", "length": 3}]
    cut, found = redact_body(b'{"user":"ana","password":"hunter2","extra":"corta', "application/json")
    assert b"hunter2" not in cut and b'"user":"ana"' in cut and found == [{"name": "password", "length": 7}]
    # Sin content-type, por forma.
    assert b"hunter2" not in redact_body(b'{"pwd":"hunter2"}', None)[0]


def test_multipart_body():
    body = (b'--X\r\nContent-Disposition: form-data; name="user"\r\n\r\nana\r\n'
            b'--X\r\nContent-Disposition: form-data; name="password"\r\n\r\nhunter2\r\nlinea2\r\n'
            b'--X\r\nContent-Disposition: form-data; name="token"; filename="t.bin"\r\nContent-Type: application/octet-stream\r\n\r\nBINARIO\r\n--X--\r\n')
    out, found = redact_body(body, "multipart/form-data; boundary=X")
    assert b"hunter2" not in out and b"linea2" not in out and b"\r\n\r\nana\r\n" in out and b"BINARIO" in out
    assert b'name="password"\r\n\r\n[enmascarado:15]\r\n--X' in out and found == [{"name": "password", "length": 15}]


@pytest.mark.parametrize("body, content_type", [(b"", "application/json"), (None, None), (b"\xff\xfe\x00binario", "application/octet-stream"),
                                                (b"texto libre con password=hunter2 dentro", "text/plain"), (b"user=ana&q=zapatillas", "application/x-www-form-urlencoded")])
def test_bodies_without_credentials_are_returned_untouched(body, content_type):
    out, found = redact_body(body, content_type)
    assert out is body and found == []


# --- sesión real con el formulario de login del fixture ---


@pytest.fixture(scope="module")
def login_capture():
    async def scenario():
        session = InteractiveSession(SITE + "/login/", proxy_user=f"scan-{uuid.uuid4()}", password="abc12345")
        try:
            assert await session.open() is None
            page = session.context.pages[0]
            await page.wait_for_load_state("load")
            # Tecleo real (eventos de teclado), como lo hace una persona por el visor.
            for selector, value in (("#user", USER), ("#clave", PASSWORD), ("#otp", OTP)):
                await page.click(selector)
                await page.keyboard.type(value, delay=5)
            await page.click("#api")
            await page.wait_for_function("document.title === 'Fixture Login enviado'", timeout=15_000)
            await page.click("#enter")
            await page.wait_for_load_state("load")
            await asyncio.sleep(1)
            fields = set(session.password_fields)
            outcome = await session.collect("user_stop")
        finally:
            await session.destroy()
        return outcome, fields

    return run_async(scenario())


def _post(capture, path):
    matches = [r for r in capture["requests"] if r["path"] == path and r["method"] == "POST"]
    assert len(matches) == 1, path
    return matches[0]


def test_password_field_name_is_learned_from_its_type(login_capture):
    assert login_capture[1] == {"clave"}


def test_no_credential_value_is_stored_anywhere(login_capture):
    outcome, _ = login_capture
    dump = json.dumps({"capture": outcome.capture, "result": outcome.result}, default=str, ensure_ascii=False)
    for secret in (PASSWORD, "Sup3r-S3creta", "Sup3r-S3creta%21%C3%B1", OTP, "tok-" + PASSWORD):
        assert secret not in dump, secret
    assert USER in dump or "ana%40ejemplo.cl" in dump  # lo que no es credencial se conserva


def test_form_json_and_multipart_bodies_are_masked(login_capture):
    capture = login_capture[0].capture
    form = _post(capture, "/login/submit")["post_data"]
    assert form["data"] == f"user=ana%40ejemplo.cl&clave=%5Benmascarado%3A{len(PASSWORD)}%5D&otp=%5Benmascarado%3A6%5D" and not form["truncated"]
    api = json.loads(_post(capture, "/login/api")["post_data"]["data"])
    assert api == {"user": USER, "password": mark(len(PASSWORD)), "profile": {"pin": mark(4), "newPassword": mark(len(PASSWORD)), "note": "visible"},
                   "items": [{"access_token": mark(len(PASSWORD) + 4)}]}
    upload = _post(capture, "/login/upload")["post_data"]["data"]
    assert f'name="clave"\r\n\r\n{mark(len(PASSWORD))}\r\n' in upload and f'name="cvv"\r\n\r\n{mark(3)}\r\n' in upload
    assert 'name="comment"\r\n\r\ntexto visible\r\n' in upload and f'name="user"\r\n\r\n{USER}\r\n' in upload


def test_only_name_and_length_are_recorded(login_capture):
    outcome, _ = login_capture
    masked = outcome.result["interactive"]["masked_fields"]
    by_path = {r["seq"]: r["path"] for r in outcome.capture["requests"]}
    got = sorted((by_path[item["seq"]], item["name"], item["length"]) for item in masked)
    n = len(PASSWORD)
    assert got == sorted([
        ("/login/submit", "clave", n), ("/login/submit", "otp", 6),
        ("/login/api", "password", n), ("/login/api", "pin", 4), ("/login/api", "newPassword", n), ("/login/api", "access_token", n + 4),
        ("/login/upload", "clave", n), ("/login/upload", "cvv", 3),
    ])
    assert all(set(item) == {"name", "length", "seq"} for item in masked)
