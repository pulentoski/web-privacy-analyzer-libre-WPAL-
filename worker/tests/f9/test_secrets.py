"""Los secretos de la configuración del worker no aparecen en repr, str, logs ni errores (F9)."""

import asyncio
import copy
import json
import logging
import pickle

import asyncpg
import pytest

from app.browser.launcher import launch_kwargs
from app.config import Secret, Settings, settings
from app.logging_setup import JsonFormatter

FAKE = "s3creto-de-prueba-9f2c7a"


def real_secrets() -> list[str]:
    return [value for value in (settings.postgres_password.get_secret_value(), settings.proxy_scan_secret.get_secret_value()) if value]


def test_settings_repr_and_str_are_masked():
    assert isinstance(settings.postgres_password, Secret) and isinstance(settings.proxy_scan_secret, Secret)
    assert len(real_secrets()) == 2
    for secret in real_secrets():
        for rendered in (repr(settings), str(settings), f"{settings}", repr(vars(settings)), repr(settings.__dict__)):
            assert secret not in rendered
    assert "**********" in repr(settings)


def test_secret_type():
    secret = Secret(FAKE)
    assert secret.get_secret_value() == FAKE
    for rendered in (repr(secret), str(secret), f"{secret}", f"{secret!r}", "%s" % secret, json.dumps({"x": secret}, default=str), repr([secret]), repr({"k": secret})):
        assert FAKE not in rendered
    assert bool(secret) and not bool(Secret("")) and str(Secret("")) == ""
    assert secret == Secret(FAKE) and secret != Secret("otro") and secret != FAKE
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        copy.deepcopy(secret)


def test_logs_mask_secrets_even_if_settings_are_logged():
    record = logging.LogRecord("worker", logging.ERROR, __file__, 1, "config %s y %r", (settings, settings.proxy_scan_secret), None)
    record.settings = settings
    record.secret = settings.proxy_scan_secret
    line = JsonFormatter().format(record)
    for secret in real_secrets():
        assert secret not in line
    assert "**********" in line


def test_traceback_with_settings_is_masked():
    try:
        assert settings.max_requests == -1, settings
    except AssertionError as error:
        for secret in real_secrets():
            assert secret not in str(error)


def test_database_errors_do_not_contain_the_password():
    async def connect():
        await asyncpg.connect(host=settings.postgres_host, user="usuario-inexistente", password=FAKE, database=settings.postgres_db, timeout=10)

    with pytest.raises(Exception) as caught:
        asyncio.run(connect())
    assert FAKE not in str(caught.value) and FAKE not in repr(caught.value)


def test_proxy_password_only_reaches_the_browser_launch_options():
    """El navegador necesita la contraseña del proxy: es el único sitio donde viaja en claro."""
    kwargs = launch_kwargs("scan-00000000-0000-0000-0000-000000000000")
    assert kwargs["proxy"]["password"] == settings.proxy_scan_secret.get_secret_value()
    # No va en la línea de comandos de Chromium (visible en `ps`), sino en las opciones del proxy.
    assert not any(settings.proxy_scan_secret.get_secret_value() in argument for argument in kwargs["args"])
    assert settings.proxy_scan_secret.get_secret_value() not in kwargs["proxy"]["server"]


def test_settings_fields_holding_secrets_are_all_wrapped():
    """Si alguien añade un campo con nombre de secreto, debe ser un Secret."""
    for name, value in vars(Settings()).items():
        if any(word in name for word in ("password", "secret", "token", "key")):
            assert isinstance(value, Secret), name
