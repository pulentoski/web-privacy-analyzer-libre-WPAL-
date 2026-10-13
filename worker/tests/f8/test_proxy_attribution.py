"""IP real de cada destino desde el log del proxy, con atribución exacta por scan (F8, criterio 3)."""

import asyncio
import json
import pathlib
import time
import urllib.error
import urllib.request
import uuid

import pytest

from app.browser.capture import run_scan
from app.browser.proxy_log import read_destinations
from app.config import settings
from tests.helpers import SITE, run_async


def hosts_of(destinations):
    return {entry["host"] for entry in destinations}


@pytest.fixture(scope="module")
def concurrent(manifest):
    """Scans a la vez, cada uno con su usuario de proxy, hacia páginas con destinos distintos.

    El tercero hace cientos de requests a un solo host mientras los otros dos hablan con
    hosts distintos. Que corren a la vez se comprueba con el tiempo de vida de cada scan,
    no con las marcas de tiempo del log: el orden en que arrancan los navegadores varía, y
    el proxy registra cada línea al cerrar la transacción.
    """
    users = tuple(f"scan-{uuid.uuid4()}" for _ in range(3))

    lifetimes = {}

    async def timed(user, url):
        started = time.monotonic()
        outcome = await run_scan(url, proxy_user=user)
        lifetimes[user] = (started, time.monotonic())
        return outcome

    async def together():
        return await asyncio.gather(
            timed(users[0], manifest["f8"]["page"]),
            timed(users[1], manifest["page"]),
            timed(users[2], manifest["flood"]["page"]),
        )

    first, second, flood = run_async(together())
    assert first.error is None and second.error is None
    # Los tres navegadores estuvieron vivos a la vez, cada uno autenticado con su usuario.
    for a in users:
        for b in users:
            assert overlaps(lifetimes[a], lifetimes[b]), "los scans no corrieron a la vez"
    return users, first, second, flood


def test_two_concurrent_scans_do_not_mix_their_connections(concurrent, manifest):
    users, first, second, flood = concurrent
    for user, outcome in zip(users, (first, second, flood)):
        assert outcome.capture["proxy_user"] == user
        # Lo que el scan guardó es exactamente lo que el log tiene para su usuario.
        assert outcome.capture["destinations"] == read_destinations(user)
        captured = {request["host"] for request in outcome.capture["requests"] if request["scheme"] in ("http", "https")}
        assert hosts_of(outcome.capture["destinations"]) == captured, user
    cloaked = manifest["f8"]["cname_cloaking"]["host"]
    # El subdominio "metrics" solo lo pide la página /f8/, y cdn-b solo la página principal.
    assert cloaked in hosts_of(first.capture["destinations"]) and cloaked not in hosts_of(second.capture["destinations"])
    assert "cdn-b.fixtures.test" in hosts_of(second.capture["destinations"]) and "cdn-b.fixtures.test" not in hosts_of(first.capture["destinations"])
    # Los tres dejaron líneas en el mismo archivo de log, cada uno con su usuario.
    assert set(log_spans(users)) == set(users)
    # Mientras los otros dos hablaban con tracker-a, cdn-b y metrics, a este scan no se le atribuyó nada de eso.
    assert hosts_of(flood.capture["destinations"]) == {"site.fixtures.test"}
    assert sum(entry["connections"] for entry in flood.capture["destinations"]) > 100


def overlaps(a, b) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def log_spans(users) -> dict:
    """Primer y último instante en que el proxy registró algo de cada usuario."""
    spans = {}
    for path in sorted(pathlib.Path(settings.scanlog_dir).glob("access.jsonl*")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("user") in users:
                low, high = spans.get(entry["user"], (entry["ts"], entry["ts"]))
                spans[entry["user"]] = (min(low, entry["ts"]), max(high, entry["ts"]))
    return spans


def test_destination_ip_is_the_one_the_proxy_connected_to(concurrent, manifest):
    _, first, second, flood = concurrent
    for outcome in (first, second, flood):
        connected = [entry for entry in outcome.capture["destinations"] if entry["ip"] is not None]
        assert connected and {entry["ip"] for entry in connected} == {manifest["f8"]["destination_ip"]}
        assert all(entry["connections"] >= 1 for entry in outcome.capture["destinations"])


def test_denied_connections_have_no_ip_instead_of_an_invented_one(concurrent, manifest):
    """La página principal pide recursos que el proxy bloquea: quedan sin IP, no con una inventada."""
    _, _, second, _ = concurrent
    blocked = {request["host"] for request in second.capture["requests"] if request.get("blocked_by_proxy")}
    by_host = {}
    for entry in second.capture["destinations"]:
        by_host.setdefault(entry["host"], []).append(entry["ip"])
    for host in blocked:
        assert by_host[host] == [None], host


def test_unknown_user_reads_nothing():
    assert read_destinations(f"scan-{uuid.uuid4()}") == []


@pytest.mark.needs_stack  # comprueba el montaje de solo lectura del stack desplegado.
def test_worker_mounts_the_log_read_only():
    directory = pathlib.Path(settings.scanlog_dir)
    assert any(directory.glob("access.jsonl*"))
    with pytest.raises(OSError):
        (directory / "escritura-de-prueba").write_text("x")


def _status(proxy_url: str | None) -> int:
    handler = urllib.request.ProxyHandler({"http": proxy_url} if proxy_url else {})
    try:
        with urllib.request.build_opener(handler).open(SITE + "/__health", timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


@pytest.mark.parametrize(
    "user, password, expected",
    [
        (None, None, 407),
        ("scan-00000000-0000-0000-0000-000000000000", "secreto-incorrecto", 407),
        ("admin", "{secret}", 407),
        ("scan-no-es-un-uuid", "{secret}", 407),
        ("scan-00000000-0000-0000-0000-000000000000", "{secret}", 200),
    ],
)
def test_proxy_only_accepts_scan_users_with_the_shared_secret(fixtures_site, user, password, expected):
    base = settings.egress_proxy_url
    if user is None:
        url = base
    else:
        url = base.replace("://", f"://{user}:{password.format(secret=settings.proxy_scan_secret.get_secret_value())}@")
    assert _status(url) == expected
