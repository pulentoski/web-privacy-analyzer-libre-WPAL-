"""v1.4: SSRF y aislamiento desde una captura interactiva real (Xvfb + x11vnc + Chromium + proxy).

El navegador de la sesión es el mismo que el de un scan: todo sale por el egress-proxy, que valida
la IP resuelta en cada conexión. Aquí se comprueba con la sesión levantada de verdad, navegando
como lo haría el usuario, y además que el VNC no es una puerta: solo escucha en la red interna,
pide contraseña y el propio navegador no puede llegar a él.
"""

import asyncio
import pathlib
import socket
import uuid

import pytest
from playwright.async_api import Error as PlaywrightError

from app.config import settings
from app.interactive import InteractiveSession
from tests.helpers import SITE, run_async

from .conftest import CANARY_BODY, PROXY_ERROR_HEADER, required_env
from .test_ssrf import BLOCKED_FROM_ENV, BLOCKED_URLS, FETCH_JS, WEBSOCKET_JS

PASSWORD = "s3cr3t-1"
FP_PAGE = SITE + "/fp/article?ref=campaign42"


def _processes(needle: str) -> list[str]:
    found = []
    for entry in pathlib.Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if needle in command:
                found.append(command)
    return found


def _connects(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _vnc_security_types(host: str, port: int) -> list[int]:
    """Saludo RFB 3.8: devuelve los tipos de seguridad que ofrece el servidor (1 = sin contraseña, 2 = VNC auth)."""
    with socket.create_connection((host, port), timeout=5) as conn:
        assert conn.recv(12).startswith(b"RFB 003.")
        conn.sendall(b"RFB 003.008\n")
        count = conn.recv(1)[0]
        return list(conn.recv(count))


async def _visit(page, url: str) -> dict:
    try:
        response = await page.goto(url, timeout=30_000)
    except PlaywrightError as exc:
        return {"error": exc.message.splitlines()[0], "proxy_error": None, "body": ""}
    return {"error": None, "status": response.status, "proxy_error": response.headers.get(PROXY_ERROR_HEADER), "body": await page.content()}


async def _go(page, url: str, **kwargs) -> None:
    """Navega a una página pública. Tras un bloqueo, Chromium aún puede estar cargando su página de error."""
    for attempt in range(4):
        try:
            await page.goto(url, timeout=30_000, **kwargs)
            return
        except PlaywrightError as exc:
            if "interrupted by another navigation" not in exc.message or attempt == 3:
                raise
            await asyncio.sleep(0.5)


@pytest.fixture(scope="module")
def interactive():
    sandbox_ip = socket.gethostbyname("egress-proxy")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((sandbox_ip, 3128))
        own_sandbox_ip = probe.getsockname()[0]

    async def scenario():
        out = {"visits": {}, "own_sandbox_ip": own_sandbox_ip}
        session = InteractiveSession(SITE + "/", proxy_user=f"scan-{uuid.uuid4()}", password=PASSWORD)
        try:
            out["open_error"] = await session.open()
            out["vnc"] = (session.vnc_host, session.vnc_port)
            out["running"] = {"x11vnc": len(_processes("x11vnc -display")), "xvfb": len(_processes(f"Xvfb {settings.interactive_display} "))}
            out["password_file_left"] = [str(p) for p in pathlib.Path("/tmp").glob("wpa-vnc-*")]
            out["security_types"] = await asyncio.to_thread(_vnc_security_types, *out["vnc"])
            out["listening"] = {
                "internal": await asyncio.to_thread(_connects, session.vnc_host, session.vnc_port),
                "loopback": await asyncio.to_thread(_connects, "127.0.0.1", session.vnc_port),
                "sandbox": await asyncio.to_thread(_connects, own_sandbox_ip, session.vnc_port),
            }
            page = session.context.pages[0]
            targets = BLOCKED_URLS + [f"http://{required_env(name)}" for name in BLOCKED_FROM_ENV]
            # El propio VNC y el display de la sesión, vistos desde el navegador que el usuario maneja.
            targets += [f"http://{session.vnc_host}:5900/", "http://127.0.0.1:5900/", "http://worker:5900/", f"http://{own_sandbox_ip}/"]
            for url in targets:
                out["visits"][url] = await _visit(page, url)
            # Desde el JavaScript de una página pública: fetch y WebSocket hacia el canario interno.
            await _go(page, SITE + "/")
            out["fetch"] = await page.evaluate(FETCH_JS, f"http://{own_sandbox_ip}/")
            out["websocket"] = await page.evaluate(WEBSOCKET_JS, f"ws://{own_sandbox_ip}/")
            # Archivos locales del worker: bloqueados por política (y, si cargaran, por la sesión).
            out["file"] = await _visit(page, "file:///etc/passwd")
            out["file_url_after"] = page.url
            # Pestaña nueva: misma captura, misma instrumentación, mismo proxy.
            await _go(page, SITE + "/")
            second = await session.context.new_page()
            await _go(second, FP_PAGE, wait_until="load")
            out["second_tab_blocked"] = await _visit(second, "http://db:5432")
            await _go(second, FP_PAGE, wait_until="load")
            await asyncio.sleep(1.5)
            out["ended"] = session.ended_by_browser()
            outcome = await session.collect("user_stop")
            out["result"], out["capture"] = outcome.result, outcome.capture
        finally:
            await session.destroy()
            await session.destroy()  # idempotente
        out["after"] = {
            "x11vnc": len(_processes("x11vnc -display")), "xvfb": len(_processes(f"Xvfb {settings.interactive_display} ")),
            "chrome": len(_processes(f"scan-{session.proxy_user}")),
            "socket": pathlib.Path(f"/tmp/.X11-unix/X{settings.interactive_display.lstrip(':')}").exists(),
            "vnc_port": _connects(*out["vnc"]),
        }
        return out

    return run_async(scenario())


def test_session_opens_with_display_vnc_and_browser(interactive):
    assert interactive["open_error"] is None
    assert interactive["running"] == {"x11vnc": 1, "xvfb": 1}
    assert interactive["password_file_left"] == []  # x11vnc borra el archivo de la contraseña al leerlo


def test_vnc_listens_only_on_the_internal_network_and_requires_password(interactive):
    host, port = interactive["vnc"]
    assert host.startswith("172.30.2.") and port == 5900
    assert interactive["listening"] == {"internal": True, "loopback": False, "sandbox": False}
    assert interactive["security_types"] == [2]  # solo autenticación VNC: nunca "None"


@pytest.mark.parametrize("index", range(len(BLOCKED_URLS) + len(BLOCKED_FROM_ENV) + 4))
def test_internal_targets_are_blocked_from_the_interactive_browser(interactive, index):
    url, visit = list(interactive["visits"].items())[index]
    assert CANARY_BODY not in visit["body"], f"{url}: se alcanzó el canario interno"
    assert "RFB 003" not in visit["body"], f"{url}: el navegador llegó al VNC"
    assert visit["error"] is not None or visit["proxy_error"] is not None, f"{url}: NO fue bloqueada (status={visit.get('status')})"


def test_page_scripts_cannot_reach_the_internal_network(interactive):
    fetched = interactive["fetch"]
    assert CANARY_BODY not in (fetched.get("body") or "") and (not fetched["ok"] or fetched["status"] == 403)
    assert interactive["websocket"] != "open"


def test_local_files_are_not_reachable(interactive):
    assert "root:" not in interactive["file"]["body"]
    assert interactive["file"]["error"] is not None or not interactive["file_url_after"].startswith("file:")


def test_capture_covers_every_tab_with_the_same_instrumentation(interactive):
    result, capture = interactive["result"], interactive["capture"]
    assert interactive["ended"] is None and result["source"] == "interactive" and result["interactive"]["end_reason"] == "user_stop"
    assert result["interactive"]["tabs"] == 2 and result["final_url"] == FP_PAGE
    timeline = result["interactive"]["timeline"]
    assert timeline[0]["url"] == SITE + "/" and timeline[0]["tab"] == 1
    assert timeline[-1] == {**timeline[-1], "url": FP_PAGE, "tab": 2}
    assert [entry["seq"] for entry in timeline] == list(range(len(timeline)))
    assert not any(entry["url"].startswith("file:") for entry in timeline)
    hosts = {request["host"] for request in capture["requests"]}
    assert {"site.fixtures.test", "tracker-a.fixtures.test", "cdn-b.fixtures.test"} <= hosts
    # Las peticiones bloqueadas quedan en la captura como bloqueadas por el proxy; el canario, nunca.
    assert any(request["blocked_by_proxy"] for request in capture["requests"])
    # Instrumentación de fingerprinting activa también en la segunda pestaña.
    calls = capture["fingerprinting"]["calls"]
    assert any(call["frame_url"] == FP_PAGE for call in calls)
    # Cookies reales de la sesión, tal como quedaron al detener.
    assert capture["cookies"] and capture["end_reason"] == "user_stop" and capture["proxy_user"].startswith("scan-")


def test_everything_is_destroyed_at_the_end(interactive):
    assert interactive["after"] == {"x11vnc": 0, "xvfb": 0, "chrome": 0, "socket": False, "vnc_port": False}
