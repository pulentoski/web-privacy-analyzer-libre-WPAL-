"""Captura interactiva (v1.4, docs/adr/029): el usuario navega en el Chromium del worker.

Mismo navegador que un scan (`launch_kwargs`: todo sale por el egress-proxy, misma
instrumentación de fingerprinting, mismo monitor de red), pero sobre un display propio (Xvfb)
que un servidor VNC (x11vnc) muestra a la interfaz. El VNC escucha solo en la red `internal`
de Docker, con una contraseña de un solo uso; quien lo publica hacia el navegador del usuario
es la api (relé WebSocket con token), nunca un puerto del worker.

Al terminar (botón, inactividad, duración máxima, tope de requests o cierre de la ventana) se
vuelca la captura con el mismo formato que un scan y se destruye todo: contexto, navegador,
x11vnc y Xvfb.
"""

import asyncio
import json
import logging
import os
import pathlib
import socket
from datetime import datetime, timezone

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app import jobs
from app.browser.capture import MAX_TITLE_CHARS, MAX_URL_CHARS, ScanOutcome, _error, clean_text, net_error_code, page_meta, partial_navigation
from app.browser.consent import tcf_info
from app.browser.fp_monitor import PAGE_FLUSH_MS, FingerprintMonitor
from app.browser.launcher import base_session_setup, context_kwargs, launch_kwargs
from app.browser.network_monitor import PROXY_ERROR_HEADER, NetworkMonitor
from app.browser.proxy_log import read_destinations_when_flushed
from app.browser.redact import MAX_NAME_CHARS, redact_body
from app.config import settings

logger = logging.getLogger(__name__)

SOURCE = "interactive"
MAX_TIMELINE = 300
# Esquemas en los que el usuario puede quedar: web y las páginas propias del navegador (pestaña
# nueva, errores). file:// además está bloqueado por política (worker/chromium-policies).
BLOCKED_SCHEMES = ("file:", "view-source:file:")
# Presupuesto para volcar una sesión larga (un scan usa 12 s para 1500 requests).
FINALIZE_BUDGET_S = 40.0
START_NAVIGATION_TIMEOUT_S = 45

MAX_PASSWORD_FIELDS = 200
PASSWORD_WATCH_S = 1.0
PASSWORD_WATCH_FRAMES = 30
# Nombres (nunca valores) de los <input type="password"> presentes en un frame, para enmascarar esos campos
# en los cuerpos capturados aunque no se llamen «password». Se consulta desde el worker: la instrumentación
# de fingerprinting retira del global el canal de bindings de Playwright, así que la página no puede avisar.
PASSWORD_FIELDS_JS = """() => {
  const names = [];
  for (const field of document.querySelectorAll('input[type=password]')) {
    for (const name of [field.name, field.id]) {
      if (typeof name === 'string' && name && name.length <= 128 && names.length < 50) names.push(name);
    }
  }
  return names;
}"""

END_REASONS = ("user_stop", "idle_timeout", "max_duration", "max_requests", "window_closed", "browser_closed")


def internal_address() -> str:
    """IP del worker en la red `internal` (la misma por la que habla con la base de datos)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((settings.postgres_host, 5432))  # UDP: no envía nada, solo elige la interfaz
        return probe.getsockname()[0]


async def _terminate(process) -> None:
    if process is None or process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), 5)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


async def start_xvfb(display: str, width: int, height: int):
    number = display.lstrip(":")
    for stale in (f"/tmp/.X{number}-lock", f"/tmp/.X11-unix/X{number}"):
        pathlib.Path(stale).unlink(missing_ok=True)
    process = await asyncio.create_subprocess_exec(
        "Xvfb", display, "-screen", "0", f"{width}x{height}x24", "-nolisten", "tcp",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    for _ in range(50):
        if pathlib.Path(f"/tmp/.X11-unix/X{number}").exists():
            return process
        if process.returncode is not None:
            break
        await asyncio.sleep(0.1)
    await _terminate(process)
    raise RuntimeError(f"Xvfb no arrancó en {display}")


async def start_vnc(display: str, host: str, port: int, password: str):
    """x11vnc sobre el display de la sesión. La contraseña va en un archivo que x11vnc borra al leerlo."""
    secret = pathlib.Path(f"/tmp/wpa-vnc-{os.getpid()}-{port}")
    secret.touch(mode=0o600)
    secret.write_text(password + "\n", encoding="utf-8")
    process = await asyncio.create_subprocess_exec(
        "x11vnc", "-display", display, "-rfbport", str(port), "-listen", host, "-passwdfile", f"rm:{secret}",
        # Una sola vista a la vez (una conexión nueva reemplaza a la anterior) y sin apagarse al desconectar.
        "-forever", "-nevershared",
        # Sin portapapeles compartido, sin control remoto de x11vnc, sin IPv6, sin DNS inverso, sin ~/.x11vncrc.
        "-nosel", "-noremote", "-noipv6", "-nolookup", "-norc", "-quiet",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        for _ in range(80):
            if process.returncode is not None:
                break
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 1)
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.1)
                continue
            writer.close()
            return process
        raise RuntimeError("x11vnc no arrancó")
    except BaseException:
        await _terminate(process)
        raise
    finally:
        secret.unlink(missing_ok=True)


class InteractiveSession:
    """El navegador de una captura interactiva y todo lo que hay que destruir al terminar."""

    def __init__(self, url: str, *, proxy_user: str, password: str, progress=None) -> None:
        self.url = url
        self.proxy_user = proxy_user
        self.vnc_host = internal_address()
        self.vnc_port = settings.interactive_vnc_port
        self._password = password
        self._progress = progress
        self._loop = asyncio.get_running_loop()
        self._xvfb = self._vnc = self._playwright = self.browser = self.context = None
        self.monitor: NetworkMonitor | None = None
        self.fingerprint: FingerprintMonitor | None = None
        self.timeline: list[dict] = []
        self.timeline_truncated = False
        self._tabs: list = []
        self._active = None
        self._response = None
        # La URL inicial no terminó de abrir a tiempo, pero ya había respuestas (docs/adr/035). None = abrió bien.
        self.partial: dict | None = None
        self._started = self._loop.time()
        self._tasks: set[asyncio.Task] = set()
        self.password_fields: set[str] = set()
        self._watcher: asyncio.Task | None = None

    def _note_password_fields(self, names: object) -> None:
        """Dato de la página (no confiable): solo nombres cortos, con tope. Lo peor que logra es enmascarar de más."""
        for name in names if isinstance(names, list) else []:
            if isinstance(name, str) and 0 < len(name) <= MAX_NAME_CHARS and len(self.password_fields) < MAX_PASSWORD_FIELDS:
                self.password_fields.add(name)

    async def _scan_password_fields(self) -> None:
        frames = []
        for page in list(self.context.pages) if self.context is not None else []:
            if not page.is_closed():
                frames.extend(page.frames)
        for frame in frames[:PASSWORD_WATCH_FRAMES]:
            if not frame.url.startswith(("http://", "https://")):
                continue
            try:
                self._note_password_fields(await asyncio.wait_for(frame.evaluate(PASSWORD_FIELDS_JS), 2))
            except (PlaywrightError, asyncio.TimeoutError):
                continue

    async def _watch_password_fields(self) -> None:
        while True:
            await self._scan_password_fields()
            await asyncio.sleep(PASSWORD_WATCH_S)

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- línea de tiempo ---

    def _on_navigated(self, page, frame) -> None:
        if frame.parent_frame is not None:
            return
        url = frame.url or ""
        if url.lower().startswith(BLOCKED_SCHEMES):
            # Segunda barrera (la primera es la política URLBlocklist): archivos locales del worker, no.
            self._spawn(self._leave(page))
            return
        if not url.startswith(("http://", "https://")):
            return
        self._active = page
        self.monitor.set_primary(page)
        if len(self.timeline) >= MAX_TIMELINE:
            self.timeline_truncated = True
            return
        tab = self._tabs.index(page) + 1 if page in self._tabs else 1
        url = clean_text(url, MAX_URL_CHARS)
        if self.timeline and self.timeline[-1]["url"] == url and self.timeline[-1]["tab"] == tab:
            return
        self.timeline.append({"seq": len(self.timeline), "ts": datetime.now(timezone.utc).isoformat(), "url": url, "title": None, "tab": tab})

    async def _leave(self, page) -> None:
        try:
            await page.goto("about:blank", timeout=5000)
        except PlaywrightError:
            pass

    async def _note_title(self, page) -> None:
        try:
            title = clean_text(await asyncio.wait_for(page.title(), 3), MAX_TITLE_CHARS)
            url = clean_text(page.url, MAX_URL_CHARS)
        except (PlaywrightError, asyncio.TimeoutError):
            return
        for entry in reversed(self.timeline):
            if entry["url"] == url:
                entry["title"] = title
                return

    async def _attach(self, page) -> None:
        if page in self._tabs:
            return
        self._tabs.append(page)
        page.on("framenavigated", lambda frame: self._on_navigated(page, frame))
        page.on("load", lambda _page: self._spawn(self._note_title(page)))
        await self.monitor.attach_page(page)

    # --- ciclo de vida ---

    async def open(self) -> dict | None:
        """Levanta display, VNC y navegador y abre la URL inicial. Devuelve el error, si lo hubo."""
        width, height = settings.interactive_screen
        display = settings.interactive_display
        self._xvfb = await start_xvfb(display, width, height)
        self._vnc = await start_vnc(display, self.vnc_host, self.vnc_port, self._password)
        self._password = ""
        self._playwright = await async_playwright().start()
        kwargs = launch_kwargs(self.proxy_user)
        # Siempre con ventana (es lo que ve el usuario), en el display de la sesión.
        kwargs.update(headless=False, env={**os.environ, "DISPLAY": display}, args=[*kwargs["args"], "--window-position=0,0"])
        self.browser = await self._playwright.chromium.launch(**kwargs)
        self.context = await self.browser.new_context(**context_kwargs())
        if settings.fp_instrumentation:
            self.fingerprint = FingerprintMonitor(self.context)
            await self.fingerprint.install()
        page = await self.context.new_page()
        self._active = page
        self.monitor = NetworkMonitor(
            self.context, page, start_url=self.url, max_requests=settings.interactive_max_requests,
            max_body_bytes=settings.max_body_capture_bytes,
        )
        # Credenciales enmascaradas antes de guardar (v1.4.1): solo queda el nombre del campo y su largo.
        self.monitor.session_setup = base_session_setup()
        self.monitor.body_filter = lambda body, content_type: redact_body(body, content_type, self.password_fields)
        await self._attach(page)
        # Pestañas nuevas (enlaces con target, Ctrl+T): mismo contexto, misma captura.
        self.context.on("page", lambda new_page: self._spawn(self._attach(new_page)))
        self._started = self._loop.time()
        if self._progress is not None:
            self._progress.navigating(lambda: self.monitor.count)
        try:
            self._response = await page.goto(self.url, timeout=START_NAVIGATION_TIMEOUT_S * 1000, wait_until="commit")
        except PlaywrightTimeoutError:
            if not self.monitor.responses:
                return _error("NAVIGATION_TIMEOUT", "La navegación superó el tiempo límite.",
                              net_error_code(self.monitor.navigation_failure()))
            # Ya hay respuestas: la sesión sigue y el usuario puede seguir navegando (captura parcial al inicio).
            self.partial = partial_navigation(self.monitor, START_NAVIGATION_TIMEOUT_S)
        except PlaywrightError as exc:
            message = exc.message.splitlines()[0] if exc.message else ""
            return _error("NAVIGATION_FAILED", clean_text(message, 300), net_error_code(message, self.monitor.navigation_failure()))
        if self._response is None and self.partial is None:
            return _error("NAVIGATION_FAILED", "La navegación no produjo respuesta.", net_error_code(self.monitor.navigation_failure()))
        proxy_error = self._response.headers.get(PROXY_ERROR_HEADER) if self._response is not None else None
        if proxy_error:
            code = "EGRESS_BLOCKED" if self._response.status == 403 else "EGRESS_ERROR"
            return _error(code, f"El egress-proxy no entregó el destino ({clean_text(proxy_error, 64)}).")
        if self._progress is not None:
            self._progress.capturing()
        self._watcher = asyncio.ensure_future(self._watch_password_fields())
        return None

    def ended_by_browser(self) -> str | None:
        """Motivos de fin que dependen del navegador (los de tiempo los decide quien vigila la sesión)."""
        if self.browser is None or not self.browser.is_connected():
            return "browser_closed"
        if self.monitor is not None and self.monitor.truncated:
            return "max_requests"
        if not [page for page in self.context.pages if not page.is_closed()]:
            return "window_closed"
        return None

    def _reference_page(self):
        pages = [page for page in (self.context.pages if self.context else []) if not page.is_closed()]
        if self._active in pages:
            return self._active
        return pages[-1] if pages else self._active

    async def collect(self, end_reason: str, error: dict | None = None) -> ScanOutcome:
        """Vuelca la captura con el mismo formato que `run_scan`. El navegador sigue abierto."""
        page = self._reference_page()
        self.monitor.set_primary(page)
        result = None
        if error is None:
            title, tcf = "", None
            try:
                title = await asyncio.wait_for(page.title(), 5)
                tcf = await tcf_info(page)
            except (PlaywrightError, asyncio.TimeoutError):
                pass
            meta = await page_meta(page)
            if self.fingerprint is not None:
                await asyncio.sleep(PAGE_FLUSH_MS / 1000 + 0.2)  # último envío periódico de la instrumentación
            result = {
                "http_status": self._response.status if self._response is not None else self.monitor.document_status(),
                "title": clean_text(title, MAX_TITLE_CHARS),
                "final_url": clean_text(page.url, MAX_URL_CHARS),
                "tcf": tcf,
                "page_meta": meta,
                "source": SOURCE,
                "interactive": {
                    "timeline": self.timeline,
                    "timeline_truncated": self.timeline_truncated,
                    "tabs": len(self._tabs),
                    "end_reason": end_reason,
                    "idle_limit_s": settings.interactive_idle_s,
                    "max_duration_s": settings.interactive_max_s,
                },
            }
            if self.partial is not None:
                result["partial"] = self.partial
        if self._watcher is not None:
            self._watcher.cancel()
            await asyncio.gather(self._watcher, return_exceptions=True)
            self._watcher = None
        if self._tasks:
            await asyncio.wait(set(self._tasks), timeout=3)
        await self._scan_password_fields()
        capture = await self.monitor.finalize(FINALIZE_BUDGET_S)
        if result is not None:
            # Qué se enmascaró: nombre del campo, largo del valor y request. Nunca el valor.
            result["interactive"]["masked_fields"] = sorted(self.monitor.masked_fields, key=lambda item: item["seq"])
        capture["fingerprinting"] = self.fingerprint.result() if self.fingerprint is not None else None
        capture["artifacts"] = []
        capture["end_reason"] = end_reason if error is None else "navigation_failed"
        capture["duration_ms"] = round((self._loop.time() - self._started) * 1000)
        capture["proxy_user"] = self.proxy_user
        return ScanOutcome(result=result, error=error, capture=capture)

    async def destroy(self) -> None:
        """Destruye contexto y navegador y libera VNC y display. Seguro de llamar más de una vez."""
        if self._watcher is not None:
            self._watcher.cancel()
            self._watcher = None
        for task in list(self._tasks):
            task.cancel()
        for closer in (
            (lambda: self.context.close()) if self.context is not None else None,
            (lambda: self.browser.close()) if self.browser is not None else None,
            (lambda: self._playwright.stop()) if self._playwright is not None else None,
        ):
            if closer is None:
                continue
            try:
                await asyncio.wait_for(closer(), 10)
            except Exception as exc:  # hay que seguir liberando lo demás
                logger.warning("interactive_close_failed", extra={"error_type": type(exc).__name__})
        self.context = self.browser = self._playwright = None
        await _terminate(self._vnc)
        await _terminate(self._xvfb)
        self._vnc = self._xvfb = None
        number = settings.interactive_display.lstrip(":")
        for stale in (f"/tmp/.X{number}-lock", f"/tmp/.X11-unix/X{number}"):
            pathlib.Path(stale).unlink(missing_ok=True)


# --- sesión contra la base de datos (la crea la api; ver api/app/routes/interactive.py) ---

READY_SQL = """
UPDATE interactive_sessions
   SET state = 'ready', ready_at = now(), last_input_at = now(), vnc_host = $2, vnc_port = $3, idle_s = $4, max_s = $5
 WHERE job_id = $1 AND ended_at IS NULL
"""
WATCH_SQL = """
SELECT stop_requested,
       extract(epoch FROM now() - coalesce(last_input_at, ready_at, created_at)) AS idle_s,
       extract(epoch FROM now() - coalesce(ready_at, created_at)) AS age_s
  FROM interactive_sessions WHERE job_id = $1
"""
END_SQL = """
UPDATE interactive_sessions
   SET state = 'ended', ended_at = now(), end_reason = $2, vnc_password = NULL, vnc_host = NULL, vnc_port = NULL
 WHERE job_id = $1 AND ended_at IS NULL
"""
POLL_S = 1.0
LEASE_EVERY = 10


async def load_interactions(pool, job_id) -> list[dict] | None:
    """[{ts, kind}] que registró el relé. None si no se pudo leer (no es lo mismo que «sin interacciones»)."""
    try:
        raw = await pool.fetchval("SELECT interactions FROM interactive_sessions WHERE job_id = $1", job_id)
    except Exception as exc:
        logger.warning("interactive_interactions_unavailable", extra={"error_type": type(exc).__name__})
        return None
    raw = json.loads(raw) if isinstance(raw, str) else raw
    out = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, list) and len(item) == 2 and isinstance(item[0], (int, float)) and item[1] in ("click", "scroll", "key"):
            out.append({"ts": item[0] / 1000, "kind": item[1]})
    return out[:3000]


async def end_session(pool, job_id, reason: str) -> None:
    await pool.execute(END_SQL, job_id, reason[:32])


async def run(pool, job, worker_id: str, progress=None) -> ScanOutcome:
    """Atiende una captura interactiva de principio a fin. Siempre destruye la sesión al salir."""
    password = await pool.fetchval("SELECT vnc_password FROM interactive_sessions WHERE job_id = $1 AND ended_at IS NULL", job["id"])
    if not isinstance(password, str) or not 6 <= len(password) <= 8:
        await end_session(pool, job["id"], "invalid")
        return ScanOutcome(result=None, error={"error_code": "INTERACTIVE_INVALID", "message": "La sesión interactiva no existe o ya terminó.", "stage": "interactive"}, capture=None)
    session = InteractiveSession(job["url"], proxy_user=f"scan-{job['id']}", password=password, progress=progress)
    reason = "error"
    try:
        error = await session.open()
        if error is not None:
            reason = "navigation_failed"
            outcome = await session.collect(reason, error)
        else:
            await pool.execute(READY_SQL, job["id"], session.vnc_host, session.vnc_port, settings.interactive_idle_s, settings.interactive_max_s)
            tick = 0
            while True:
                await asyncio.sleep(POLL_S)
                tick += 1
                reason = session.ended_by_browser()
                if reason:
                    break
                try:
                    row = await pool.fetchrow(WATCH_SQL, job["id"])
                    if tick % LEASE_EVERY == 0:
                        await jobs.renew_lease(pool, job, worker_id, settings.lease_s)
                except Exception as exc:  # una consulta fallida no tumba la sesión; los límites siguen por reloj local
                    logger.warning("interactive_watch_failed", extra={"error_type": type(exc).__name__})
                    row = False
                if row is False:
                    reason = "max_duration" if tick * POLL_S >= settings.interactive_max_s else None
                elif row is None:
                    reason = "user_stop"  # la sesión se borró (p. ej. con el historial): no queda nada que esperar
                elif row["stop_requested"]:
                    reason = "user_stop"
                elif row["age_s"] >= settings.interactive_max_s:
                    reason = "max_duration"
                elif row["idle_s"] >= settings.interactive_idle_s:
                    reason = "idle_timeout"
                if reason:
                    break
            outcome = await session.collect(reason)
            if outcome.result is not None:
                # Hora y tipo de cada clic, desplazamiento y tecla (los anota el relé de la api; nunca qué se tecleó).
                outcome.result["interactive"]["interactions"] = await load_interactions(pool, job["id"])
    finally:
        await asyncio.shield(session.destroy())
        try:
            await asyncio.shield(end_session(pool, job["id"], reason))
        except Exception as exc:
            logger.error("interactive_end_failed", extra={"error_type": type(exc).__name__})
    # Con el navegador ya cerrado, el proxy terminó de registrar sus conexiones.
    outcome.capture["destinations"] = await read_destinations_when_flushed(session.proxy_user, bool(outcome.capture["requests"]))
    logger.info("interactive_finished", extra={"job_id": str(job["id"]), "end_reason": reason, "pages": len(session.timeline)})
    return outcome
