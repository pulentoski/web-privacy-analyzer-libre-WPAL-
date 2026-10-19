"""Ejecuta un scan: navega, captura el tráfico y devuelve resultado + captura.

Protocolo de visita fijo (v1.5.0, docs/adr/038, data/visit_protocol.yaml): carga → espera → scroll → espera →
cierre de la pestaña. La carga termina con el evento load + una ventana sin requests nuevas (SPEC F2). Todo el
scan corta en SCAN_TIMEOUT_S y al llegar a MAX_REQUESTS; las etapas que no llegan a completarse constan así.
"""

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app.analyzer.consistency import check as check_consistency
from app.browser import profiles
from app.browser.consent import SCENARIOS, handle_consent, tcf_info
from app.browser.fp_monitor import PAGE_FLUSH_MS, FingerprintMonitor
from app.browser.proxy_log import read_destinations_when_flushed
from app.browser.launcher import base_session_setup, launch_browser, launch_persistent_context, new_context
from app.browser.network_monitor import PROXY_ERROR_HEADER, NetworkMonitor
from app.browser.visit import StageLog, close_stage, interrupted, load_protocol, scroll_stage, wait_stage
from app.config import settings
from app.egress import lookup_country_async

logger = logging.getLogger(__name__)

MAX_TITLE_CHARS = 512
MAX_URL_CHARS = 2048
POLL_S = 0.1


@dataclass
class ScanOutcome:
    result: dict | None
    error: dict | None
    capture: dict


def clean_text(value: object, limit: int) -> str:
    """Los datos del sitio no son confiables: forzar tipo, quitar control chars y acotar."""
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if ch.isprintable())[:limit]


NET_ERROR_RE = re.compile(r"net::ERR_[A-Z0-9_]+")
MAX_META_CHARS = 1000
# Meta description y keywords de la página (v1.4.8): un «término de búsqueda» igual a ellos no es una búsqueda.
# v1.4.9: también el meta delegate-ch (delegación de Client Hints). La clave presente = el meta se leyó.
PAGE_META_JS = """() => {
  const read = (name) => { const el = document.querySelector(`meta[name="${name}" i]`); return el ? el.getAttribute("content") : null; };
  // v1.4.9: delegación de Client Hints a terceros (<meta http-equiv="delegate-ch">).
  const delegate = document.querySelector('meta[http-equiv="delegate-ch" i]');
  return {description: read("description"), keywords: read("keywords"), delegate_ch: delegate ? delegate.getAttribute("content") : null};
}"""


async def page_title(page) -> str | None:
    """Título del documento (`document.title`), o None si no se pudo leer (v1.5.1).

    No se usa page.title(): mientras el documento carga, Chromium devuelve ahí el título provisional de la pestaña
    («Loading <URL>»), que no es un dato del sitio. `document.title` es el del documento, también en un scan parcial con
    la carga sin terminar. Como todo dato del sitio, se sanea (clean_text).
    """
    try:
        return clean_text(await asyncio.wait_for(page.evaluate("() => document.title"), 5), MAX_TITLE_CHARS)
    except (PlaywrightError, asyncio.TimeoutError):
        return None


async def page_meta(page) -> dict:
    """Meta description y keywords de la página, como texto acotado. None si falta o no se pudo leer. Nunca lanza."""
    try:
        raw = await asyncio.wait_for(page.evaluate(PAGE_META_JS), 3)
    except (PlaywrightError, asyncio.TimeoutError):
        raw = None
    if not isinstance(raw, dict):
        # Sin lectura: sin la clave delegate_ch, la delegación queda «no determinada» (no «sin delegación»).
        return {"description": None, "keywords": None}
    return {key: (clean_text(raw.get(key), MAX_META_CHARS) or None) if isinstance(raw.get(key), str) else None
            for key in ("description", "keywords", "delegate_ch")}


def net_error_code(*texts: object) -> str | None:
    """Primer código net::ERR_* que aparezca en los textos de error del navegador. None = no hubo."""
    for value in texts:
        match = NET_ERROR_RE.search(value) if isinstance(value, str) else None
        if match:
            return match.group(0)
    return None


def _error(code: str, message: str, net_error: str | None = None) -> dict:
    # net_error: código real de Chromium (net::ERR_*); None si el navegador no informó ninguno (p. ej. timeout).
    return {"error_code": code, "message": message, "stage": "navigation", "net_error": net_error}


def partial_navigation(monitor: NetworkMonitor, timeout_s: float) -> dict:
    """goto agotó el tiempo, pero ya había respuestas: se analiza lo capturado como scan parcial (docs/adr/035)."""
    return {
        "reason": "navigation_timeout",
        "net_error": net_error_code(monitor.navigation_failure()),
        "requests": monitor.count,
        "responses": monitor.responses,
        "message": (f"La navegación no terminó en {round(timeout_s)} s; se analiza lo capturado hasta ese momento "
                    f"({monitor.count} requests, {monitor.responses} con respuesta)."),
    }


async def _wait_for_end(page, monitor: NetworkMonitor, deadline: float, idle_s: float) -> str:
    loop = asyncio.get_running_loop()
    load = asyncio.ensure_future(page.wait_for_load_state("load", timeout=0))
    try:
        while True:
            now = loop.time()
            if monitor.truncated:
                return "max_requests"
            if now >= deadline:
                return "timeout"
            if load.done():
                if load.exception() is not None:
                    return "page_closed"
                if now - monitor.last_activity >= idle_s:
                    return "network_idle"
            await asyncio.sleep(POLL_S)
    finally:
        if not load.done():
            load.cancel()
        await asyncio.gather(load, return_exceptions=True)


async def run_scan(
    url: str,
    *,
    timeout_s: float | None = None,
    max_requests: int | None = None,
    max_body_bytes: int | None = None,
    idle_s: float | None = None,
    fp_instrumentation: bool | None = None,
    scenario: str | None = None,
    profile_name: str | None = None,
    probe: bool = False,
    proxy_user: str | None = None,
    progress=None,
    profile_session=None,
) -> ScanOutcome:
    """`scenario` y `profile_name` son los del Privacy Test (F7); `probe` añade el sondeo de atributos.

    `profile_session` (solo las visitas de una comparación, v1.5.2, app/comparison.py): navegador con contexto persistente
    en su directorio de perfil y verificación del estado antes de navegar y antes de cerrar. Sin él, como siempre:
    contexto efímero.
    """
    timeout_s = settings.scan_timeout_s if timeout_s is None else timeout_s
    loop = asyncio.get_running_loop()
    # Cada scan tiene su usuario de proxy: así se sabe qué conexiones del log son suyas.
    proxy_user = proxy_user or f"scan-{uuid.uuid4()}"
    # País de la IP de salida (v1.5.0): una consulta por scan, fuera del navegador y con otro usuario de proxy.
    egress = asyncio.ensure_future(lookup_country_async())
    try:
        outcome = await _run_scan(url, timeout_s, max_requests, max_body_bytes, idle_s, fp_instrumentation, scenario, profile_name, probe, proxy_user, loop, progress, profile_session)
    except BaseException:
        egress.cancel()
        raise
    # Con el navegador ya cerrado, el proxy terminó de registrar sus conexiones.
    outcome.capture["proxy_user"] = proxy_user
    outcome.capture["destinations"] = await read_destinations_when_flushed(proxy_user, bool(outcome.capture["requests"]))
    if outcome.result is not None:
        outcome.result["measurement"]["egress_country"] = await egress
    else:
        egress.cancel()
    return outcome


def measurement(browser_version: str | None, started_at: str, visit_protocol: dict, *, headless: bool | None = None) -> dict:
    """Condiciones de la medición (v1.5.0). El país de la IP de salida se añade al final, cuando llega la consulta."""
    headless = settings.headless if headless is None else headless
    return {
        "browser": {"name": "Chromium", "version": clean_text(browser_version, 64) or None},
        "browser_mode": "headless" if headless else "headful",
        "started_at": started_at,
        "visit_protocol": visit_protocol,
    }


LOAD_REASONS = {"network_idle": "network_idle", "timeout": "scan_timeout", "max_requests": "max_requests", "page_closed": "page_closed"}


async def _run_scan(url, timeout_s, max_requests, max_body_bytes, idle_s, fp_instrumentation, scenario, profile_name, probe, proxy_user, loop, progress=None, profile_session=None) -> ScanOutcome:
    protocol = load_protocol()
    idle_s = settings.network_idle_s if idle_s is None else idle_s
    if profile_session is not None and (scenario or probe or (profile_name and profile_name != profiles.REAL)):
        # La comparación de visitas usa el perfil base, sin escenario ni sondeo: lo único que cambia es el perfil en disco.
        raise ValueError("la comparación de visitas no admite escenario, perfil emulado ni sondeo")
    async with async_playwright() as playwright:
        if profile_session is None:
            browser = await launch_browser(playwright, proxy_user)
            closer = browser
        else:
            profile_session.launching()
            persistent = await launch_persistent_context(playwright, profile_session.user_data_dir, proxy_user)
            browser, closer = persistent.browser, persistent
        try:
            profile = None
            if profile_name and profile_name != profiles.REAL:
                profile = profiles.resolve(profiles.load_profile(profile_name), browser.version)
            # El contexto persistente ya trae una pestaña about:blank; se deja abierta (sin tráfico) para que cerrar la
            # pestaña del scan no cierre el navegador antes de volcar la captura.
            context = await new_context(browser, profile) if profile_session is None else persistent
            if profile is not None:
                # Antes que la instrumentación: así esta registra los valores ya emulados.
                await context.add_init_script(script=profiles.init_script(profile))
            fingerprint = None
            if settings.fp_instrumentation if fp_instrumentation is None else fp_instrumentation:
                fingerprint = FingerprintMonitor(context)
                await fingerprint.install()  # antes de crear la página
            page = await context.new_page()
            if profile is not None:
                await profiles.apply_to_page(context, page, profile)
            monitor = NetworkMonitor(
                context,
                page,
                start_url=url,
                max_requests=settings.max_requests if max_requests is None else max_requests,
                max_body_bytes=settings.max_body_capture_bytes if max_body_bytes is None else max_body_bytes,
            )
            if profile is None:
                monitor.session_setup = base_session_setup()
            await monitor.start()
            if profile_session is not None:
                # Estado con que abrió el perfil (cookies cargadas del disco), antes de la primera request del sitio.
                await profile_session.before_navigation(context)

            started = loop.time()
            started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            deadline = started + timeout_s
            stages = StageLog(protocol, lambda: monitor.count)
            if progress is not None:
                # Desde aquí corre el tiempo máximo y el contador de requests es el del monitor.
                progress.navigating(lambda: monitor.count)
            error, response, end_reason, partial = None, None, "navigation_failed", None
            load = stages.start()
            try:
                # "commit": el resto de la carga la vigila _wait_for_end, para poder cortar
                # por timeout o por MAX_REQUESTS sin perder lo ya capturado.
                response = await page.goto(url, timeout=timeout_s * 1000, wait_until="commit")
            except PlaywrightTimeoutError:
                if monitor.responses:
                    partial, end_reason = partial_navigation(monitor, timeout_s), "navigation_timeout_partial"
                else:
                    error = _error("NAVIGATION_TIMEOUT", "La navegación superó el tiempo límite.",
                                   net_error_code(monitor.navigation_failure()))
            except PlaywrightError as exc:
                message = exc.message.splitlines()[0] if exc.message else ""
                error = _error("NAVIGATION_FAILED", clean_text(message, 300), net_error_code(message, monitor.navigation_failure()))

            if error is None and response is None and partial is None:
                error = _error("NAVIGATION_FAILED", "La navegación no produjo respuesta.", net_error_code(monitor.navigation_failure()))
            if error is None and response is not None:
                proxy_error = response.headers.get(PROXY_ERROR_HEADER)
                if proxy_error:
                    code = "EGRESS_BLOCKED" if response.status == 403 else "EGRESS_ERROR"
                    error = _error(code, f"El egress-proxy no entregó el destino ({clean_text(proxy_error, 64)}).")
            if error is None and partial is None:
                if progress is not None:
                    progress.capturing()
                end_reason = await _wait_for_end(page, monitor, deadline, idle_s)
            stage_reason = "navigation_failed" if error is not None else LOAD_REASONS.get(end_reason, end_reason)
            stages.end(load, stage_reason == "network_idle", stage_reason)

            consent, artifacts = None, []
            if load["completed"]:
                # Etapa 2: espera sin interacción.
                wait = stages.start()
                cut = await wait_stage(page, monitor, deadline, protocol.wait_s[0])
                # Privacy Test: el escenario de consentimiento va al final de la primera espera, antes del scroll; sus
                # requests cuentan en esta etapa. Si la espera se cortó (tiempo agotado), no hay margen para él.
                if cut is None and scenario in SCENARIOS:
                    try:
                        consent, artifacts = await handle_consent(page, context, scenario, monitor)
                    except Exception:  # el escenario es un añadido: si falla, el scan sigue valiendo
                        logger.exception("consent_scenario_failed")
                        consent = {"scenario": scenario, "status": "no_aplicable", "banner_detected": False,
                                   "reason": "El escenario de consentimiento falló por un error interno."}
                    if consent.get("interaction_seq") is not None:
                        # Tras la decisión se sigue capturando hasta que la red se calme otra vez.
                        end_reason = await _wait_for_end(page, monitor, deadline, idle_s)
                    cut = interrupted(page, monitor, deadline)
                stages.end(wait, cut is None, cut or "duration_elapsed",
                           **({"includes": ["consent_scenario"]} if consent is not None else {}))
            if stages.current["completed"]:
                # Etapa 3: scroll hasta el final del documento.
                step = stages.start()
                cut, reached_end = await scroll_stage(page, monitor, deadline, protocol.scroll_max_s, protocol.scroll_step_ms)
                stages.end(step, cut is None, cut or ("document_end" if reached_end else "max_time"), reached_end=reached_end)
            last_wait, wait_cut = None, None
            if stages.current["completed"]:
                # Etapa 4: segunda espera. Termina después del volcado previo al cierre (ver abajo).
                last_wait = stages.start()
                wait_cut = await wait_stage(page, monitor, deadline, protocol.wait_s[1])

            # Estado de la página al final de la visita, antes del cierre (tras la decisión, si la hubo).
            open_page = error is None and not page.is_closed()
            # Scan parcial: sin página confirmada no hay estado TCF que leer, y el margen para volcar la captura es corto.
            tcf = await tcf_info(page) if open_page and partial is None else None
            result = None
            if error is None:
                title = await page_title(page) if open_page else None
                result = {
                    "http_status": response.status if response is not None else monitor.document_status(),
                    "title": title or "",
                    # Parcial sin commit: la pestaña sigue en about:blank; la dirección visitada es la pedida.
                    "final_url": clean_text(url if page.url == "about:blank" else page.url, MAX_URL_CHARS),
                }
                if partial is None:
                    result["page_meta"] = await page_meta(page)
                else:
                    result["partial"] = partial
            if fingerprint is not None and open_page:
                # Deja salir el último envío periódico de la instrumentación.
                await asyncio.sleep(PAGE_FLUSH_MS / 1000 + 0.2)

            if last_wait is not None:
                if wait_cut is None:
                    # Lo que depende de la pestaña (cabeceras, storage) se vuelca antes de cerrarla; con la pestaña
                    # cerrada Chromium ya no lo entrega. Las requests de este tramo cuentan en la segunda espera.
                    await monitor.prepare_close()
                stages.end(last_wait, wait_cut is None, wait_cut or "duration_elapsed",
                           **({"includes": ["pre_close_dump"]} if wait_cut is None else {}))
            if last_wait is not None and last_wait["completed"] and loop.time() < deadline:
                # Etapa 5: cierre de la pestaña con la captura activa.
                closing = stages.start()
                closed = await close_stage(page, protocol.close_observe_s)
                stages.end(closing, closed, "tab_closed" if closed else "tab_not_closed")
            else:
                # El volcado previo al cierre pudo terminar ya pasado SCAN_TIMEOUT_S: el cierre no empieza.
                stages.skip_rest("scan_timeout" if last_wait is not None and last_wait["completed"] else "previous_stage_incomplete")

            capture = await monitor.finalize()
            capture["fingerprinting"] = fingerprint.result() if fingerprint is not None else None
            capture["artifacts"] = artifacts
            if result is not None:
                result["tcf"] = tcf
                result["measurement"] = measurement(browser.version, started_at, stages.result())
            if result is not None and consent is not None:
                result["consent"] = consent
            if result is not None and probe:
                headers = profiles.observed_headers(capture)
                js = await profiles.run_probe(browser, profile)
                result["profile"] = {
                    "name": profile_name or profiles.REAL,
                    "label": profile["label"] if profile else "Navegador real del worker",
                    "declared_coherent": profile["coherent"] if profile else True,
                    "js": js,
                    "headers": headers,
                    # None = no se pudo sondear; no es lo mismo que "sin inconsistencias".
                    "inconsistencies": check_consistency(js, headers, profiles.consistency_rules()) if js else None,
                }
            capture["end_reason"] = end_reason
            capture["duration_ms"] = round((loop.time() - started) * 1000)
            if profile_session is not None:
                await profile_session.before_close(context)
            return ScanOutcome(result=result, error=error, capture=capture)
        finally:
            # Contexto persistente: cerrarlo cierra el navegador y Chromium vuelca su estado al directorio del perfil.
            await closer.close()
            if profile_session is not None:
                profile_session.closed()
