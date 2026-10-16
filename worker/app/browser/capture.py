"""Ejecuta un scan: navega, captura el tráfico y devuelve resultado + captura.

Fin de captura (SPEC F2): evento load + ventana sin requests nuevas, o
SCAN_TIMEOUT_S, lo que ocurra primero. Al llegar a MAX_REQUESTS se corta.
"""

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app.analyzer.consistency import check as check_consistency
from app.browser import profiles
from app.browser.consent import SCENARIOS, handle_consent, tcf_info
from app.browser.fp_monitor import PAGE_FLUSH_MS, FingerprintMonitor
from app.browser.proxy_log import read_destinations_when_flushed
from app.browser.launcher import base_session_setup, launch_browser, new_context
from app.browser.network_monitor import PROXY_ERROR_HEADER, NetworkMonitor
from app.config import settings

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
) -> ScanOutcome:
    """`scenario` y `profile_name` son los del Privacy Test (F7); `probe` añade el sondeo de atributos."""
    timeout_s = settings.scan_timeout_s if timeout_s is None else timeout_s
    loop = asyncio.get_running_loop()
    # Cada scan tiene su usuario de proxy: así se sabe qué conexiones del log son suyas.
    proxy_user = proxy_user or f"scan-{uuid.uuid4()}"
    outcome = await _run_scan(url, timeout_s, max_requests, max_body_bytes, idle_s, fp_instrumentation, scenario, profile_name, probe, proxy_user, loop, progress)
    # Con el navegador ya cerrado, el proxy terminó de registrar sus conexiones.
    outcome.capture["proxy_user"] = proxy_user
    outcome.capture["destinations"] = await read_destinations_when_flushed(proxy_user, bool(outcome.capture["requests"]))
    return outcome


async def _run_scan(url, timeout_s, max_requests, max_body_bytes, idle_s, fp_instrumentation, scenario, profile_name, probe, proxy_user, loop, progress=None) -> ScanOutcome:
    async with async_playwright() as playwright:
        browser = await launch_browser(playwright, proxy_user)
        try:
            profile = None
            if profile_name and profile_name != profiles.REAL:
                profile = profiles.resolve(profiles.load_profile(profile_name), browser.version)
            context = await new_context(browser, profile)
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

            started = loop.time()
            deadline = started + timeout_s
            if progress is not None:
                # Desde aquí corre el tiempo máximo y el contador de requests es el del monitor.
                progress.navigating(lambda: monitor.count)
            error, response, end_reason, partial = None, None, "navigation_failed", None
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
                end_reason = await _wait_for_end(
                    page, monitor, deadline, settings.network_idle_s if idle_s is None else idle_s
                )

            consent, artifacts = None, []
            # Scan parcial: el tiempo ya se agotó, no queda margen para el escenario de consentimiento.
            if error is None and partial is None and scenario in SCENARIOS:
                try:
                    consent, artifacts = await handle_consent(page, context, scenario, monitor)
                except Exception:  # el escenario es un añadido: si falla, el scan sigue valiendo
                    logger.exception("consent_scenario_failed")
                    consent = {"scenario": scenario, "status": "no_aplicable", "banner_detected": False,
                               "reason": "El escenario de consentimiento falló por un error interno."}
                if consent.get("interaction_seq") is not None:
                    # Tras la decisión se sigue capturando hasta que la red se calme otra vez.
                    end_reason = await _wait_for_end(
                        page, monitor, deadline, settings.network_idle_s if idle_s is None else idle_s
                    )

            # Estado TCF declarado por la página, al final de la visita (tras la decisión, si la hubo).
            # Scan parcial: sin página confirmada no hay estado TCF que leer, y el margen para volcar la captura es corto.
            tcf = await tcf_info(page) if error is None and partial is None else None

            result = None
            if error is None:
                try:
                    title = await asyncio.wait_for(page.title(), 5)
                except (PlaywrightError, asyncio.TimeoutError):
                    title = ""
                result = {
                    "http_status": response.status if response is not None else monitor.document_status(),
                    "title": clean_text(title, MAX_TITLE_CHARS),
                    # Parcial sin commit: la pestaña sigue en about:blank; la dirección visitada es la pedida.
                    "final_url": clean_text(url if page.url == "about:blank" else page.url, MAX_URL_CHARS),
                }
                if partial is None:
                    result["page_meta"] = await page_meta(page)
                else:
                    result["partial"] = partial
            if fingerprint is not None and error is None:
                # Deja salir el último envío periódico de la instrumentación.
                await asyncio.sleep(PAGE_FLUSH_MS / 1000 + 0.2)
            capture = await monitor.finalize()
            capture["fingerprinting"] = fingerprint.result() if fingerprint is not None else None
            capture["artifacts"] = artifacts
            if result is not None:
                result["tcf"] = tcf
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
            return ScanOutcome(result=result, error=error, capture=capture)
        finally:
            await browser.close()
