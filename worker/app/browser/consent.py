"""Escenarios de consentimiento (F7): sin_interaccion | aceptar | rechazar.

Solo se pulsa un botón cuyo selector está en data/cmp_selectors.yaml. Si el banner no
se reconoce, el escenario queda "no_aplicable" con su evidencia: nunca se adivina.
"""

import asyncio
import logging
import pathlib

import yaml
from playwright.async_api import Error as PlaywrightError

from app.config import settings

logger = logging.getLogger(__name__)

SCENARIOS = ("sin_interaccion", "aceptar", "rechazar")
MAX_BANNER_BYTES = 400_000

TCF_JS = """() => new Promise((resolve) => {
  if (typeof window.__tcfapi !== 'function') return resolve(null);
  const timer = setTimeout(() => resolve({error: 'sin respuesta'}), 1500);
  try {
    window.__tcfapi('getTCData', 2, (data, ok) => {
      clearTimeout(timer);
      if (!ok || !data) return resolve({error: 'getTCData falló'});
      const consents = (data.purpose && data.purpose.consents) || {};
      const granted = Object.keys(consents).filter((key) => consents[key] === true).length;
      resolve({event_status: String(data.eventStatus || ''), tc_string_length: typeof data.tcString === 'string' ? data.tcString.length : 0,
               purposes_granted: granted, purposes_total: Object.keys(consents).length, gdpr_applies: data.gdprApplies === true});
    });
  } catch (error) { clearTimeout(timer); resolve({error: String(error).slice(0, 100)}); }
})"""


# ping + getTCData (docs/adr/015). Del tcString solo se registra que existe y su largo.
TCF_INFO_JS = """() => new Promise((resolve) => {
  if (typeof window.__tcfapi !== 'function') return resolve(null);
  const out = {ping: null, tc_data: null, error: null};
  const text = (v) => (typeof v === 'string' ? v.slice(0, 40) : null);
  const number = (v) => (typeof v === 'number' && isFinite(v) ? v : null);
  const bool = (v) => (typeof v === 'boolean' ? v : null);
  const timer = setTimeout(() => { out.error = out.error || 'sin respuesta'; resolve(out); }, 2000);
  let pending = 2;
  const done = () => { if (--pending === 0) { clearTimeout(timer); resolve(out); } };
  try {
    window.__tcfapi('ping', 2, (ping) => {
      if (ping && typeof ping === 'object') {
        out.ping = {gdpr_applies: bool(ping.gdprApplies), cmp_loaded: bool(ping.cmpLoaded), cmp_status: text(ping.cmpStatus),
                    display_status: text(ping.displayStatus), cmp_id: number(ping.cmpId), cmp_version: number(ping.cmpVersion),
                    api_version: text(ping.apiVersion), tcf_policy_version: number(ping.tcfPolicyVersion)};
      }
      done();
    });
    window.__tcfapi('getTCData', 2, (data, ok) => {
      if (ok && data && typeof data === 'object') {
        const consents = (data.purpose && data.purpose.consents) || {};
        out.tc_data = {gdpr_applies: bool(data.gdprApplies), cmp_id: number(data.cmpId), cmp_version: number(data.cmpVersion),
                       event_status: text(data.eventStatus), cmp_status: text(data.cmpStatus),
                       has_tc_string: typeof data.tcString === 'string' && data.tcString.length > 0,
                       tc_string_length: typeof data.tcString === 'string' ? data.tcString.length : 0,
                       purposes_granted: Object.keys(consents).filter((key) => consents[key] === true).length,
                       purposes_total: Object.keys(consents).length};
      }
      done();
    });
  } catch (error) { clearTimeout(timer); out.error = String(error).slice(0, 100); resolve(out); }
})"""


async def tcf_info(page) -> dict:
    """Estado TCF que declara la propia página, sin depender de ningún banner. Nunca lanza."""
    try:
        info = await asyncio.wait_for(page.evaluate(TCF_INFO_JS), 5)
    except (PlaywrightError, asyncio.TimeoutError):
        return {"present": None, "error": "no se pudo consultar"}
    if not isinstance(info, dict):
        return {"present": False}
    return {"present": True, "ping": info.get("ping") if isinstance(info.get("ping"), dict) else None,
            "tc_data": info.get("tc_data") if isinstance(info.get("tc_data"), dict) else None,
            "error": info.get("error") if isinstance(info.get("error"), str) else None}


def load_selectors() -> dict:
    return yaml.safe_load((pathlib.Path(settings.data_dir) / "cmp_selectors.yaml").read_text(encoding="utf-8"))


async def _visible(page, selector: str) -> bool:
    try:
        return await page.locator(selector).first.is_visible(timeout=500)
    except PlaywrightError:
        return False


async def _tcf_state(page) -> dict | None:
    try:
        state = await asyncio.wait_for(page.evaluate(TCF_JS), 4)
    except (PlaywrightError, asyncio.TimeoutError):
        return None
    return state if isinstance(state, dict) else None


async def handle_consent(page, context, scenario: str, monitor, config: dict | None = None) -> tuple[dict, list[dict]]:
    """Detecta el CMP, ejecuta el escenario y verifica el estado. Devuelve (resultado, artefactos)."""
    config = config or load_selectors()
    loop = asyncio.get_running_loop()
    result = {
        "scenario": scenario, "status": "no_aplicable", "cmp": None, "cmp_name": None, "banner_detected": False,
        "tcfapi_present": False, "clicked": None, "interaction_seq": None, "verified": None, "state": None,
        "reason": None, "has_banner_image": False,
    }
    artifacts: list[dict] = []

    found = None
    deadline = loop.time() + config.get("wait_ms", 5000) / 1000
    while found is None and loop.time() < deadline:
        for cmp in config["cmps"]:
            if await _visible(page, cmp["banner"]):
                found = cmp
                break
        else:
            await asyncio.sleep(0.25)
    tcf_before = await _tcf_state(page)
    result["tcfapi_present"] = tcf_before is not None
    if found is None:
        result["reason"] = "No se reconoció ningún banner de consentimiento conocido; no se pulsó nada." + (
            " La página expone __tcfapi, pero sin un banner reconocible no se interactúa." if tcf_before is not None else ""
        )
        result["evidence"] = {"selectors_tried": [cmp["banner"] for cmp in config["cmps"]], "tcf_before": tcf_before}
        return result, artifacts

    result.update(cmp=found["id"], cmp_name=found["name"], banner_detected=True, banner_seq=monitor.count)
    try:
        image = await page.locator(found["banner"]).first.screenshot(type="jpeg", quality=60, timeout=5000)
        if len(image) <= MAX_BANNER_BYTES:
            artifacts.append({"kind": "consent_banner", "mime": "image/jpeg", "data": image})
            result["has_banner_image"] = True
    except PlaywrightError:
        pass

    if scenario == "sin_interaccion":
        result.update(status="sin_interaccion", state={"tcf": tcf_before}, reason="Banner detectado; no se interactuó.")
        return result, artifacts

    selector = found["accept" if scenario == "aceptar" else "reject"]
    if not selector or not await _visible(page, selector):
        result["reason"] = (
            f"{found['name']} no tiene un botón conocido para «{scenario}» en la primera capa del banner; no se pulsó nada."
            if not selector else f"El botón esperado de {found['name']} para «{scenario}» no está visible; no se pulsó nada."
        )
        result["evidence"] = {"selector": selector}
        return result, artifacts

    # Todo lo capturado desde aquí ocurre DESPUÉS de la decisión.
    result["interaction_seq"] = monitor.count
    try:
        await page.locator(selector).first.click(timeout=5000)
    except PlaywrightError as exc:
        result["reason"] = f"No se pudo pulsar el botón de {found['name']}: {type(exc).__name__}."
        result["interaction_seq"] = None
        return result, artifacts
    monitor.last_activity = loop.time()
    await asyncio.sleep(config.get("settle_ms", 1500) / 1000)

    tcf_after = await _tcf_state(page)
    try:
        cookies = sorted({cookie["name"] for cookie in await context.cookies() if cookie["name"] in found.get("cookies", [])})
    except PlaywrightError:
        cookies = []
    banner_gone = not await _visible(page, found["banner"])
    # Verificación: primero el estado TCF; si el sitio no lo expone, la cookie del propio CMP.
    verified, how = None, None
    if tcf_after and "error" not in tcf_after and tcf_after.get("purposes_total"):
        granted = tcf_after["purposes_granted"]
        verified = granted > 0 if scenario == "aceptar" else granted == 0
        how = "tcf"
    elif cookies:
        verified, how = True, "cookie_del_cmp"
    result.update(
        status="aceptado" if scenario == "aceptar" else "rechazado",
        clicked=selector,
        verified=verified,
        state={"tcf": tcf_after, "cmp_cookies": cookies, "banner_closed": banner_gone, "verified_by": how},
        reason=None if verified else "Se pulsó el botón, pero no se pudo confirmar el estado resultante." if verified is None
        else "Se pulsó el botón, pero el estado registrado no coincide con la decisión.",
    )
    return result, artifacts
