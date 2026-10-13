"""Perfiles de emulación (F7): cargar, aplicar y sondear lo que realmente quedó expuesto.

Un perfil cambia lo que el navegador DICE ser. No cambia la IP, ni el motor (siempre
Chromium), ni la huella de canvas/audio de este equipo. Nada de esto es anonimato.

Orden de aplicación (importa):
  1. opciones del contexto: UA, locale, zona horaria, viewport, pantalla, DPR, táctil;
  2. init script profile_spoof.js (platform, CPU, memoria, WebGL), ANTES de la
     instrumentación de fingerprinting, que así registra los valores ya emulados;
  3. por página, CDP Emulation.setUserAgentOverride con userAgentMetadata: Client Hints
     coherentes en JavaScript y en las cabeceras Sec-CH-UA-*.
"""

import hashlib
import json
import pathlib
import re

import yaml

from app.config import settings

SPOOF_PATH = pathlib.Path(__file__).with_name("profile_spoof.js")
PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PROBE_URL = "https://probe.invalid/"
REAL = "real"


class UnknownProfile(ValueError):
    pass


def load_profile(name: str) -> dict:
    if not isinstance(name, str) or not PROFILE_NAME.match(name):
        raise UnknownProfile(name)
    path = pathlib.Path(settings.data_dir) / "profiles" / f"{name}.yaml"
    if not path.is_file():
        raise UnknownProfile(name)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def consistency_rules() -> dict:
    return yaml.safe_load((pathlib.Path(settings.data_dir) / "consistency_rules.yaml").read_text(encoding="utf-8"))


def resolve(profile: dict, browser_version: str) -> dict:
    """Sustituye {major} por la versión real del motor y arma los Client Hints."""
    major = browser_version.split(".")[0]
    resolved = dict(profile)
    resolved["user_agent"] = profile["user_agent"].replace("{major}", major)
    resolved["metadata"] = {
        "brands": [{"brand": "Chromium", "version": major}, {"brand": "Not_A Brand", "version": "8"}],
        "fullVersionList": [{"brand": "Chromium", "version": browser_version}, {"brand": "Not_A Brand", "version": "8.0.0.0"}],
        "fullVersion": browser_version,
        "platform": profile["ua_platform"],
        "platformVersion": profile["ua_platform_version"],
        "architecture": profile["architecture"],
        "model": profile["model"],
        "mobile": bool(profile["mobile"]),
        "bitness": profile["bitness"],
        "wow64": False,
    }
    return resolved


def context_overrides(profile: dict) -> dict:
    width, height = profile["viewport"]
    screen_width, screen_height = profile["screen"]
    return {
        "user_agent": profile["user_agent"],
        "locale": profile["locale"],
        "timezone_id": profile["timezone"],
        "viewport": {"width": width, "height": height},
        "screen": {"width": screen_width, "height": screen_height},
        "device_scale_factor": profile["device_scale_factor"],
        "is_mobile": bool(profile["mobile"]),
        "has_touch": bool(profile["has_touch"]),
    }


def init_script(profile: dict) -> str:
    values = {key: profile.get(key) for key in ("platform", "hardware_concurrency", "device_memory", "max_touch_points", "webgl_vendor", "webgl_renderer")}
    return SPOOF_PATH.read_text(encoding="utf-8").replace("__WPA_PROFILE__", json.dumps(values))


async def apply_to_page(context, page, profile: dict) -> None:
    session = await context.new_cdp_session(page)
    await session.send(
        "Emulation.setUserAgentOverride",
        {
            "userAgent": profile["user_agent"],
            "acceptLanguage": profile["locale"],
            "platform": profile["platform"],
            "userAgentMetadata": profile["metadata"],
        },
    )
    await session.send("Emulation.setHardwareConcurrencyOverride", {"hardwareConcurrency": profile["hardware_concurrency"]})


# Lo que un script puede leer, más pruebas de artefactos del propio spoofing.
PROBE_JS = """async () => {
  const native = (fn) => { try { return /\\{\\s*\\[native code\\]\\s*\\}$/.test(Function.prototype.toString.call(fn)); } catch (e) { return false; } };
  const getterOf = (proto, name) => { const d = Object.getOwnPropertyDescriptor(proto, name); return d && d.get; };
  const out = {};
  out.user_agent = navigator.userAgent;
  out.platform = navigator.platform;
  out.languages = Array.from(navigator.languages || []);
  out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  out.locale = Intl.DateTimeFormat().resolvedOptions().locale;
  out.screen = [screen.width, screen.height];
  out.viewport = [innerWidth, innerHeight];
  out.device_pixel_ratio = devicePixelRatio;
  out.hardware_concurrency = navigator.hardwareConcurrency;
  out.device_memory = navigator.deviceMemory === undefined ? null : navigator.deviceMemory;
  out.max_touch_points = navigator.maxTouchPoints;
  out.webdriver = navigator.webdriver;
  out.ua_ch = null;
  if (navigator.userAgentData) {
    const high = await navigator.userAgentData.getHighEntropyValues(['platformVersion', 'architecture', 'bitness', 'model', 'fullVersionList']);
    out.ua_ch = {platform: navigator.userAgentData.platform, mobile: navigator.userAgentData.mobile,
      brands: navigator.userAgentData.brands.map((b) => b.brand + ' ' + b.version), platform_version: high.platformVersion,
      architecture: high.architecture, bitness: high.bitness, model: high.model};
  }
  out.webgl_vendor = null; out.webgl_renderer = null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const info = gl.getExtension('WEBGL_debug_renderer_info');
    out.webgl_vendor = gl.getParameter(info.UNMASKED_VENDOR_WEBGL);
    out.webgl_renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
  } catch (e) {}
  out.canvas = null;
  try {
    const canvas = document.createElement('canvas'); canvas.width = 240; canvas.height = 60;
    const ctx = canvas.getContext('2d'); ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125, 1, 62, 20); ctx.fillStyle = '#069'; ctx.fillText('Privacy test, \\u00f1 \\ud83d\\ude03', 2, 15);
    out.canvas = canvas.toDataURL();
  } catch (e) {}
  // Artefactos: funciones que no parecen nativas o propiedades donde no deberían estar.
  const artifacts = [];
  const checks = [['navigator.userAgent', getterOf(Navigator.prototype, 'userAgent')], ['navigator.platform', getterOf(Navigator.prototype, 'platform')],
    ['navigator.hardwareConcurrency', getterOf(Navigator.prototype, 'hardwareConcurrency')], ['navigator.deviceMemory', getterOf(Navigator.prototype, 'deviceMemory')],
    ['navigator.maxTouchPoints', getterOf(Navigator.prototype, 'maxTouchPoints')], ['WebGLRenderingContext.getParameter', WebGLRenderingContext.prototype.getParameter],
    ['Function.prototype.toString', Function.prototype.toString]];
  for (const [name, fn] of checks) if (fn && !native(fn)) artifacts.push(name + ': toString no nativo');
  const own = Object.getOwnPropertyNames(navigator);
  if (own.length) artifacts.push('navigator tiene propiedades propias: ' + own.join(', '));
  if (Function.prototype.toString.name !== 'toString' || Function.prototype.toString.length !== 0) artifacts.push('Function.prototype.toString: nombre o aridad alterados');
  out.artifacts = artifacts;
  return out;
}"""

HEADER_NAMES = ("user-agent", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")


def observed_headers(capture: dict) -> dict:
    """Cabeceras de la navegación principal: lo que vio el servidor del sitio."""
    requests = capture.get("requests") or []
    headers = {h["name"].lower(): h["value"] for h in (requests[0]["request_headers"] if requests else [])}
    return {name: headers.get(name) for name in HEADER_NAMES}


async def run_probe(browser, profile: dict | None) -> dict | None:
    """Abre un contexto limpio con el mismo perfil (sin instrumentación) y lee lo que ve un script.

    La página de sondeo es https pero no sale a la red: la respuesta la da Playwright.
    """
    from app.browser.launcher import new_context

    context = await new_context(browser, profile)
    try:
        if profile is not None:
            await context.add_init_script(script=init_script(profile))
        page = await context.new_page()
        if profile is not None:
            await apply_to_page(context, page, profile)
        await page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body="<!doctype html><title>probe</title>"))
        await page.goto(PROBE_URL, timeout=10000)
        probe = await page.evaluate(PROBE_JS)
    except Exception:  # el sondeo es informativo: nunca tumba el scan
        return None
    finally:
        await context.close()
    canvas = probe.pop("canvas", None)
    probe["canvas_hash"] = hashlib.sha256(canvas.encode()).hexdigest() if isinstance(canvas, str) else None
    return probe
