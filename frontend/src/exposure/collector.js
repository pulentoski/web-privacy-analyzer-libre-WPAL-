// Colector de "Mi exposición". Todo se lee y se calcula AQUÍ, en el navegador de quien
// visita la página. Nada de este archivo envía datos a ninguna parte.
//
// Cada atributo queda como {status: "DISPONIBLE", value} o
// {status: "NO_DISPONIBLE", reason}. Nunca se solicita un permiso, y la IP local no se
// intenta obtener (no se usa WebRTC).
import { sha256Bytes, sha256Text } from "./sha256.js";

export const DISPONIBLE = "DISPONIBLE";
export const NO_DISPONIBLE = "NO_DISPONIBLE";

const ok = (value) => ({ status: DISPONIBLE, value });
const missing = (reason) => ({ status: NO_DISPONIBLE, reason });
const insecure = "Esta API solo existe en contexto seguro (https o localhost).";

// Lista fija de fuentes a comprobar con document.fonts.check (no se enumera el sistema).
export const FONT_LIST = [
  "Arial", "Arial Black", "Calibri", "Cambria", "Comic Sans MS", "Consolas", "Courier New", "DejaVu Sans",
  "DejaVu Sans Mono", "Georgia", "Helvetica", "Helvetica Neue", "Impact", "Liberation Sans", "Lucida Console",
  "Menlo", "Monaco", "Noto Sans", "Roboto", "Segoe UI", "SF Pro Text", "Tahoma", "Times New Roman",
  "Trebuchet MS", "Ubuntu", "Verdana",
];
const PERMISSIONS = ["geolocation", "notifications", "camera", "microphone", "clipboard-read", "persistent-storage"];

/** Ejecuta un lector; cualquier excepción se convierte en NO_DISPONIBLE con su motivo. */
export function attempt(reader, fallbackReason = "La API no está disponible en este navegador.") {
  try {
    const result = reader();
    if (result === undefined || result === null || result === "") return missing(fallbackReason);
    return ok(result);
  } catch (error) {
    return missing(`Bloqueada o no accesible (${error && error.name ? error.name : "error"}).`);
  }
}

async function attemptAsync(reader, fallbackReason, timeoutMs = 4000) {
  try {
    const result = await Promise.race([
      reader(),
      new Promise((_, reject) => setTimeout(() => reject(Object.assign(new Error("timeout"), { name: "Tiempo agotado" })), timeoutMs)),
    ]);
    if (result === undefined || result === null || result === "") return missing(fallbackReason);
    return ok(result);
  } catch (error) {
    return missing(`Bloqueada o no accesible (${error && error.name ? error.name : "error"}).`);
  }
}

function storageWorks(name, win) {
  const storage = win[name];
  const key = "__wpa_probe__";
  storage.setItem(key, "1");
  storage.removeItem(key);
  return true;
}

function webgl(doc) {
  const canvas = doc.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return null;
  const out = { vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER) };
  const info = gl.getExtension("WEBGL_debug_renderer_info");
  if (info) {
    out.unmasked_vendor = gl.getParameter(info.UNMASKED_VENDOR_WEBGL);
    out.unmasked_renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
  } else {
    out.unmasked = "no permitido por el navegador";
  }
  return out;
}

function canvasHash(doc) {
  const canvas = doc.createElement("canvas");
  canvas.width = 240;
  canvas.height = 60;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.textBaseline = "top";
  ctx.font = "14px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillRect(125, 1, 62, 20);
  ctx.fillStyle = "#069";
  ctx.fillText("Mi exposición, ñ 😃", 2, 15);
  ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
  ctx.fillText("Mi exposición, ñ 😃", 4, 17);
  return sha256Text(canvas.toDataURL());
}

async function audioHash(win) {
  const Offline = win.OfflineAudioContext || win.webkitOfflineAudioContext;
  if (!Offline) return null;
  const context = new Offline(1, 4410, 44100);
  const oscillator = context.createOscillator();
  oscillator.type = "triangle";
  oscillator.frequency.value = 10000;
  const compressor = context.createDynamicsCompressor();
  oscillator.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);
  const buffer = await context.startRendering();
  const samples = buffer.getChannelData(0);
  return sha256Bytes(new Uint8Array(samples.buffer, samples.byteOffset, samples.byteLength));
}

async function permissionStates(nav) {
  const out = {};
  for (const name of PERMISSIONS) {
    try {
      // Solo se CONSULTA el estado. Nunca se llama a una API que muestre un diálogo de permiso.
      out[name] = (await nav.permissions.query({ name })).state;
    } catch {
      out[name] = "no consultable";
    }
  }
  return out;
}

/**
 * Lee todos los atributos. `env` permite inyectar window/navigator/document en los tests.
 * Devuelve {attributes: {id: {status, value|reason}}, secure}.
 */
export async function collect(env = {}) {
  const win = env.window || window;
  const nav = env.navigator || win.navigator;
  const doc = env.document || win.document;
  const scr = win.screen;
  const secure = win.isSecureContext === true;
  const media = (query) => (typeof win.matchMedia === "function" ? win.matchMedia(query).matches : null);
  const a = {};

  // --- Navegador y sistema ---
  a.user_agent = attempt(() => nav.userAgent);
  if (nav.userAgentData) {
    a.ua_client_hints = await attemptAsync(async () => {
      const high = await nav.userAgentData.getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "fullVersionList"]);
      return {
        brands: (nav.userAgentData.brands || []).map((b) => `${b.brand} ${b.version}`).join(", "),
        mobile: nav.userAgentData.mobile, platform: nav.userAgentData.platform,
        architecture: high.architecture, bitness: high.bitness, model: high.model || "(vacío)", platformVersion: high.platformVersion,
        fullVersionList: (high.fullVersionList || []).map((b) => `${b.brand} ${b.version}`).join(", "),
      };
    });
  } else {
    a.ua_client_hints = missing(secure ? "Este navegador no implementa User-Agent Client Hints." : `${insecure} Tampoco todos los navegadores la implementan.`);
  }
  a.platform = attempt(() => nav.platform);
  a.languages = attempt(() => (nav.languages && nav.languages.length ? Array.from(nav.languages).join(", ") : nav.language));
  a.timezone = attempt(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  a.cookies_enabled = attempt(() => String(nav.cookieEnabled));
  a.storage = ok({
    localStorage: attempt(() => storageWorks("localStorage", win)).status === DISPONIBLE,
    sessionStorage: attempt(() => storageWorks("sessionStorage", win)).status === DISPONIBLE,
    indexedDB: attempt(() => Boolean(win.indexedDB)).status === DISPONIBLE && Boolean(win.indexedDB),
  });
  // Sin la API no se dice "ninguno": eso sería inventar un valor.
  a.plugins = attempt(() => (nav.plugins === undefined || nav.plugins === null ? null : {
    plugins: Array.from(nav.plugins).map((p) => p.name).join(", ") || "(lista vacía)",
    mimeTypes: nav.mimeTypes ? nav.mimeTypes.length : "no disponible",
  }), "Este navegador no expone la lista de plugins.");
  a.do_not_track = attempt(() => (nav.doNotTrack === null || nav.doNotTrack === undefined ? "no configurado" : String(nav.doNotTrack)));
  a.global_privacy_control = nav.globalPrivacyControl === undefined
    ? missing("Este navegador no expone Global Privacy Control.")
    : ok(String(nav.globalPrivacyControl));

  // --- Pantalla ---
  a.screen = attempt(() => `${scr.width}x${scr.height} (disponible ${scr.availWidth}x${scr.availHeight})`);
  a.viewport = attempt(() => `${win.innerWidth}x${win.innerHeight}`);
  a.device_pixel_ratio = attempt(() => String(win.devicePixelRatio));
  a.color_depth = attempt(() => String(scr.colorDepth));
  a.touch = attempt(() => (typeof nav.maxTouchPoints !== "number" ? null
    : `${nav.maxTouchPoints} puntos táctiles${"ontouchstart" in win ? ", eventos táctiles" : ""}`), "Este navegador no expone los puntos táctiles.");
  a.color_scheme = attempt(() => (media("(prefers-color-scheme: dark)") ? "oscuro" : "claro"));
  a.reduced_motion = attempt(() => (media("(prefers-reduced-motion: reduce)") ? "reducir" : "sin preferencia"));

  // --- Hardware ---
  a.hardware_concurrency = attempt(() => (nav.hardwareConcurrency ? String(nav.hardwareConcurrency) : null));
  a.device_memory = nav.deviceMemory === undefined
    ? missing(secure ? "Este navegador no expone la memoria del dispositivo." : insecure)
    : ok(`${nav.deviceMemory} GB (aproximado)`);
  a.webgl = attempt(() => webgl(doc), "WebGL no está disponible o está desactivado.");
  if (nav.gpu && typeof nav.gpu.requestAdapter === "function") {
    a.webgpu = await attemptAsync(async () => {
      const adapter = await nav.gpu.requestAdapter();
      if (!adapter) return null;
      const info = adapter.info || {};
      return { vendor: info.vendor || "(vacío)", architecture: info.architecture || "(vacío)", device: info.device || "(vacío)", description: info.description || "(vacío)" };
    }, "El navegador no entregó ningún adaptador WebGPU.");
  } else {
    a.webgpu = missing(secure ? "Este navegador no implementa WebGPU." : insecure);
  }

  // --- Huellas derivadas ---
  a.canvas = attempt(() => canvasHash(doc), "El canvas 2D no está disponible.");
  a.audio = await attemptAsync(() => audioHash(win), "OfflineAudioContext no está disponible.");
  a.fonts = attempt(() => {
    if (!doc.fonts || typeof doc.fonts.check !== "function") return null;
    const found = FONT_LIST.filter((font) => doc.fonts.check(`12px "${font}"`));
    return `${found.length} de ${FONT_LIST.length}: ${found.join(", ") || "(ninguna)"}`;
  }, "document.fonts no está disponible.");

  // --- Permisos (solo estado) ---
  a.permissions = nav.permissions && typeof nav.permissions.query === "function"
    ? await attemptAsync(() => permissionStates(nav))
    : missing(secure ? "Este navegador no implementa la API de permisos." : insecure);

  // --- Criptografía del navegador (depende del contexto seguro) ---
  a.crypto_subtle = win.crypto && win.crypto.subtle
    ? ok("disponible")
    : missing(secure ? "Este navegador no implementa Web Crypto." : insecure);

  return { attributes: a, secure };
}

/** Texto estable de un valor (objetos con claves ordenadas) para poder hashearlo. */
export function canonical(value) {
  if (value === null || typeof value !== "object") return String(value);
  return JSON.stringify(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}

// El viewport cambia al redimensionar la ventana: no forma parte de la huella combinada.
export const VOLATILE = ["viewport"];

/** Hash por atributo y hash combinado. `salt` es la sal del grupo (o "" para uso local). */
export function fingerprint(attributes, salt = "") {
  const hashes = {};
  Object.keys(attributes).sort().forEach((id) => {
    const attribute = attributes[id];
    const text = attribute.status === DISPONIBLE ? canonical(attribute.value) : NO_DISPONIBLE;
    hashes[id] = sha256Text(`${salt}|${id}|${text}`);
  });
  const stable = Object.keys(hashes).filter((id) => !VOLATILE.includes(id));
  const combined = sha256Text(`${salt}|${stable.map((id) => `${id}=${hashes[id]}`).join("&")}`);
  return { hashes, combined };
}

export function displayValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value !== "object") return String(value);
  return Object.keys(value).map((key) => `${key}: ${typeof value[key] === "object" ? JSON.stringify(value[key]) : value[key]}`).join("\n");
}
