// Funciones puras de presentación. Todo lo que reciben puede venir de un sitio
// analizado: nunca se interpreta como HTML ni como URL navegable sin validar.

export const LEVELS = {
  EVIDENCIA: {
    label: "Evidencia",
    description: "Hecho observado directamente en el tráfico o en una llamada registrada. No es una interpretación.",
    className: "bg-emerald-100 text-emerald-900 border-emerald-700",
  },
  INFERENCIA: {
    label: "Inferencia",
    description: "Conclusión razonable a partir de un patrón (un nombre, una lista, una secuencia de llamadas). No se observó directamente.",
    className: "bg-amber-100 text-amber-900 border-amber-700",
  },
  POSIBLE: {
    label: "Posible",
    description: "Indicio débil: la forma de un dato sugiere algo, pero hay otras explicaciones.",
    className: "bg-sky-100 text-sky-900 border-sky-700",
  },
  DESCONOCIDO: {
    label: "Desconocido",
    description: "Se observó algo que no se pudo interpretar. No se afirma qué es.",
    className: "bg-slate-200 text-slate-900 border-slate-600",
  },
};

export function levelInfo(level) {
  return LEVELS[level] || { label: String(level ?? "sin nivel"), description: "Nivel no reconocido.", className: "bg-white text-slate-900 border-slate-500" };
}

export const BANDS = ["Bajo", "Posible", "Moderado", "Alto", "Muy alto"];

const BAND_CLASSES = {
  Bajo: "bg-slate-100 text-slate-800 border-slate-400",
  Posible: "bg-yellow-100 text-yellow-900 border-yellow-600",
  Moderado: "bg-orange-100 text-orange-900 border-orange-600",
  Alto: "bg-red-100 text-red-900 border-red-600",
  "Muy alto": "bg-red-700 text-white border-red-900",
};

export function bandClass(band) {
  return BAND_CLASSES[band] || "bg-white text-slate-700 border-slate-300";
}

export const STATUS_LABELS = { observado: "Observado", inferido: "Inferido", potencial: "Potencial" };

export const ATTRIBUTE_STATUS = {
  OBSERVADO: { label: "Observado en una request", className: "bg-emerald-100 text-emerald-900 border-emerald-700" },
  UTILIZADO: { label: "Utilizado por un script", className: "bg-amber-100 text-amber-900 border-amber-700" },
  DISPONIBLE: { label: "Disponible, sin uso", className: "bg-slate-100 text-slate-800 border-slate-400" },
  NO_DISPONIBLE: { label: "No disponible", className: "bg-white text-slate-600 border-slate-300" },
};

/** Corta un texto largo. Devuelve {text, truncated, hidden}. */
export function truncate(value, limit = 120) {
  const text = value === null || value === undefined ? "" : String(value);
  if (text.length <= limit) return { text, truncated: false, hidden: 0 };
  return { text: text.slice(0, limit), truncated: true, hidden: text.length - limit };
}

/**
 * Devuelve la URL solo si es http(s) y parsea bien; si no, null.
 * Una URL capturada nunca se usa como enlace sin pasar por aquí (javascript:, data:, etc.).
 */
export function safeHttpUrl(value) {
  if (typeof value !== "string" || value.length > 8192) return null;
  // El navegador ignora espacios y caracteres de control al inicio: se rechazan antes de parsear.
  if (!/^https?:\/\//i.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

/** Validación del formulario. Es una ayuda: la que decide es la del servidor. */
export function validateScanUrl(value) {
  const text = (value || "").trim();
  if (!text) return "Escriba una URL.";
  if (text.length > 2048) return "La URL es demasiado larga (máximo 2048 caracteres).";
  if (!/^https?:\/\//i.test(text)) return "La URL debe empezar con http:// o https://.";
  let url;
  try {
    url = new URL(text);
  } catch {
    return "La URL no es válida.";
  }
  if (url.username || url.password) return "No se permiten credenciales en la URL.";
  if (url.port && url.port !== "80" && url.port !== "443") return "Solo se permiten los puertos 80 y 443.";
  if (!url.hostname.includes(".")) return "El host debe ser un dominio público.";
  return null;
}

/**
 * Etapa visible de un scan. La decide la API (progress.stage) con lo que publica el worker:
 * queued → opening → capturing → analyzing → building → done | failed.
 */
export function scanStage(scan) {
  if (!scan) return "desconocido";
  const stage = scan.progress ? scan.progress.stage : scan.stage;
  return typeof stage === "string" && (stageIndex(stage) >= 0 || stage === "failed") ? stage : "desconocido";
}

// Etapas de la barra de progreso (F10), en orden. "failed" no es una etapa: es un final.
export const PROGRESS_STAGES = [
  { id: "queued", label: "En cola", description: "El scan espera a que el worker lo procese." },
  { id: "opening", label: "Abriendo el sitio", description: "El navegador del worker se inicia y solicita la página." },
  { id: "capturing", label: "Capturando", description: "La página carga y se registra cada request." },
  { id: "analyzing", label: "Analizando", description: "Se clasifican las requests y se buscan hallazgos." },
  { id: "building", label: "Generando resultado", description: "El análisis terminó y se está guardando." },
  { id: "done", label: "Finalizado", description: "Resultados disponibles." },
];
export function stageIndex(stage) {
  return PROGRESS_STAGES.findIndex((item) => item.id === stage);
}

export function stageLabel(stage) {
  if (stage === "failed") return "Falló";
  const item = PROGRESS_STAGES[stageIndex(stage)];
  return item ? item.label : "Desconocido";
}

export function isFinished(scan) {
  const stage = scanStage(scan);
  return stage === "done" || stage === "failed";
}

const ERROR_MESSAGES = {
  EGRESS_BLOCKED: "El destino está bloqueado por la política de red: apunta a una dirección interna o no permitida.",
  EGRESS_ERROR: "El proxy de salida no pudo llegar al sitio (por ejemplo, el dominio no existe).",
  NAVIGATION_FAILED: "El navegador no pudo cargar la página.",
  NAVIGATION_TIMEOUT: "La página tardó demasiado en responder.",
  SCAN_TIMEOUT: "El scan superó el tiempo máximo.",
  WORKER_ERROR: "El worker falló mientras procesaba el scan.",
  PERSIST_FAILED: "La captura no se pudo guardar.",
  LEASE_EXPIRED: "El scan se interrumpió varias veces y se abandonó.",
  INVALID_URL: "La URL no es válida.",
  SCHEME_NOT_ALLOWED: "Solo se permiten URLs http y https.",
  PORT_NOT_ALLOWED: "Solo se permiten los puertos 80 y 443.",
  CREDENTIALS_NOT_ALLOWED: "No se permiten credenciales en la URL.",
  IPV6_NOT_SUPPORTED: "No se admiten direcciones IPv6.",
  HOST_FORBIDDEN: "Ese host es interno y no se puede analizar.",
  IP_FORBIDDEN: "Esa dirección está en un rango prohibido (red interna o reservada).",
  DNS_RESOLUTION_FAILED: "No se pudo resolver el dominio.",
  RATE_LIMITED: "Demasiados scans seguidos desde esta dirección. Espere un momento.",
  QUEUE_FULL: "Hay demasiados scans en cola. Intente más tarde.",
  REQUEST_INVALID: "La solicitud no es válida.",
  JOB_NOT_FOUND: "Ese scan no existe.",
  REQUEST_NOT_FOUND: "Esa request no existe en este scan.",
  ANALYSIS_NOT_READY: "El scan todavía no tiene análisis.",
  NO_CAPTURE: "El scan no tiene una captura guardada.",
  NETWORK: "No se pudo contactar a la API.",
  UNKNOWN_PROFILE: "Ese perfil no existe.",
  GROUP_TOO_LARGE: "El test pide demasiados scans. Reduzca escenarios, perfiles o corridas.",
  TEST_NOT_FOUND: "Ese test no existe.",
  CONSENT_REQUIRED: "La comparación requiere su consentimiento explícito.",
  HASHES_ONLY: "Solo se pueden enviar hashes.",
  ROOM_FULL: "El grupo alcanzó el máximo de participantes.",
  PURGE_DISABLED: "La purga remota no está configurada en este servidor.",
  FORBIDDEN: "Token de administrador incorrecto.",
  HISTORY_DELETE_DISABLED: "En modo demo no se puede borrar el historial.",
  CONFIRMATION_REQUIRED: "Para borrar todo hay que escribir la palabra de confirmación.",
  INVALID_IP: "No es una dirección IP válida.",
};

/** Mensaje claro para un error de la API ({error_code, message}). */
export function errorMessage(error) {
  const code = error && error.error_code;
  const known = ERROR_MESSAGES[code];
  if (known) return known;
  // El mensaje del servidor es texto nuestro (no del sitio), pero igual se muestra como texto.
  return (error && typeof error.message === "string" && error.message) || "Ocurrió un error inesperado.";
}

export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("es-CL", { dateStyle: "short", timeStyle: "medium" });
}

export function formatBytes(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

/** null/undefined se muestran como "no disponible": nunca como 0 ni vacío. */
export function orUnavailable(value) {
  return value === null || value === undefined || value === "" ? "no disponible" : value;
}

/** Query string a partir de filtros, omitiendo vacíos. */
export function buildQuery(filters) {
  const params = new URLSearchParams();
  Object.keys(filters || {}).sort().forEach((key) => {
    const value = filters[key];
    if (value === null || value === undefined || value === "") return;
    params.set(key, String(value));
  });
  const text = params.toString();
  return text ? `?${text}` : "";
}

export const REQUEST_FILTER_KEYS = ["band", "category", "mechanism", "third_party", "blocked", "domain", "sort", "page", "page_size"];

/** Deja solo filtros conocidos y con valores válidos (vienen del hash de la URL). */
export function sanitizeRequestFilters(query) {
  const out = {};
  const source = query || {};
  if (BANDS.includes(source.band)) out.band = source.band;
  ["category", "mechanism", "domain"].forEach((key) => {
    if (typeof source[key] === "string" && source[key] && source[key].length <= 255) out[key] = source[key];
  });
  ["third_party", "blocked"].forEach((key) => {
    if (source[key] === "true" || source[key] === "false") out[key] = source[key];
  });
  if (["time", "-time", "score", "-score"].includes(source.sort)) out.sort = source.sort;
  const page = Number.parseInt(source.page, 10);
  if (Number.isInteger(page) && page >= 1 && page <= 100000) out.page = page;
  const size = Number.parseInt(source.page_size, 10);
  if ([25, 50, 100, 200].includes(size)) out.page_size = size;
  return out;
}

export const COMPONENT_LABELS = {
  tracker_domains: "Dominios de terceros con tracking",
  id_sync: "Valores compartidos entre organizaciones",
  url_leak_recipients: "Terceros que recibieron la URL de la página",
  persistent_id_recipients: "Terceros que recibieron un identificador guardado",
  third_party_domains: "Dominios de terceros contactados",
  stored_items: "Cookies e ítems de storage",
  fp_scripts: "Scripts con patrón de fingerprinting",
  fp_exfiltration: "APIs distintas cuyos valores leídos aparecen en requests",
  first_party_telemetry: "Telemetría propia (endpoints de eventos y scripts de analítica propia)",
};

export const CATEGORY_LABELS = {
  "first-party": "Propio del sitio",
  "third-party": "Tercero (genérico)",
  analytics: "Analítica",
  advertising: "Publicidad",
  social: "Redes sociales",
  fingerprinting: "Fingerprinting",
  session: "Sesión",
  telemetry: "Telemetría",
  "cross-site": "Entre sitios",
};

export function categoryLabel(category) {
  return CATEGORY_LABELS[category] || String(category ?? "sin categoría");
}

export const UNKNOWN_ENTITY = "no_disponible";

export function entityLabel(entity) {
  return !entity || entity === UNKNOWN_ENTITY ? "Organización no disponible" : entity;
}

export const SCENARIO_LABELS = {
  sin_interaccion: "Sin interacción",
  aceptar: "Aceptar todo",
  rechazar: "Rechazar todo",
};
export const CONSENT_STATUS = {
  sin_interaccion: "banner detectado, sin interacción",
  aceptado: "se pulsó «aceptar»",
  rechazado: "se pulsó «rechazar»",
  no_aplicable: "no aplicable",
};
export const ATTRIBUTE_CHANGE = {
  CAMBIO: { label: "Cambió", className: "bg-sky-100 text-sky-900 border-sky-700" },
  PERMANECIO: { label: "Permaneció", className: "bg-amber-100 text-amber-900 border-amber-700" },
  NUEVO: { label: "Nuevo", className: "bg-violet-100 text-violet-900 border-violet-700" },
  SIN_REFERENCIA: { label: "Sin referencia", className: "bg-white text-slate-700 border-slate-400" },
};

/** "mediana 414 (409–765)" o "—" si no hay corridas completadas. */
export function formatStats(value) {
  if (!value) return "—";
  return value.min === value.max ? String(value.median) : `${value.median} (${value.min}–${value.max})`;
}

/** Cuántos scans pide un test: escenarios × perfiles × corridas. */
export function testSize(scenarios, profiles, runs) {
  return (scenarios || []).length * (profiles || []).length * (Number(runs) || 0);
}

/** Terceros por organización (v1.2.1): `party` del análisis; sin análisis, el criterio por dominio. */
export function partyLabel(item, { short = false } = {}) {
  if (item.party === "same_org") return short ? "Misma org." : "misma organización (no es tercero)";
  if (item.party === "third_party") return short ? "Tercero" : "tercero";
  if (item.party === "first_party") return short ? "Propio" : "propio del sitio";
  if (item.third_party === null || item.third_party === undefined) return short ? "—" : "origen no determinado";
  return item.third_party ? (short ? "Tercero" : "tercero") : (short ? "Propio" : "propio del sitio");
}

/** Estado de una request en la tabla. Las canceladas por una extensión (HAR importado) se nombran aparte. */
export function requestOutcome(item) {
  if (item.blocked_by_proxy) return "bloqueada";
  if (String(item.failure_text || "").includes("ERR_BLOCKED_BY_CLIENT")) return "bloqueada por una extensión del navegador";
  return item.failure_text ? "falló" : item.response_status ?? "—";
}
