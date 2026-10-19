// Cliente de la API. Los errores se normalizan a {error_code, message, status}.

async function request(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw { error_code: "NETWORK", message: "No se pudo contactar a la API.", status: 0 };
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw {
      error_code: (body && body.error_code) || `HTTP_${response.status}`,
      message: (body && body.message) || "",
      details: (body && body.details) || {},
      status: response.status,
    };
  }
  return body;
}

const id = (value) => encodeURIComponent(String(value));
/** "&clave=valor" por cada filtro con valor; las claves son fijas del código. */
const params = (filters) => Object.keys(filters || {}).sort()
  .filter((key) => filters[key] !== null && filters[key] !== undefined && filters[key] !== "")
  .map((key) => `&${key}=${id(filters[key])}`).join("");
const exportBase = (subject, subjectId) =>
  subject === "group" ? `/api/privacy/test/${id(subjectId)}/export` : `/api/scans/${id(subjectId)}/export`;

export const api = {
  health: () => request("/health"),
  // filters: {site, status, date_from, date_to, grouped} (Historial).
  listScans: (limit = 20, filters) => request(`/api/scans?limit=${limit}${params(filters)}`),
  // cleanUrl=false mantiene los parámetros de seguimiento de la URL (por defecto se limpian).
  createScan: (url, cleanUrl = true) =>
    request("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, clean_url: Boolean(cleanUrl) }) }),
  // POST: la URL viaja en el cuerpo, no en la query (no queda en el log de accesos).
  inspectUrl: (url) =>
    request("/api/scans/inspect-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) }),
  // HAR (v1.3). El archivo viaja como cuerpo crudo; la api lo valida, lo depura y no lo conserva.
  harInspect: (file) => request("/api/har/inspect", { method: "POST", headers: { "Content-Type": "application/json" }, body: file }),
  harImport: (file, load) =>
    request(`/api/har/import?load=${id(load)}&name=${id(String(file.name || "").slice(0, 200))}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: file }),
  harExportUrl: (jobId) => `/api/scans/${id(jobId)}/har`,
  compareCandidates: (jobId) => request(`/api/scans/${id(jobId)}/compare-candidates`),
  compare: (jobId, otherId) => request(`/api/scans/${id(jobId)}/compare/${id(otherId)}`),
  panel: (includeTests) => request(`/api/panel${includeTests ? "?include_tests=true" : ""}`),
  listTests: (limit = 50, filters) => request(`/api/privacy/tests?limit=${limit}${params(filters)}`),
  scan: (jobId) => request(`/api/scans/${id(jobId)}`),
  // Historial (F10). Borrar es definitivo; en modo demo la API responde 403.
  history: () => request("/api/history"),
  deleteScan: (jobId) => request(`/api/scans/${id(jobId)}`, { method: "DELETE" }),
  deleteAllScans: (confirm) =>
    request("/api/scans", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm }) }),
  glossary: () => request("/api/glossary"),
  bands: () => request("/api/bands"),
  report: (jobId) => request(`/api/scans/${id(jobId)}/report`),
  domains: (jobId) => request(`/api/scans/${id(jobId)}/domains`),
  requests: (jobId, query) => request(`/api/scans/${id(jobId)}/requests${query || ""}`),
  // v1.5.1: sin `reveal` la api devuelve los identificadores enmascarados.
  requestDetail: (jobId, requestId, reveal = false) =>
    request(`/api/scans/${id(jobId)}/requests/${id(requestId)}${reveal ? "?reveal=true" : ""}`),
  fingerprinting: (jobId) => request(`/api/scans/${id(jobId)}/fingerprinting`),
  findings: (jobId) => request(`/api/scans/${id(jobId)}/findings`),
  privacyProfiles: () => request("/api/privacy/profiles"),
  privacyCreate: (body) =>
    request("/api/privacy/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
  privacyTest: (groupId) => request(`/api/privacy/test/${id(groupId)}`),
  bannerUrl: (jobId) => `/api/privacy/artifacts/${id(jobId)}/consent_banner`,
  mode: () => request("/mode.json"),
  // Captura interactiva (v1.4). El token y la contraseña del visor se entregan una sola vez, al iniciar.
  interactiveStatus: () => request("/api/interactive"),
  interactiveStart: (url, cleanUrl = true) =>
    request("/api/interactive", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, clean_url: Boolean(cleanUrl) }) }),
  interactiveStop: (jobId) => request(`/api/interactive/${id(jobId)}/stop`, { method: "POST" }),
  // Indicador de recursos (v1.4).
  resources: () => request("/api/resources"),
  exposureServer: () => request("/api/exposure/server"),
  exposureIdentifiability: () => request("/api/exposure/identifiability"),
  exposureRoom: () => request("/api/exposure/room"),
  // Con jobId: solo ese scan («Comparar con un scan»).
  exposureScanUsage: (jobId) => request(`/api/exposure/scan-usage${jobId ? `?job_id=${id(jobId)}` : ""}`),
  // POST: la IP viaja en el cuerpo, nunca en la URL (no queda en ningún log).
  exposureIpLookup: (ip) =>
    request("/api/exposure/ip-lookup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) }),
  exposureCompare: (body) =>
    request("/api/exposure/compare", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
  exposurePurge: (token) => request("/api/exposure/purge", { method: "POST", headers: { "X-Presenter-Token": token } }),
  reportUrl: (jobId) => `/api/scans/${id(jobId)}/report`,
  // Reportes exportables (F8). subject: "scan" | "group".
  exportCreate: (subject, subjectId, reveal) =>
    request(`${exportBase(subject, subjectId)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reveal: Boolean(reveal) }) }),
  exportStatus: (subject, subjectId, reveal) => request(`${exportBase(subject, subjectId)}?reveal=${reveal ? "true" : "false"}`),
  exportFileUrl: (subject, subjectId, kind, reveal) => `${exportBase(subject, subjectId)}/${id(kind)}?reveal=${reveal ? "true" : "false"}`,
};
