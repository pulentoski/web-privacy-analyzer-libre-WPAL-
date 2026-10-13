// Nombre de cada atributo de los scans (F4) con las mismas etiquetas de «Mi exposición».
import { CATALOG } from "./catalog.js";

const BY_SCAN = {};
CATALOG.forEach((item) => item.scan.forEach((name) => {
  if (!BY_SCAN[name]) BY_SCAN[name] = item;
}));

/** Entrada del catálogo que corresponde a un atributo de scan, o null si el catálogo no lo tiene. */
export function catalogEntry(attribute) {
  return Object.hasOwn(BY_SCAN, attribute) ? BY_SCAN[attribute] : null;
}

// Atributos que el worker instrumenta y «Mi exposición» no lee (no tienen fila en el catálogo).
const ONLY_IN_SCANS = {
  webgl_parameters: "Parámetros de WebGL", webrtc: "WebRTC", webdriver: "Indicador de automatización",
  media_devices: "Dispositivos multimedia", battery: "Batería", speech_voices: "Voces de síntesis",
};

/** Etiqueta de «Mi exposición»; para lo que solo miden los scans, su nombre propio; si no se conoce, el identificador tal cual. */
export function scanAttributeLabel(attribute) {
  const entry = catalogEntry(attribute);
  if (entry) return entry.label;
  return Object.hasOwn(ONLY_IN_SCANS, attribute) ? ONLY_IN_SCANS[attribute] : String(attribute);
}

/**
 * Filas de la API (una por atributo de scan) -> filas por etiqueta de «Mi exposición»
 * (webgl_vendor y webgl_renderer son el mismo atributo para quien lee la tabla).
 */
export function groupByLabel(rows) {
  const grouped = new Map();
  (rows || []).forEach((row) => {
    const label = scanAttributeLabel(row.attribute);
    const entry = grouped.get(label) || { label, attributes: [], read_by: [], sent_to: [] };
    entry.attributes.push(row.attribute);
    (row.read_by || []).forEach((item) => {
      if (!entry.read_by.some((known) => known.script_url === item.script_url)) entry.read_by.push(item);
    });
    (row.sent_to || []).forEach((item) => {
      if (!entry.sent_to.some((known) => known.organization === item.organization && known.domain === item.domain)) entry.sent_to.push(item);
    });
    grouped.set(label, entry);
  });
  return [...grouped.values()];
}
