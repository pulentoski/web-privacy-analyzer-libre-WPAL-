// Íconos dibujados aquí mismo (SVG en línea, sin fuentes ni archivos externos). Son
// decorativos: el nombre de cada sección va siempre en texto junto al ícono.
const PATHS = {
  // Resumen: una foto.
  photo: <><rect x="3" y="6" width="18" height="13" rx="2" /><circle cx="12" cy="12.5" r="3.5" /><path d="M8 6l1.5-2h5L16 6" /></>,
  // Hallazgos: grupos numerados.
  steps: <><circle cx="5" cy="6" r="2" /><circle cx="5" cy="12" r="2" /><circle cx="5" cy="18" r="2" /><path d="M10 6h10M10 12h10M10 18h10" /></>,
  // Rastreadores: huellas.
  footprints: <><ellipse cx="8" cy="15" rx="2.6" ry="4" /><ellipse cx="16" cy="9" rx="2.6" ry="4" /><circle cx="6" cy="8" r="1" /><circle cx="9" cy="7" r="1" /><circle cx="14" cy="2.5" r="1" /><circle cx="17.5" cy="2.5" r="1" /></>,
  // Fingerprinting: una pantalla bajo la lupa.
  device: <><rect x="3" y="4" width="13" height="9" rx="1.5" /><path d="M7 17h5M9.5 13v4" /><circle cx="17" cy="15" r="3.2" /><path d="M19.4 17.4L22 20" /></>,
  // Tráfico: flechas de ida y vuelta.
  traffic: <><path d="M4 8h14M14 4l4 4-4 4" /><path d="M20 16H6M10 12l-4 4 4 4" /></>,
  tag: <><path d="M3 12V4h8l10 10-8 8L3 12z" /><circle cx="7.5" cy="8.5" r="1.5" /></>,
  eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>,
  upload: <><path d="M12 16V4M7 9l5-5 5 5" /><path d="M4 16v4h16v-4" /></>,
  share: <><circle cx="6" cy="12" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M8.2 10.9l7.6-3.8M8.2 13.1l7.6 3.8" /></>,
  check: <><rect x="3" y="3" width="18" height="18" rx="3" /><path d="M7 12l3.5 3.5L17 9" /></>,
  fog: <><path d="M3 8h13M6 12h15M3 16h11M17 16h4" /></>,
  help: <><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 115 0c0 1.7-2.5 2-2.5 4M12 17.2v.3" /></>,
  trash: <><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6" /></>,
  // v1.4.2: registro de interacción y modos de «Analizar un sitio» (cada modo: color + título + ícono).
  pointer: <><path d="M5 3l14 7-6 2-2 6L5 3z" /><path d="M13.5 13.5L20 20" /></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="M15.5 15.5L21 21" /></>,
  sliders: <><path d="M4 6h10M18 6h2M4 12h3M11 12h9M4 18h12M20 18h0" /><circle cx="16" cy="6" r="2" /><circle cx="9" cy="12" r="2" /><circle cx="18" cy="18" r="2" /></>,
  file: <><path d="M6 3h8l4 4v14H6V3z" /><path d="M14 3v4h4M9 13h6M9 17h6" /></>,
  pulse: <><path d="M3 12h4l2-6 4 12 2-6h6" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7" /></>,
  repeat: <><path d="M4 9a6 6 0 016-6h8M15 0l3 3-3 3" transform="translate(0 3)" /><path d="M20 12a6 6 0 01-6 6H6M9 21l-3-3 3-3" /></>,
  book: <><path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2V5z" /><path d="M8 7h7M8 11h7" /></>,
  // v1.6.0: alertas del Resumen (consentimiento, sincronización y rastreo del lado del servidor).
  shield: <><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6l8-3z" /><path d="M12 8v5M12 16v.3" /></>,
  link: <><path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1" /><path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1" /></>,
  server: <><rect x="4" y="4" width="16" height="6" rx="1.5" /><rect x="4" y="14" width="16" height="6" rx="1.5" /><path d="M8 7h.01M8 17h.01M12 10v4" /></>,
};

export const ICON_NAMES = Object.keys(PATHS);

export function Icon({ name, className = "w-5 h-5" }) {
  const path = PATHS[name] || PATHS.help;
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" data-icon={PATHS[name] ? name : "help"}>
      {path}
    </svg>
  );
}
