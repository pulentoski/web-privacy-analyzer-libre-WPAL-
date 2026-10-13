// Componentes compartidos. Regla de seguridad: todo dato capturado se pinta como
// TEXTO (hijos de React). Aquí no hay dangerouslySetInnerHTML ni enlaces a URLs
// capturadas salvo <ExternalUrl>, que solo acepta http/https.
import { Icon } from "./Icons.jsx";
import { useId, useState } from "react";

import { ATTRIBUTE_STATUS, bandClass, errorMessage, levelInfo, safeHttpUrl, truncate } from "../lib/format.js";
import { LEVEL_TERMS, useGlossary } from "../lib/glossary.js";
import { buildHash } from "../lib/router.js";

const BADGE = "badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap";

/** Nivel de evidencia: el mismo badge en toda la app, con su explicación. */
export function EvidenceBadge({ level }) {
  const info = levelInfo(level);
  // La explicación del nivel es la del glosario cuando está cargado; si no, la propia.
  const term = useGlossary().byId[LEVEL_TERMS[level]];
  const description = term ? term.definition : info.description;
  return (
    <span className={`${BADGE} ${info.className}`} title={description} aria-label={`${info.label}: ${description}`} data-level={level}>
      {info.label}
    </span>
  );
}

/**
 * Frase técnica (F10): el mecanismo y su explicación en una línea, con su nivel de evidencia. Va SIEMPRE antes del
 * detalle técnico. El texto sale de una plantilla del servidor rellenada con datos capturados:
 * se pinta como texto, igual que todo lo demás.
 */
export function Plain({ text, level, inline = false, testId = "plain" }) {
  if (!text) return null;
  return (
    <div className={`bubble ${inline ? "bubble-inline" : ""}`} data-testid={testId} data-level={level || undefined}>
      <span className="bubble-text">{String(text)}</span>{" "}
      {level && <EvidenceBadge level={level} />}
    </div>
  );
}

// Quien abre un detalle técnico suele querer ver también los siguientes: se recuerda mientras
// dure la pestaña (no se guarda en ningún lado).
let techDetailOpen = false;

/** Botón «Ver detalle técnico»: lo técnico queda a un clic, debajo de la frase técnica. */
export function TechDetail({ children, testId = "tech-detail", remember = false, label = "detalle técnico" }) {
  const [open, setOpen] = useState(remember ? techDetailOpen : false);
  const regionId = useId();
  const toggle = () => {
    if (remember) techDetailOpen = !open;
    setOpen(!open);
  };
  return (
    <div data-testid={testId} data-open={String(open)}>
      <button type="button" className="btn text-sm" aria-expanded={open} aria-controls={regionId} onClick={toggle} data-testid={`${testId}-toggle`}>
        {open ? `Cerrar ${label}` : `Ver ${label}`}
      </button>
      {open && <div id={regionId} className="mt-3 space-y-4" data-testid={`${testId}-content`}>{children}</div>}
    </div>
  );
}

export function EvidenceLegend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm" aria-label="Niveles de evidencia">
      {["EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO"].map((level) => (
        <li key={level} className="flex items-center gap-1">
          <EvidenceBadge level={level} />
          <span className="muted">{levelInfo(level).description}</span>
        </li>
      ))}
    </ul>
  );
}

// Captura HAR importada: sin cookies ni fingerprinting, su índice no es comparable con el de un scan (v1.3.1).
export const PARTIAL_INDEX = "índice parcial (sin cookies ni fingerprinting)";

export function BandBadge({ band, score, partial = false }) {
  if (band === null || band === undefined) return <span className="muted text-xs">sin análisis</span>;
  const badge = (
    <span className={`${BADGE} ${bandClass(band)}`} data-band={band} title="Banda del tracking_score (estimación, no veredicto)">
      {score === null || score === undefined ? band : `${score} · ${band}`}
    </span>
  );
  if (!partial) return badge;
  return <span data-testid="partial-index">{badge} <span className="muted text-xs">{PARTIAL_INDEX}</span></span>;
}

export function StatusBadge({ status }) {
  const info = ATTRIBUTE_STATUS[status] || { label: String(status), className: "bg-white border-slate-300" };
  return <span className={`${BADGE} ${info.className}`}>{info.label}</span>;
}

/** Texto capturado: siempre texto plano, truncado, con "ver más" (salvo dentro de un enlace: `expandable={false}`). */
export function Captured({ value, limit = 120, block = false, expandable = true }) {
  const [open, setOpen] = useState(false);
  if (value === null || value === undefined || value === "") return <span className="muted">no disponible</span>;
  const cut = truncate(value, limit);
  const Tag = block ? "div" : "span";
  return (
    <Tag className="captured text-sm">
      {open ? String(value) : cut.text}
      {cut.truncated && !expandable && "…"}
      {cut.truncated && expandable && (
        <>
          {!open && "…"}{" "}
          <button type="button" className="link text-xs font-sans" onClick={() => setOpen(!open)}>
            {open ? "ver menos" : `ver más (${cut.hidden} caracteres)`}
          </button>
        </>
      )}
    </Tag>
  );
}

/** JSON u otro texto estructurado, en un visor de texto con scroll. Nunca como HTML. */
export function TextViewer({ value, label }) {
  let text = value;
  if (typeof value !== "string") {
    try {
      text = JSON.stringify(value, null, 2);
    } catch {
      text = String(value);
    }
  } else {
    try {
      text = JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      text = value;
    }
  }
  return (
    <pre className="captured text-xs bg-slate-50 border border-slate-300 rounded p-2 max-h-64 overflow-auto" aria-label={label || "contenido"} tabIndex={0}>
      {text}
    </pre>
  );
}

/**
 * URL capturada. Por defecto es texto. Solo con `clickable` y si es http(s) válida se
 * ofrece abrirla, en otra pestaña y sin referer ni opener.
 */
export function ExternalUrl({ value, clickable = false, limit = 100 }) {
  const safe = clickable ? safeHttpUrl(value) : null;
  return (
    <span>
      <Captured value={value} limit={limit} />
      {safe && (
        <>
          {" "}
          <a className="link text-xs" href={safe} target="_blank" rel="noopener noreferrer">
            abrir
          </a>
        </>
      )}
    </span>
  );
}

/** ⓘ con la explicación al pasar el cursor o al enfocarlo con el teclado (modo compacto: aquí va lo que antes era un párrafo). */
export function Info({ label, children }) {
  const tipId = useId();
  return (
    <span className="term info" tabIndex={0} role="button" aria-label={`Información: ${label}`} aria-describedby={tipId} data-testid="info">
      ⓘ
      <span className="term-tip" role="tooltip" id={tipId}>{children}</span>
    </span>
  );
}

/** Panel: título, subtítulo de UNA línea y, si hace falta explicar algo, un ⓘ. Sin párrafos explicativos. */
/**
 * `tone` solo afecta al tema «Unidad Púrpura», donde el título lleva franja de advertencia:
 * "alert" (naranja, por defecto), "danger" (rojo, avisos de bloqueo) o "neutral" (morado/verde).
 */
/** `mode` (v1.4.2): color de acento propio del panel (borde, título e ícono); el título y el ícono lo identifican sin depender del color. */
export function Panel({ title, subtitle, info, children, actions, testId, tone = "alert", mode, icon }) {
  return (
    <section className={`panel p-4 ${mode ? "mode" : ""}`} data-testid={testId} data-mode={mode}>
      {(title || actions) && (
        <div className={`flex items-start justify-between gap-2 mb-3 ${title ? "panel-head" : ""}`} data-tone={title ? tone : undefined}>
          <div className="min-w-0">
            {title && <h2 className={`text-lg font-semibold ${mode ? "mode-title" : ""}`}>{icon && <Icon name={icon} />}{icon && " "}{title}{info && <>{" "}<Info label={title}>{info}</Info></>}</h2>}
            {subtitle && <p className="panel-subtitle muted text-sm" data-testid="panel-subtitle">{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/**
 * Ilustración que gira mientras un scan o una importación de HAR están en curso (archivo local:
 * la CSP no cambia). Quien la usa la monta solo durante el proceso; con prefers-reduced-motion no gira.
 */
export function ScanSpinner({ label = "Scan en curso", testId = "scan-spinner" }) {
  return (
    <picture className="scan-spinner" data-testid={testId}>
      <source srcSet="/scanning-320.webp" type="image/webp" />
      <img src="/scanning-320.jpg" width="320" height="320" decoding="async" alt={`${label}: ilustración de un pingüino con un portátil, un reloj y un reloj de arena`} />
    </picture>
  );
}

/** Logo del proyecto (archivo local: la CSP no cambia). El círculo blanco lo hace legible sobre fondos oscuros. */
export function Logo({ size = "header", testId = "logo" }) {
  return <img src="/logo-256.png" alt="" width="256" height="256" className={`logo logo-${size}`} data-testid={testId} />;
}

/** Tarjeta del resumen. En «Unidad Púrpura» lleva esquinas cortadas y rótulo. */
export function StatCard({ label, value, hint, testId }) {
  return (
    <div className="vignette" data-testid={testId}>
      <div className="vignette-caption">{label}</div>
      <div className="vignette-body">
        <div className="text-3xl font-bold vignette-value">{value === null || value === undefined ? "—" : value}</div>
        {hint && <div className="muted text-xs mt-1">{hint}</div>}
      </div>
    </div>
  );
}

export function ErrorNotice({ error }) {
  if (!error) return null;
  return (
    <div role="alert" className="panel p-3 border-red-600 bg-red-50 text-red-900" data-testid="error">
      <strong>{errorMessage(error)}</strong>
      {error.error_code && <span className="ml-2 text-xs captured">({String(error.error_code)})</span>}
    </div>
  );
}

export function Loading({ what = "datos" }) {
  return <p className="muted" role="status">Cargando {what}…</p>;
}

export function Empty({ children }) {
  return <p className="muted italic">{children}</p>;
}

export function Link({ to, query, children, testId, className = "link" }) {
  return (
    <a className={className} href={buildHash(to, query)} data-testid={testId}>
      {children}
    </a>
  );
}

/** Referencias de evidencia navegables: requests y llamadas a APIs. */
export function EvidenceRefs({ jobId, requests = [], calls = [], max = 12 }) {
  const shownRequests = requests.slice(0, max);
  const shownCalls = calls.slice(0, max);
  if (!requests.length && !calls.length) return <span className="muted">sin referencias</span>;
  return (
    <span className="text-sm" data-testid="evidence-refs">
      {shownRequests.length > 0 && (
        <span>
          Requests:{" "}
          {shownRequests.map((ref) => (
            <span key={`r${ref}`}>
              <Link to={["scan", jobId, "request", ref]} testId="ref-request">#{ref}</Link>{" "}
            </span>
          ))}
          {requests.length > max && <span className="muted">y {requests.length - max} más. </span>}
        </span>
      )}
      {shownCalls.length > 0 && (
        <span>
          Llamadas:{" "}
          {shownCalls.map((ref) => (
            <span key={`c${ref}`}>
              <Link to={["scan", jobId, "fingerprinting"]} query={{ call: ref }} testId="ref-call">#{ref}</Link>{" "}
            </span>
          ))}
          {calls.length > max && <span className="muted">y {calls.length - max} más.</span>}
        </span>
      )}
    </span>
  );
}

/** Límites de la medición: plegado por defecto (modo compacto). */
// Aviso de visita posiblemente bloqueada (v1.2.1): el sitio pudo detectar el navegador automatizado.
export const BLOCKING_BANNER = "Resultado posiblemente no representativo: el sitio pudo detectar el navegador automatizado.";

// v1.3.2: la firma antibot apareció en un componente, pero la página cargó con rastreo normal.
export const PARTIAL_BLOCK_BANNER = "Bloqueo parcial: un componente mostró verificación antibot.";

export function BlockingBanner({ blocking, inRanking = true }) {
  if (blocking && !blocking.blocked && blocking.partial) {
    return (
      <div role="status" className="panel p-3 border-sky-700 bg-sky-100 text-sky-900 text-sm" data-testid="partial-blocking-banner">
        <strong>{PARTIAL_BLOCK_BANNER}</strong> Aviso informativo: el resto de la página cargó y el scan sigue en el ranking del Panel.
        {blocking.signals && blocking.signals.length > 0 && (
          <ul className="list-disc ml-5 mt-1">
            {blocking.signals.map((signal, index) => <li key={index}>{signal.detail}</li>)}
          </ul>
        )}
      </div>
    );
  }
  if (blocking && !blocking.blocked && blocking.note) {
    // v1.3.4: poco rastreo de terceros, pero el sitio mide con infraestructura propia. Informativo.
    return (
      <div role="status" className="panel p-3 border-sky-700 bg-sky-100 text-sky-900 text-sm" data-testid="low-tracking-note">
        <strong>Rastreo de terceros bajo; telemetría propia detectada.</strong> Nota informativa: el scan no se marca como bloqueado y sigue en el ranking del Panel.
        <ul className="list-disc ml-5 mt-1"><li>{blocking.note.detail}</li></ul>
      </div>
    );
  }
  if (!blocking || !blocking.blocked) return null;
  return (
    <div role="alert" className="panel hazard p-3 border-amber-600 bg-amber-50 text-sm" data-tone="danger" data-testid="blocking-banner">
      <strong>{BLOCKING_BANNER}</strong>
      {inRanking && " Por eso este scan se excluye del ranking comparativo del Panel."}
      {blocking.signals && blocking.signals.length > 0 && (
        <ul className="list-disc ml-5 mt-1">
          {blocking.signals.map((signal, index) => <li key={index}>{signal.detail}</li>)}
        </ul>
      )}
    </div>
  );
}

// Giro (tipo de servicio) de una organización: contexto, no evidencia del uso concreto (v1.2.1).
export function ServiceTag({ label }) {
  return (
    <span className="muted text-xs" data-testid="service-type" title="Giro del servicio (contexto, no evidencia del uso concreto)">
      {label || "tipo no identificado"}
    </span>
  );
}

export function LimitsNotice({ limitations }) {
  return (
    <details className="panel hazard p-3 border-amber-600 bg-amber-50 text-sm" data-testid="limits-notice" aria-label="Límites de la medición">
      <summary className="cursor-pointer font-bold" data-testid="limits-toggle">Límites de la medición</summary>
      <div className="mt-2" data-testid="limits-content">
        <p>
          Lo que se muestra es lo que vio un navegador automatizado en una sola visita, sin iniciar sesión ni aceptar o rechazar cookies.{" "}
          <strong>«0 exfiltraciones» no significa que no salgan datos</strong>: solo se reconocen valores enviados tal cual o con un hash común.
          Los puntajes son estimaciones, no veredictos.
        </p>
        {limitations && limitations.length > 0 && (
          <ul className="list-disc ml-5 mt-1">
            {limitations.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        )}
      </div>
    </details>
  );
}
