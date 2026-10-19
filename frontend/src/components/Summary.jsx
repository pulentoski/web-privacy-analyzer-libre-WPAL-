// Piezas del Resumen en bento (v1.6.0, docs/adr/042). Solo presentación: todo sale del reporte y de
// GET /api/scans/{id}/overview; nada se recalcula ni cambia de nivel. Los colores van por variables (index.css).
import { Icon } from "./Icons.jsx";
import { BandBadge, Captured, EvidenceBadge, Info } from "./ui.jsx";
import { COMPONENT_LABELS, entityLabel, formatDate } from "../lib/format.js";

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

/** Validez de la medición a partir de `site.summary.blocking` (la regla antibot es la del analizador, v1.4.8). */
export function validity(blocking) {
  const info = blocking || {};
  if (info.not_applicable) {
    return { id: "no_aplica", label: "No aplica", kind: "third",
      note: info.not_applicable === "interactive" ? "Captura interactiva: la regla antibot no se aplica a una navegación humana."
        : info.not_applicable === "har_import" ? "Captura importada: la regla antibot no se aplica al navegador del usuario."
          : "Navegación fallida: no hubo página que juzgar." };
  }
  if (info.blocked) return { id: "bloqueo", label: "Posible bloqueo", kind: "exfil" };
  if (info.partial) return { id: "bloqueo_parcial", label: "Bloqueo parcial", kind: "warn" };
  if (info.possible_variant) return { id: "posible_variante", label: "Posible variante", kind: "warn" };
  return { id: "valida", label: "Medición válida", kind: "valid" };
}

export function antibotRule(blocking) {
  const min = (blocking || {}).min_requests;
  return `Regla antibot: una señal dura (estado HTTP de bloqueo, título de desafío o firma antibot en la URL) marca un posible bloqueo; ${
    min ? `menos de ${min} requests` : "pocas requests"} o rastreo anómalo, sin señal dura, quedan como posible variante.`;
}

/** Las 3 cifras de «Lo más relevante»: salen del desglose del índice y de los hallazgos de sincronización. */
export function figures(report) {
  const breakdown = Object.fromEntries((report.site.breakdown || []).map((item) => [item.component, item.count]));
  const owners = report.findings.filter((item) => item.type === "id_sync")
    .map((item) => Number((item.details || {}).owners) || 0);
  return {
    trackerDomains: breakdown.tracker_domains ?? 0,
    urlRecipients: breakdown.url_leak_recipients ?? 0,
    sameIdCompanies: owners.length ? Math.max(...owners) : 0,
  };
}

export function figuresSentence({ trackerDomains, urlRecipients, sameIdCompanies }) {
  return `${plural(trackerDomains, "dominio de tercero", "dominios de terceros")} con rastreo; ${plural(urlRecipients, "tercero recibió", "terceros recibieron")} la URL de la página; ${
    sameIdCompanies === 0 ? "ninguna empresa recibió" : plural(sameIdCompanies, "empresa recibió", "empresas recibieron")} el mismo identificador.`;
}

const firstLevel = (items, fallback) => (items.find((item) => item.level === "EVIDENCIA") || items[0] || {}).level || fallback;

/** Hasta 3 alertas, solo las que existen, en este orden. El nivel es el del hallazgo que la sostiene. */
export function alerts(report, fpScripts = 0) {
  const findings = report.findings || [];
  const consent = report.consent || {};
  const out = [];
  const pressed = consent.banner_interaction ?? consent.user_interaction;
  const consentSignals = (consent.conclusions || []).length > 0 || ((consent.consent_mode || {}).requests || 0) > 0;
  if (consentSignals && !pressed) {
    const items = consent.conclusions || [];
    out.push({ id: "consent", icon: "shield", kind: "tracking", level: firstLevel(items, "EVIDENCIA"),
      text: `Consentimiento sin interacción: se enviaron señales de consentimiento sin que se pulsara el aviso${items[0] ? ` (${items[0].text})` : "."}` });
  }
  const sync = findings.filter((item) => ["id_sync", "redirect_sync", "sync_wave"].includes(item.type));
  if (sync.length) {
    out.push({ id: "sync", icon: "link", kind: "tracking", level: firstLevel(sync, "EVIDENCIA"),
      text: `Sincronización entre empresas: ${plural(sync.length, "hallazgo", "hallazgos")} de identificadores compartidos entre organizaciones.` });
  }
  const server = findings.filter((item) => item.type === "server_side_meta");
  if (server.length) {
    out.push({ id: "server_side", icon: "server", kind: "fp", level: firstLevel(server, "INFERENCIA"),
      text: `Rastreo del lado del servidor: ${plural(server.length, "host compatible", "hosts compatibles")} con un reenvío entre servidores (no observable).` });
  }
  if (fpScripts > 0) {
    out.push({ id: "fingerprinting", icon: "device", kind: "fp", level: "INFERENCIA",
      text: `Fingerprinting: ${plural(fpScripts, "script con patrón", "scripts con patrón")} de lectura de atributos del dispositivo.` });
  }
  return out.slice(0, 3);
}

/** Medidor semicircular 0–99. */
export function Gauge({ score }) {
  const value = Math.max(0, Math.min(99, Number(score) || 0));
  const radius = 80;
  const length = Math.PI * radius;
  return (
    <svg className="gauge" viewBox="0 0 200 118" role="img" aria-label={`Índice de exposición ${value} de 99`} data-testid="exposure-gauge">
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" strokeWidth="16" strokeLinecap="round" className="gauge-track" />
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" strokeWidth="16" strokeLinecap="round" className="gauge-fill"
        strokeDasharray={`${(length * value) / 99} ${length}`} />
      <text x="20" y="116" textAnchor="middle" fontSize="11" className="gauge-value" aria-hidden="true">0</text>
      <text x="180" y="116" textAnchor="middle" fontSize="11" className="gauge-value" aria-hidden="true">99</text>
    </svg>
  );
}

export function previousDelta(score, overview) {
  const previous = overview && overview.previous_scan;
  if (!previous || typeof previous.score !== "number" || typeof score !== "number") return null;
  return { delta: Math.round((score - previous.score) * 10) / 10, previous };
}

export function IndexCard({ site, source, overview, partialText }) {
  const levels = site.summary.score_by_level;
  const total = levels ? (levels.EVIDENCIA || 0) + (levels.INFERENCIA || 0) : 0;
  const change = source === "har_import" ? null : previousDelta(site.exposure_score, overview);
  return (
    <section className="panel card p-4" data-testid="card-exposure">
      <h2 className="section-title">Índice de exposición{" "}
        <Info label="Exposición del sitio"><strong>Exposición del sitio</strong> (0–99, estimación): cada fila aporta puntos que se acercan a su tope sin alcanzarlo; el total nunca llega a 100.</Info>
      </h2>
      <div className="relative w-full max-w-[15rem]">
        <Gauge score={site.exposure_score} />
        <span className="gauge-number absolute inset-x-0 text-center text-5xl font-bold" style={{ bottom: "1.1rem" }} data-testid="exposure-score">{site.exposure_score}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2 mt-1">
        <BandBadge band={site.band} />
        {change && (
          <span className="pill" data-testid="exposure-previous" data-delta={change.delta} title={`Scan anterior del ${formatDate(change.previous.created_at)}: ${change.previous.score}`}>
            {change.delta > 0 ? "↑" : change.delta < 0 ? "↓" : "="} {Math.abs(change.delta)} vs scan anterior
          </span>
        )}
      </div>
      {levels && (
        <div className="mt-3">
          <p className="text-sm" data-testid="exposure-levels">
            Evidencia {levels.EVIDENCIA} + Inferencia {levels.INFERENCIA}{" "}
            <Info label="Evidencia e inferencia en el índice">Puntos que se sostienen solo con hechos observados (Evidencia) y los que dependen de inferencias, como un patrón compatible con fingerprinting o el puntaje de una request que necesita razones de nivel Inferencia para llegar a la banda de rastreador.</Info>
          </p>
          <div className="split-bar mt-1" aria-hidden="true">
            <span className="split-evidence" style={{ width: `${total ? (100 * (levels.EVIDENCIA || 0)) / total : 0}%` }} />
            <span className="split-inference" style={{ width: `${total ? (100 * (levels.INFERENCIA || 0)) / total : 0}%` }} />
          </div>
        </div>
      )}
      {partialText && <p className="text-sm font-medium mt-2" data-testid="exposure-partial">{partialText}</p>}
      <details className="mt-3" data-testid="exposure-breakdown">
        <summary className="cursor-pointer text-sm font-semibold">Cómo se calculó</summary>
        <ul className="mt-2 space-y-2 text-sm">
          {site.breakdown.map((component) => (
            <li key={component.component} data-testid="exposure-component" data-component={component.component}>
              <div className="flex justify-between gap-2">
                <span>{COMPONENT_LABELS[component.component] || component.component} <span className="muted">({component.count})</span></span>
                <span className="whitespace-nowrap">+{component.points} <span className="muted">de {component.cap}</span>
                  {component.inference_points > 0 && <span className="muted text-xs" data-testid="component-inference"> (inferencia {component.inference_points})</span>}</span>
              </div>
              <div className="thin-bar mt-1" aria-hidden="true"><span className="thin-fill" style={{ width: `${component.cap ? (100 * component.points) / component.cap : 0}%` }} /></div>
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}

export function HighlightsCard({ report, fpScripts, children }) {
  const items = alerts(report, fpScripts);
  return (
    <section className="panel card p-4" data-testid="highlights">
      <h2 className="section-title">Lo más relevante</h2>
      <p className="text-base font-semibold" data-testid="highlights-sentence">{figuresSentence(figures(report))}</p>
      <div className="mt-2">{children}</div>
      {items.length > 0 && (
        <ul className="mt-3" data-testid="summary-alerts">
          {items.map((item) => (
            <li key={item.id} className="alert-row text-sm" data-kind={item.kind} data-testid="summary-alert" data-alert={item.id}>
              <Icon name={item.icon} className="w-5 h-5" />
              <span className="min-w-0">{item.text} <EvidenceBadge level={item.level} /></span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function ConsentCard({ consent }) {
  const info = consent || {};
  const pressed = info.banner_interaction ?? info.user_interaction;
  const states = Object.entries(((info.consent_mode || {}).states) || {});
  return (
    <section className="panel card p-4" data-testid="consent-conclusions">
      <h2 className="section-title">Consentimiento</h2>
      <ul className="text-sm space-y-1">
        <li data-testid="banner-interaction">Interacción con el aviso de consentimiento: {pressed ? "sí" : "no"}{" "}
          <Info label="Interacción con el aviso de consentimiento"><strong>Interacción con el aviso de consentimiento</strong>: si el escenario pulsó un botón del aviso (aceptar o rechazar). No incluye los clics ni los desplazamientos de una captura interactiva.</Info>
        </li>
        <li data-testid="consent-tcf">TCF: {info.tcf && info.tcf.present ? "presente" : "no observado en esta captura"}</li>
        <li data-testid="consent-mode">Consent Mode: {states.length === 0 ? "no observado en esta captura" : (
          <span className="flex flex-wrap gap-1 mt-1">
            {states.map(([state, count]) => <span key={state} className="pill" data-testid="consent-mode-state"><span className="captured">{state}</span> · {plural(count, "request", "requests")}</span>)}
          </span>
        )}</li>
      </ul>
      {(info.conclusions || []).length > 0 && (
        <ul className="mt-2 space-y-1 text-sm">
          {info.conclusions.map((item, index) => <li key={index} data-testid="consent-conclusion">{item.text} <EvidenceBadge level={item.level} /></li>)}
        </ul>
      )}
    </section>
  );
}

export const STAT_KINDS = {
  "card-trackers": "tracking", "card-orgs": "tracking", "card-leaks": "tracking", "card-exfil": "exfil",
  "card-fp": "fp", "card-third": "third", "card-telemetry": "own", "card-same-org": "own", "card-blocked-client": "third",
};

export function RecipientsCard({ overview, jobId }) {
  const rows = (overview && overview.recipients) || [];
  return (
    <section className="panel card p-4" data-testid="recipients">
      <h2 className="section-title">Quién recibió más datos{" "}
        <Info label="Quién recibió más datos">Organizaciones (terceros) ordenadas por la cantidad de tipos de dato que recibieron según los hallazgos (identificador, URL de la página, consentimiento, dispositivo, búsqueda) y luego por sus requests de tracking. El nivel de cada dato es el de su hallazgo.</Info>
      </h2>
      {overview === undefined ? <p className="muted text-sm">Cargando…</p> : rows.length === 0 ? <p className="muted text-sm">Ningún tercero recibió estos datos en esta captura.</p> : (
        <ol className="space-y-2">
          {rows.slice(0, 10).map((row) => (
            <li key={`${row.organization}-${row.domains[0] || ""}`} className="flex gap-3 text-sm" data-testid="recipient-row" data-rank={row.rank}>
              <span className="font-bold w-6 text-right flex-none">{row.rank}</span>
              <div className="min-w-0 flex-1">
                <div className="font-semibold" data-testid="recipient-org">
                  {row.label ? entityLabel(row.label) : <>(sin organización) <span className="captured">{row.domains[0]}</span></>}
                </div>
                <div className="flex flex-wrap gap-1 mt-1" data-testid="recipient-types">
                  {row.data_type_labels.map((label) => <span key={label} className="pill" data-kind="tracking"><span className="pill-dot" />{label}</span>)}
                  {row.data_type_labels.length === 0 && <span className="muted">sin datos de los cinco tipos</span>}
                </div>
                <div className="muted text-xs mt-1" data-testid="recipient-cookie">
                  Cookie más larga: {row.longest_cookie_days === null ? "no observada en esta captura" : `${plural(row.longest_cookie_days, "día", "días")}${row.longest_cookie ? ` (${row.longest_cookie})` : ""}`}
                  {" · "}{plural(row.tracking_requests, "request de tracking", "requests de tracking")}
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}
      {rows.length > 10 && <p className="muted text-xs mt-2">Se muestran 10 de {rows.length}; el resto está en <a className="link" href={`#/scan/${encodeURIComponent(jobId)}/trackers`}>Rastreadores</a>.</p>}
    </section>
  );
}

export function Fold({ id, title, children }) {
  return (
    <details className="panel card p-4 fold" data-testid={`fold-${id}`}>
      <summary><h2 className="section-title">{title}</h2></summary>
      {children}
    </details>
  );
}

/** Cookies por propósito como barra apilada (los colores no llevan significado propio: el texto los nombra). */
export function PurposeBar({ purposes, keys }) {
  const total = keys.reduce((sum, key) => sum + (purposes.by_purpose[key] || 0), 0);
  if (!total) return null;
  const KIND = { funcional: "own", analitica: "fp", publicidad: "tracking", sin_clasificar: "third" };
  return (
    <div className="split-bar mt-2" role="img" aria-label="Cookies por propósito" data-testid="cookie-purpose-bar">
      {keys.map((key) => <span key={key} data-kind={KIND[key] || "third"} style={{ width: `${(100 * (purposes.by_purpose[key] || 0)) / total}%`, background: "var(--kind)" }} />)}
    </div>
  );
}

export function HeaderCard({ data, jobId, exportHref, children }) {
  const scan = data.scan;
  const conditions = (data.measurement || {}).conditions || {};
  const state = validity(data.site.summary.blocking);
  let domain = "sitio";
  try {
    domain = new URL(scan.url).hostname || "sitio";
  } catch {
    /* URL no parseable: rótulo neutro */
  }
  const when = conditions.measured_at && conditions.measured_at !== "no_disponible" ? conditions.measured_at : scan.started_at;
  return (
    <section className="panel card p-4" data-testid="summary-header">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-bold" data-testid="summary-domain"><Captured value={domain} limit={80} expandable={false} /></h1>
          <dl className="text-sm mt-1 space-y-0.5">
            <div><dt className="inline muted">ID del scan: </dt><dd className="inline captured" data-testid="summary-id">{jobId}</dd></div>
            <div><dt className="inline muted">URL final: </dt><dd className="inline" data-testid="summary-final-url"><Captured value={scan.final_url || scan.url} limit={110} /></dd></div>
            <div><dt className="inline muted">Fecha: </dt><dd className="inline" data-testid="summary-date">{when ? formatDate(when) : "no disponible"}</dd></div>
          </dl>
        </div>
        <div className="flex flex-col items-start gap-2 sm:items-end">
          <span className="pill validity" data-kind={state.kind} data-testid="summary-validity" data-validity={state.id}><span className="pill-dot" />{state.label}</span>
          <a className="btn btn-primary" href={exportHref} download={`reporte-${jobId}.json`} data-testid="summary-export">Exportar</a>
        </div>
      </div>
      {/* La regla va en el ⓘ: en pantalla no se deja un párrafo explicativo largo (modo compacto, v1.2). */}
      <p className="muted text-xs mt-2" data-testid="summary-antibot-rule">{state.note || <>Validez según la regla antibot del analizador{" "}
        <Info label="Regla antibot">{antibotRule(data.site.summary.blocking)}</Info></>}</p>
      {children}
    </section>
  );
}
