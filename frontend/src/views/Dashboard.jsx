import { useEffect } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import Graph from "../components/Graph.jsx";
import { Term, WhatIsThis } from "../components/Term.jsx";
import { BandBadge, BlockingBanner, Captured, Empty, ErrorNotice, EvidenceBadge, EvidenceLegend, EvidenceRefs, Info, LimitsNotice, Loading, Panel, PARTIAL_INDEX, Plain, StatCard } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { categoryLabel, COMPONENT_LABELS, entityLabel, formatDate, STATUS_LABELS, truncate } from "../lib/format.js";
import { useApi } from "../lib/useApi.js";
import { ThirdPartyServices } from "./Trackers.jsx";

const DATA_ORDER = ["IDENTIFIERS", "BEHAVIOR", "DEVICE", "NETWORK", "LOCATION", "ADVERTISING", "SESSION"];
const DATA_LABELS = {
  IDENTIFIERS: "Identificadores", BEHAVIOR: "Comportamiento", DEVICE: "Dispositivo", NETWORK: "Red",
  LOCATION: "Ubicación", ADVERTISING: "Publicidad", SESSION: "Sesión",
};
const STATUS_CLASS = {
  observado: "bg-emerald-100 text-emerald-900 border-emerald-700",
  inferido: "bg-amber-100 text-amber-900 border-amber-700",
  potencial: "bg-slate-100 text-slate-800 border-slate-500",
};

/** Host de la URL analizada para rotular el grafo; si no parsea, un rótulo neutro. */
function siteHost(url) {
  try {
    return new URL(url).hostname || "sitio";
  } catch {
    return "sitio";
  }
}

/**
 * El gráfico mide sus rótulos en un <span id="recharts_measurement_span"> que la librería agrega al
 * <body> y nunca quita: ahí quedaba, en todas las páginas, el último rótulo medido (un dominio
 * truncado). Se retira al desmontar el gráfico; la librería lo vuelve a crear cuando lo necesita.
 */
function useChartCleanup() {
  useEffect(() => () => {
    const span = document.getElementById("recharts_measurement_span");
    if (span) span.remove();
  }, []);
}

function Chart({ data, label }) {
  useChartCleanup();
  if (!data.length) return <Empty>Sin datos.</Empty>;
  return (
    <div style={{ width: "100%", height: Math.max(160, data.length * 30 + 40) }} role="img" aria-label={label}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" horizontal={false} />
          <XAxis type="number" allowDecimals={false} />
          <YAxis type="category" dataKey="name" width={190} tick={{ fontSize: 12 }} />
          <Tooltip />
          <Bar dataKey="requests" name="Requests" fill="#2563eb" isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** La visita en una frase, con los números del análisis. Todo lo que dice se observó (EVIDENCIA). */
const PURPOSE_ORDER = ["funcional", "analitica", "publicidad", "sin_clasificar"];

// v1.4.6: cookies por propósito, inferido del nombre (propias y de terceros). Las funcionales no suman al índice.
export function CookiePurposes({ purposes }) {
  if (!purposes || !purposes.by_purpose) return null;  // análisis anterior a v1.4.6: no se inventa «0»
  const keys = [...PURPOSE_ORDER.filter((key) => key in purposes.by_purpose),
    ...Object.keys(purposes.by_purpose).filter((key) => !PURPOSE_ORDER.includes(key))];
  const total = keys.reduce((sum, key) => sum + (purposes.by_purpose[key] || 0), 0);
  return (
    <Panel title="Cookies por propósito" tone="neutral" testId="cookie-purposes"
      subtitle="Propias y de terceros. El propósito se infiere del nombre de la cookie o, si no se conoce, de la organización que la creó."
      info={<><strong>Cookies por propósito</strong>: el nombre de una cookie (por ejemplo _ga o PHPSESSID) o el tipo de servicio de la organización que la creó es compatible con un uso conocido, pero no lo prueba. Las cookies funcionales (sesión, antibot, idioma, carrito) no suman al índice de exposición.</>}>
      <p className="text-sm mb-2"><EvidenceBadge level={purposes.level || "INFERENCIA"} /> {total} {total === 1 ? "cookie" : "cookies"} al terminar la visita.</p>
      <ul className="flex flex-wrap gap-3 text-sm">
        {keys.map((key) => (
          <li key={key} data-testid="cookie-purpose" data-purpose={key}>
            <span className="font-semibold">{purposes.by_purpose[key]}</span> {(purposes.labels || {})[key] || key}
          </li>
        ))}
      </ul>
      {purposes.by_basis ? (
        <p className="muted text-xs mt-1" data-testid="cookie-purpose-basis">
          Por el nombre: {purposes.by_basis.nombre || 0} · por la organización que la creó: {purposes.by_basis.organizacion || 0}.
        </p>
      ) : null}
      {purposes.by_purpose.funcional ? <p className="muted text-xs mt-1">Las funcionales no suman al índice de exposición.</p> : null}
    </Panel>
  );
}

export function headline(capture, summary, source = "scan") {
  const requests = capture.total_requests;
  const third = summary.third_party_domains;
  // Captura interactiva o importada (v1.4.2): no es la carga de una página, es toda una sesión de navegación.
  if (source === "interactive" || source === "har_import") {
    return `Durante la sesión se realizaron ${requests} ${requests === 1 ? "request" : "requests"} y se contactó ${third} ${third === 1 ? "dominio de tercero" : "dominios de terceros"}.`;
  }
  return `La página realizó ${requests} ${requests === 1 ? "request" : "requests"} y contactó ${third} ${third === 1 ? "dominio de tercero" : "dominios de terceros"}.`;
}

export const INTERACTIVE_END = {
  user_stop: "detenida por el usuario", idle_timeout: "cerrada por inactividad", max_duration: "cerrada al alcanzar la duración máxima",
  max_requests: "cerrada al alcanzar el máximo de requests", window_closed: "el usuario cerró la ventana", browser_closed: "el navegador se cerró",
};

/** Captura interactiva (v1.4): marca y línea de tiempo de páginas visitadas. URLs y títulos son datos del sitio: solo texto. */
export function InteractiveTimeline({ info }) {
  const timeline = (info && info.timeline) || [];
  const masked = info ? info.masked_fields : null;
  return (
    <Panel title="Captura interactiva" testId="interactive-banner" tone="neutral"
      subtitle="Una persona navegó en el navegador del analizador. Las cifras son de toda la sesión: no son comparables con las de una visita automática.">
      <p className="text-sm">
        Sesión <span data-testid="interactive-end">{(info && INTERACTIVE_END[info.end_reason]) || "terminada"}</span> ·{" "}
        <strong data-testid="interactive-pages">{timeline.length}</strong> {timeline.length === 1 ? "página visitada" : "páginas visitadas"}.
        Lo que se escribió durante la sesión y sus cookies forman parte de la captura.{" "}
        <span data-testid="interactive-masked">
          {masked === null || masked === undefined
            ? "Captura anterior a v1.4.1: los campos de contraseña no se enmascararon."
            : masked.length === 0
              ? "No se detectaron campos de contraseña ni credenciales en los cuerpos enviados."
              : <>Credenciales enmascaradas antes de guardar (solo nombre y largo): {masked.slice(0, 20).map((item, index) => (
                  <span key={index}>{index > 0 && ", "}<span className="captured">{item.name}</span> ({item.length})</span>))}.</>}
        </span>
      </p>
      {timeline.length > 0 && (
        <table className="w-full text-sm mt-2" data-testid="interactive-timeline">
          <thead><tr className="text-left"><th className="pr-2">#</th><th className="pr-2">Hora</th><th className="pr-2">Pestaña</th><th className="pr-2">Dirección</th><th>Título</th></tr></thead>
          <tbody>
            {timeline.map((entry) => (
              <tr key={entry.seq} className="align-top" data-testid="interactive-timeline-row">
                <td className="pr-2">{entry.seq + 1}</td>
                <td className="pr-2 whitespace-nowrap">{formatDate(entry.ts)}</td>
                <td className="pr-2">{entry.tab}</td>
                <td className="pr-2"><Captured value={entry.url} limit={90} /></td>
                <td>{entry.title ? <Captured value={entry.title} limit={80} /> : <span className="muted">no disponible</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {info && info.timeline_truncated && <p className="muted text-sm mt-2">La línea de tiempo se cortó al llegar a su máximo de entradas.</p>}
    </Panel>
  );
}

// v1.4.9: Client Hints del sitio: solicitudes por organización, envíos observados y delegación (contexto).
function SiteClientHints({ info }) {
  if (!info || ((info.requests || []).length === 0 && (info.sends || []).length === 0)) return null;
  const delegation = info.delegation || {};
  return (
    <Panel title={<Term id="client_hints">Client Hints</Term>} subtitle="Solicitud, envío y delegación: tres hechos distintos." testId="site-client-hints">
      <ul className="space-y-1 text-sm">
        {(info.requests || []).map((item) => (
          <li key={item.organization} data-testid="site-ch-request">
            <EvidenceBadge level="EVIDENCIA" /> <strong>Solicitud</strong>: <span className="captured">{item.organization}</span> pidió <span className="captured">{item.hints.join(", ")}</span>.{" "}
            Envío: {item.sent === "confirmado" ? `confirmado (${item.sent_hints.join(", ")})` : "no observado en esta captura"}.
          </li>
        ))}
        {(info.sends || []).length > 0 && <li data-testid="site-ch-sends"><EvidenceBadge level="EVIDENCIA" /> <strong>Envíos</strong>: {(info.sends || []).length} request(s) llevaron hints de alta entropía.</li>}
        <li data-testid="site-ch-delegation"><strong>Delegación por el sitio</strong>: {delegation.label || "No determinado"}{delegation.note ? `. ${delegation.note}` : ""}</li>
      </ul>
      <p className="muted text-xs mt-1">{info.request_text}</p>
      {(info.notes || []).length > 0 && <ul className="muted text-xs list-disc ml-5">{info.notes.map((note, index) => <li key={index}>{note}</li>)}</ul>}
    </Panel>
  );
}

export default function Dashboard({ jobId }) {
  const report = useApi(() => api.report(jobId), `report-${jobId}`);
  const domains = useApi(() => api.domains(jobId), `domains-${jobId}`);
  if (report.loading) return <Loading what="el resumen" />;
  if (report.error) return <ErrorNotice error={report.error} />;
  const data = report.data;
  const site = data.site;
  const fingerprinting = data.fingerprinting;
  const fpScripts = fingerprinting.scripts.filter((script) => script.fingerprinting_inferred);
  const exfilApis = new Set(fingerprinting.exfiltrations.map((item) => (item.details || {}).api)).size;
  const urlLeaks = data.findings.filter((finding) => finding.type === "url_leak" || finding.type === "referer_leak");
  const organizations = data.trackers.filter((group) => group.entity !== "no_disponible").length;
  const byCategory = Object.entries(site.summary.categories || {})
    .map(([category, requests]) => ({ name: categoryLabel(category), requests }))
    .sort((a, b) => b.requests - a.requests);
  const byOrganization = data.trackers.slice(0, 12).map((group) => ({
    name: truncate(group.entity === "no_disponible" ? `(sin organización) ${group.domains[0] || ""}` : entityLabel(group.entity), 28).text,
    requests: group.request_count,
  }));
  const grouped = DATA_ORDER.map((category) => [category, site.data_categories.filter((item) => item.category === category)]);
  const sameOrg = (site.summary.parties || {}).same_org_domains || [];
  const conclusions = (data.consent || {}).conclusions || [];

  return (
    <div className="space-y-4" data-testid="dashboard">
      <WhatIsThis panel="summary" />
      <BlockingBanner blocking={site.summary.blocking} />
      {data.scan.source === "interactive" && <InteractiveTimeline info={data.scan.interactive} />}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-[16rem]"><Plain text={headline(data.capture, site.summary, data.scan.source)} level="EVIDENCIA" testId="summary-plain" /></div>
      </div>
      {conclusions.length > 0 && (
        <Panel title="Consentimiento" testId="consent-conclusions">
          {conclusions.map((item, index) => <Plain key={index} text={item.text} level={item.level} />)}
        </Panel>
      )}
      <LimitsNotice limitations={data.limitations} />

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <div className="panel p-3 col-span-2 lg:row-span-3" data-testid="card-exposure">
          <div className="muted text-sm">Exposición del sitio (0–99, estimación){" "}
            <Info label="Exposición del sitio"><strong>Exposición del sitio</strong>: cada fila aporta puntos que se acercan a su tope sin alcanzarlo; el total nunca llega a 100.</Info>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-5xl font-bold" data-testid="exposure-score">{site.exposure_score}</span>
            <BandBadge band={site.band} />
          </div>
          {site.summary.score_by_level && (
            <p className="text-sm" data-testid="exposure-levels">
              Evidencia {site.summary.score_by_level.EVIDENCIA} + Inferencia {site.summary.score_by_level.INFERENCIA}{" "}
              <Info label="Evidencia e inferencia en el índice">Puntos que se sostienen solo con hechos observados (Evidencia) y los que dependen de inferencias, como un patrón compatible con fingerprinting o el puntaje de una request que necesita razones de nivel Inferencia para llegar a la banda de rastreador.</Info>
            </p>
          )}
          {data.scan.source === "har_import" && (
            <p className="text-sm font-medium" data-testid="exposure-partial">
              {PARTIAL_INDEX.charAt(0).toUpperCase() + PARTIAL_INDEX.slice(1)}: no es comparable con el índice de un scan.
            </p>
          )}
          <table className="w-full text-sm mt-2">
            <tbody>
              {site.breakdown.map((component) => (
                <tr key={component.component} className="border-t border-slate-200">
                  <td className="py-0.5 pr-2">{COMPONENT_LABELS[component.component] || component.component}</td>
                  <td className="pr-2 text-right">{component.count}</td>
                  <td className="text-right whitespace-nowrap">+{component.points} <span className="muted">de {component.cap}</span>
                    {component.inference_points > 0 && <span className="muted text-xs" data-testid="component-inference"> (inferencia {component.inference_points})</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <StatCard testId="card-trackers" label={<>Conexiones de <Term id="tracker">rastreadores</Term> (requests de tracking)</>} value={site.summary.trackers} hint="Banda Moderado o superior" />
        <StatCard testId="card-third" label={<>Dominios de <Term id="tercero">terceros</Term></>} value={site.summary.third_party_domains} hint="Ser tercero no implica rastrear" />
        <StatCard testId="card-orgs" label="Organizaciones" value={organizations} hint="Con requests de tracking y dueño conocido" />
        <StatCard testId="card-fp" label={<>Scripts con patrón de <Term id="fingerprinting">fingerprinting</Term></>} value={fingerprinting.instrumented ? fpScripts.length : "—"} hint={fingerprinting.instrumented ? "Inferencia, no confirmación" : "Scan sin instrumentación"} />
        <StatCard testId="card-exfil" label={<><Term id="exfiltracion">Exfiltraciones</Term> observadas</>} value={fingerprinting.instrumented ? fingerprinting.exfiltrations.length : "—"}
          hint={fingerprinting.instrumented
            ? `Pares «valor leído → destino». Corresponden a ${exfilApis} API(s) distinta(s), que es lo que cuenta el desglose. 0 no significa que no salgan datos.`
            : "Scan sin instrumentación"} />
        <StatCard testId="card-leaks" label="Fugas de URL" value={urlLeaks.length} hint="La URL de la página llegó a un tercero" />
        {site.summary.first_party_telemetry && (
          <StatCard testId="card-telemetry" label="Telemetría propia (requests de eventos)" value={site.summary.first_party_telemetry.requests}
            hint={`Al propio sitio o a su misma organización; no son terceros. ${site.summary.first_party_telemetry.scripts} script(s) de analítica propia`} />
        )}
        <StatCard testId="card-same-org" label="Dominios de la misma organización" value={sameOrg.length} hint="Otro dominio del mismo dueño; no son terceros" />
        {data.scan.source === "har_import" && (
          <StatCard testId="card-blocked-client" label="Bloqueadas por una extensión del navegador" value={data.capture.blocked_by_client}
            hint="Requests que el navegador del usuario canceló (net::ERR_BLOCKED_BY_CLIENT); se cuentan aparte" />
        )}
      </div>
      <ThirdPartyServices services={site.summary.third_party_services} compact />
      <SiteClientHints info={site.summary.client_hints} />
      <CookiePurposes purposes={site.summary.cookie_purposes} />
      {sameOrg.length > 0 && (
        <Panel title="Recursos de la misma organización (no son terceros)" testId="same-org">
          <p className="text-sm muted">Dominios de otra dirección pero del mismo dueño que el sitio, según el mapa de entidades. No cuentan como terceros ni entran en el índice de exposición.</p>
          <ul className="mt-1 flex flex-wrap gap-2">
            {sameOrg.map((domain) => <li key={domain} className="captured text-xs">{domain}</li>)}
          </ul>
        </Panel>
      )}

      <Panel title="Niveles de evidencia"><EvidenceLegend /></Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Requests por categoría" testId="chart-category"><Chart data={byCategory} label="Requests por categoría" /></Panel>
        <Panel title="Requests de tracking por organización" testId="chart-org"><Chart data={byOrganization} label="Requests de tracking por organización" /></Panel>
      </div>

      <Panel title="Relaciones: sitio → categorías → organizaciones → dominios">
        {domains.loading ? <Loading what="el grafo" /> : domains.error ? <ErrorNotice error={domains.error} /> : (
          <Graph domains={domains.data.domains} siteLabel={siteHost(data.scan.url)} />
        )}
      </Panel>

      <Panel title="Categorías de datos expuestos a terceros" testId="data-categories">
        <div className="space-y-2">
          {grouped.map(([category, items]) => (
            <div key={category}>
              <h3 className="font-semibold">{DATA_LABELS[category]}</h3>
              {items.length === 0 ? <Empty>Nada observado ni inferido en este scan.</Empty> : (
                <ul className="space-y-1">
                  {items.map((item, index) => (
                    <li key={index} className="text-sm">
                      <span className={`badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold mr-2 ${STATUS_CLASS[item.status] || ""}`}>
                        {STATUS_LABELS[item.status] || item.status}
                      </span>
                      {item.item} <EvidenceRefs jobId={jobId} requests={item.evidence_refs} max={5} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
