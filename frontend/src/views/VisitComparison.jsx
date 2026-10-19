// Comparación de visitas (v1.5.2, docs/adr/040): tres visitas a la misma URL (perfil A limpio, perfil A persistente
// tras un intervalo, perfil B limpio de control). Es una comparación reproducible, no un detector: los textos de cada
// clase son fijos (los entrega la api) y la advertencia se muestra siempre.
import { useEffect, useState } from "react";

import { Icon } from "../components/Icons.jsx";
import { BandBadge, Captured, Empty, ErrorNotice, Info, Link, Loading, Panel } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { formatDate, orUnavailable, stageLabel, validateScanUrl } from "../lib/format.js";
import { navigate } from "../lib/router.js";

const POLL_MS = 3000;
export const DEFAULT_INTERVAL_S = 300;
export const MAX_INTERVAL_S = 86400;

export const VALIDITY_LABELS = { valida: "Válida", no_valida: "No válida", en_curso: "En curso" };
// Orden y nombre de cada clase en la vista; el texto de cada una lo da la api.
export const CLASS_ORDER = [
  ["persistent", "Persistencia"],
  ["only_visit_2", "Solo en la visita 2"],
  ["also_control", "En la visita 2 y en el control"],
  ["profile_a", "En las dos visitas del perfil A"],
  ["clean_only", "Solo en perfiles limpios"],
];

/** Segundos como texto legible («5 min», «1 h 30 min», «45 s»); «no disponible» si no hay dato. */
export function seconds(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return orUnavailable(null);
  if (value < 60) return `${Math.round(value * 10) / 10} s`;
  const minutes = Math.floor(value / 60);
  const rest = Math.round(value % 60);
  if (minutes < 60) return rest ? `${minutes} min ${rest} s` : `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`;
}

/** Valida el intervalo del formulario: entero entre 0 y 86400 segundos. Devuelve el mensaje de error o null. */
export function intervalProblem(text) {
  if (!/^\d{1,5}$/.test(String(text).trim())) return "El intervalo debe ser un número entero de segundos.";
  const value = Number(text);
  return value > MAX_INTERVAL_S ? `El intervalo máximo es ${MAX_INTERVAL_S} s (24 h).` : null;
}

/** Inicio de una comparación desde «Analizar un sitio»: usa la URL del formulario principal. */
export function VisitComparisonStart({ url, cleanUrl = true }) {
  const [interval, setIntervalText] = useState(String(DEFAULT_INTERVAL_S));
  const [problem, setProblem] = useState(null);
  const [error, setError] = useState(null);
  const [sending, setSending] = useState(false);

  const start = () => {
    setError(null);
    const issue = validateScanUrl(url) || intervalProblem(interval);
    setProblem(issue);
    if (issue) return;
    setSending(true);
    api.comparisonCreate({ url: url.trim(), interval_s: Number(interval), clean_url: Boolean(cleanUrl) })
      .then((created) => navigate(["comparison", created.comparison_id]), (failure) => { setError(failure); setSending(false); });
  };

  return (
    <Panel title="Comparar visitas" icon="repeat" testId="comparison-start"
      subtitle="Tres visitas a la URL de arriba: perfil A limpio, el mismo perfil A tras un intervalo, y un perfil B limpio de control.">
      <div className="space-y-2 text-sm">
        <p>
          Entre la visita 1 y la 2 se cierra el navegador y se conserva el perfil A en disco (cookies, almacenamiento local e IndexedDB). La
          visita 3 usa otro perfil, nuevo y vacío.{" "}
          <Info label="Comparar visitas">
            <strong>Comparar visitas</strong>: las tres visitas siguen el mismo protocolo que un scan y se analizan igual. Después se comparan
            los valores exactos en su contexto (mismo destino y mismo campo). Tres visitas no prueban causalidad. Cuenta como 3 scans.
          </Info>
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col">
            <span className="font-medium">Intervalo entre la visita 1 y la 2 (segundos)</span>
            <input type="text" inputMode="numeric" className="border border-slate-400 rounded px-2 py-1 w-32" value={interval}
              onChange={(event) => setIntervalText(event.target.value)} aria-invalid={Boolean(problem)} data-testid="comparison-interval" />
          </label>
          <button type="button" className="btn btn-primary" disabled={sending} onClick={start} data-testid="comparison-submit">
            {sending ? "Enviando…" : "Comparar visitas (3 scans)"}
          </button>
        </div>
        {problem && <p role="alert" className="text-red-800" data-testid="comparison-field-error">{problem}</p>}
        <ErrorNotice error={error} />
      </div>
    </Panel>
  );
}

function VisitStatus({ visit }) {
  if (visit.status === "queued" && visit.waiting_until) {
    return <span data-testid="visit-waiting">En espera hasta {formatDate(visit.waiting_until)}</span>;
  }
  return (
    <span>
      {visit.progress ? stageLabel(visit.progress.stage) : orUnavailable(null)}
      {visit.error_code && <span className="block captured text-xs" data-testid="visit-error">{String(visit.error_code)}</span>}
    </span>
  );
}

function Value({ value }) {
  if (value === null || value === undefined) return <span className="muted">(presencia)</span>;
  return <Captured value={String(value)} limit={60} />;
}

function Context({ context }) {
  return (
    <span className="text-xs">
      {Object.entries(context).map(([key, value], index) => (
        <span key={key}>{index > 0 && " · "}<span className="muted">{key}</span> <Captured value={String(value)} limit={60} expandable={false} /></span>
      ))}
    </span>
  );
}

function ClassBlock({ name, label, data, texts }) {
  if (!data) return null;
  return (
    <section className="space-y-1" data-testid={`class-${name}`} data-total={data.total}>
      <h3 className="font-bold">{label} <span className="muted font-normal">({data.total})</span></h3>
      <p className="text-sm" data-testid={`class-text-${name}`}>{data.text}</p>
      {data.total === 0 ? <p className="text-sm muted">{texts.absent}</p> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left border-b border-slate-300">
                <th className="py-1 pr-2">Elemento</th><th className="pr-2">Contexto</th><th className="pr-2">Valor</th>
                <th className="pr-2">Visita 1</th><th className="pr-2">Visita 2</th><th className="pr-2">Visita 3</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item, index) => (
                <tr key={index} className="border-b border-slate-200 align-top" data-testid={`item-${name}`} data-kind={item.kind}>
                  <td className="py-1 pr-2">{item.kind_label}</td>
                  <td className="pr-2"><Context context={item.context} /></td>
                  <td className="pr-2"><Value value={item.value} /></td>
                  {["1", "2", "3"].map((visit) => <td key={visit} className="pr-2" data-testid={`item-visit-${visit}`}>{item.visits[visit]}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {data.items.length < data.total && <p className="muted text-xs">Se muestran {data.items.length} de {data.total}.</p>}
        </div>
      )}
    </section>
  );
}

function ProfileState({ profiles }) {
  const rows = [
    ["Perfil", (item) => item.profile],
    ["Navegador abierto", (item) => formatDate(item.launched_at)],
    ["Navegador cerrado", (item) => formatDate(item.closed_at)],
    ["Cookies al abrir", (item) => orUnavailable(item.start.cookies_at_start)],
    ["Directorio vacío al empezar", (item) => (item.start.files_before_launch === undefined ? "—" : item.start.files_before_launch === 0 ? "sí" : "no")],
    ["Estado en disco igual al de la visita 1", (item) => (item.start.manifest_matches === undefined ? "—" : item.start.manifest_matches ? "sí" : "no")],
    ["Cookies persistentes de la visita 1 que faltaban", (item) => (item.start.persistent_cookies_missing === undefined ? "—" : item.start.persistent_cookies_missing)],
    ["Cookies persistentes al cerrar", (item) => orUnavailable(item.end.persistent_cookies)],
    ["Orígenes con IndexedDB en disco", (item) => (item.end.inventory ? item.end.inventory.indexeddb_origins.length : orUnavailable(null))],
  ];
  const visits = ["1", "2", "3"];
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse" data-testid="profile-state">
        <thead><tr className="text-left border-b border-slate-300"><th className="py-1 pr-2">Estado del perfil</th>{visits.map((visit) => <th key={visit} className="pr-2">Visita {visit}</th>)}</tr></thead>
        <tbody>
          {rows.map(([label, read]) => (
            <tr key={label} className="border-b border-slate-200">
              <td className="py-1 pr-2">{label}</td>
              {visits.map((visit) => <td key={visit} className="pr-2">{profiles[visit] ? String(read(profiles[visit])) : orUnavailable(null)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function VisitComparison({ comparisonId }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [reveal, setReveal] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer = null;
    const load = () => api.comparison(comparisonId, reveal).then((body) => {
      if (!alive) return;
      setData(body);
      setError(null);
      if (body.status === "en_curso") timer = setTimeout(load, POLL_MS);
    }, (failure) => alive && setError(failure));
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [comparisonId, reveal]);

  if (error && !data) return <ErrorNotice error={error} />;
  if (!data) return <Loading what="la comparación" />;
  const result = data.result;

  return (
    <div className="space-y-4" data-testid="comparison-view" data-status={data.status}>
      <Panel title="Comparación de visitas" icon="repeat" subtitle={<Captured value={data.url} limit={110} />}>
        <p className="panel p-3 border-amber-600 bg-amber-50 text-sm" role="note" data-testid="comparison-warning">
          <strong>Advertencia:</strong> {data.warning}
        </p>
        <div className="mt-3 text-sm space-y-1">
          <p data-testid="comparison-validity" data-valid={String(data.validity.valid)}>
            <strong>Validez:</strong> {VALIDITY_LABELS[data.status] || data.status}
          </p>
          {data.validity.reasons.length > 0 && (
            <ul className="list-disc pl-5" data-testid="comparison-reasons">
              {data.validity.reasons.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
          )}
          <p data-testid="comparison-interval-info">
            <strong>Intervalo:</strong> configurado {seconds(data.interval.configured_s)} · real {seconds(data.interval.real_s)}{" "}
            <Info label="Intervalo">Del cierre del navegador en la visita 1 a su apertura en la visita 2.</Info>
          </p>
        </div>
      </Panel>

      <Panel title="Las tres visitas" testId="comparison-visits">
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left border-b border-slate-300">
                <th className="py-1 pr-2">Visita</th><th className="pr-2">Perfil</th><th className="pr-2">Estado</th><th className="pr-2">Requests</th>
                <th className="pr-2">Cookies</th><th className="pr-2">Storage</th><th className="pr-2">Exposición</th><th className="pr-2">Scan</th>
              </tr>
            </thead>
            <tbody>
              {data.visits.map((visit) => (
                <tr key={visit.visit} className="border-b border-slate-200 align-top" data-testid="comparison-visit" data-status={visit.status}>
                  <td className="py-1 pr-2">{visit.visit}</td>
                  <td className="pr-2">{visit.label}</td>
                  <td className="pr-2"><VisitStatus visit={visit} /></td>
                  <td className="pr-2">{orUnavailable(visit.requests)}</td>
                  <td className="pr-2">{orUnavailable(visit.cookies)}</td>
                  <td className="pr-2">{orUnavailable(visit.storage_items)}</td>
                  <td className="pr-2">{visit.site_exposure_score === null ? "—" : <BandBadge band={visit.band} score={visit.site_exposure_score} />}</td>
                  <td className="pr-2">{visit.job_id ? <Link to={["scan", visit.job_id]} testId="comparison-scan-link">Ver scan</Link> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3"><ProfileState profiles={data.profiles} /></div>
        <div className="mt-3 text-sm" data-testid="condition-differences">
          <strong>Condiciones:</strong>{" "}
          {data.condition_differences.length === 0
            ? "las tres visitas registraron las mismas condiciones (URL, Chromium, modo, idioma, zona horaria, protocolo y configuración)."
            : (
              <ul className="list-disc pl-5">
                {data.condition_differences.map((item) => (
                  <li key={item.condition} data-testid="condition-difference">
                    {item.label}: {Object.entries(item.values).map(([visit, value]) => `visita ${visit} = ${String(orUnavailable(value))}`).join(" · ")}
                  </li>
                ))}
              </ul>
            )}
        </div>
      </Panel>

      <Panel title="Resultado" testId="comparison-result"
        actions={(
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={reveal} onChange={(event) => setReveal(event.target.checked)} data-testid="comparison-reveal" />
            <span>Mostrar identificadores completos</span>
          </label>
        )}>
        {!result ? <Empty>{data.status === "en_curso" ? "La comparación aparece cuando terminen y se analicen las tres visitas." : "Sin resultado: falta al menos una visita analizada."}</Empty> : (
          <div className="space-y-4">
            {CLASS_ORDER.map(([name, label]) => <ClassBlock key={name} name={name} label={label} data={result.classes[name]} texts={data.texts} />)}
            <section className="text-sm" data-testid="comparison-discarded">
              <h3 className="font-bold">Descartados</h3>
              <ul className="list-disc pl-5">
                {Object.entries(result.discarded).map(([name, item]) => <li key={name} data-testid={`discarded-${name}`}>{item.reason}: {item.total}</li>)}
              </ul>
            </section>
          </div>
        )}
        <section className="text-sm mt-4" data-testid="comparison-limits">
          <h3 className="font-bold"><Icon name="help" className="w-4 h-4" /> Límites</h3>
          <ul className="list-disc pl-5">{data.limits.map((limit) => <li key={limit}>{limit}</li>)}</ul>
        </section>
      </Panel>
    </div>
  );
}
