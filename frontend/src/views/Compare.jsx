// Comparar un scan (navegador del worker) con una captura HAR importada (navegador del usuario). v1.3.
import { useEffect, useState } from "react";

import { Captured, Empty, ErrorNotice, EvidenceBadge, Loading } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { formatDate } from "../lib/format.js";

function Organizations({ title, items, testId }) {
  return (
    <div data-testid={testId}>
      <h3 className="font-bold">{title} ({items.length})</h3>
      {items.length === 0 ? <Empty>Ninguna.</Empty> : (
        <ul className="text-sm list-disc pl-5">
          {items.slice(0, 40).map((item) => (
            <li key={item.organization}>
              <Captured value={item.organization} limit={50} expandable={false} /> — {item.requests} {item.requests === 1 ? "request" : "requests"}
              {item.blocked ? ` (${item.blocked} bloqueadas por una extensión)` : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function waveText(wave) {
  if (!wave || wave.available === false) return "medición no disponible (reanalice la captura)";
  if (!wave.detected) return "no se observó";
  return `${wave.requests} requests a ${wave.organizations} organizaciones, iniciada por ${wave.initiator || "origen no identificado"}`;
}

const count = (value) => (value === null || value === undefined ? "no disponible" : value);

export default function Compare({ jobId, source }) {
  const [candidates, setCandidates] = useState(null);
  const [other, setOther] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const wantsHar = source !== "har_import";

  useEffect(() => {
    let alive = true;
    setCandidates(null); setResult(null); setError(null);
    api.compareCandidates(jobId).then(
      (data) => { if (alive) { setCandidates(data.candidates); setOther(data.candidates.length ? data.candidates[0].job_id : ""); } },
      (failure) => alive && setError(failure),
    );
    return () => { alive = false; };
  }, [jobId]);

  const run = () => {
    setError(null); setResult(null);
    api.compare(jobId, other).then(setResult, setError);
  };

  if (error && !candidates) return <ErrorNotice error={error} />;
  if (!candidates) return <Loading what="las capturas comparables" />;
  return (
    <div className="space-y-3" data-testid="compare">
      {candidates.length === 0 ? (
        <Empty>{wantsHar ? "Aún no hay capturas HAR importadas y analizadas. Importe una en «Analizar un sitio»." : "Aún no hay scans analizados con los que comparar."}</Empty>
      ) : (
        <div className="flex flex-wrap items-end gap-2">
          <div>
            <label htmlFor="compare-other" className="block text-sm font-medium">{wantsHar ? "Captura HAR importada" : "Scan"}</label>
            <select id="compare-other" className="border border-slate-400 rounded px-2 py-1 bg-white max-w-full" value={other}
              onChange={(event) => setOther(event.target.value)} data-testid="compare-select">
              {candidates.map((item) => (
                <option key={item.job_id} value={item.job_id}>
                  {formatDate(item.finished_at)} · {String(item.url).slice(0, 60)} · {item.requests} requests{item.same_site ? "" : " (otro sitio)"}
                </option>
              ))}
            </select>
          </div>
          <button type="button" className="btn btn-primary" onClick={run} disabled={!other} data-testid="compare-run">Comparar</button>
        </div>
      )}
      <ErrorNotice error={error} />
      {result && (
        <div className="space-y-3" data-testid="compare-result">
          <p className="font-medium" data-testid="compare-conclusion">
            <EvidenceBadge level={result.conclusion.level} /> {result.conclusion.text}
          </p>
          <p className="muted text-sm">{result.note}</p>
          <div className="grid gap-4 md:grid-cols-2">
            <Organizations title="Organizaciones solo en el HAR importado" items={result.organizations.only_har} testId="compare-only-har" />
            <Organizations title="Organizaciones solo en el scan" items={result.organizations.only_scan} testId="compare-only-scan" />
          </div>
          <p className="text-sm">Organizaciones en ambas capturas: {result.organizations.both.length}. Requests: {result.har.requests} en el HAR y {result.scan.requests} en el scan.</p>
          {result.tracking && (
            <div data-testid="compare-tracking">
              <h3 className="font-bold">Requests de rastreo y organizaciones</h3>
              <table className="text-sm">
                <thead><tr className="text-left"><th className="pr-4"></th><th className="pr-4">HAR importado</th><th>Scan</th></tr></thead>
                <tbody>
                  <tr><td className="pr-4">Requests de rastreo</td><td className="pr-4" data-testid="compare-trackers-har">{count(result.tracking.har.trackers)}</td><td data-testid="compare-trackers-scan">{count(result.tracking.scan.trackers)}</td></tr>
                  <tr><td className="pr-4">Organizaciones de terceros</td><td className="pr-4">{count(result.tracking.har.organizations)}</td><td>{count(result.tracking.scan.organizations)}</td></tr>
                </tbody>
              </table>
              {result.tracking.scan.possibly_blocked && <p className="text-sm font-medium" data-testid="compare-scan-blocked">El scan está marcado como visita posiblemente bloqueada.</p>}
              <p className="muted text-sm" data-testid="compare-index-note">{result.tracking.index_note}</p>
            </div>
          )}
          <div data-testid="compare-wave" data-state={result.sync_wave.state}>
            <h3 className="font-bold">Ola de sincronización</h3>
            <ul className="text-sm list-disc pl-5">
              <li>HAR importado: {waveText(result.sync_wave.har)}.</li>
              <li>Scan: {waveText(result.sync_wave.scan)}.</li>
            </ul>
          </div>
          <div data-testid="compare-blocked">
            <h3 className="font-bold">Bloqueadas por una extensión del navegador ({result.blocked_by_extension.requests})</h3>
            {result.blocked_by_extension.organizations.length === 0 ? <Empty>Ninguna request de terceros bloqueada en el HAR.</Empty> : (
              <ul className="text-sm list-disc pl-5">
                {result.blocked_by_extension.organizations.map((item) => (
                  <li key={item.organization}><Captured value={item.organization} limit={50} expandable={false} /> — {item.requests}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
