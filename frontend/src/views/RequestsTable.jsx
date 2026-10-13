import { useEffect, useRef, useState } from "react";

import { Term, WhatIsThis } from "../components/Term.jsx";
import { BandBadge, Captured, Empty, ErrorNotice, Link, Loading, Panel, Plain } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { BANDS, buildQuery, categoryLabel, CATEGORY_LABELS, partyLabel, requestOutcome, sanitizeRequestFilters } from "../lib/format.js";
import { navigate } from "../lib/router.js";
import { useApi } from "../lib/useApi.js";

const MECHANISMS = ["pixel", "beacon", "fetch/xhr", "script", "iframe", "image", "static", "document", "other"];

function Select({ label, value, onChange, options, testId }) {
  return (
    <label className="text-sm">
      <span className="block muted">{label}</span>
      <select className="border border-slate-400 rounded px-1 py-1 bg-white" value={value || ""} onChange={(event) => onChange(event.target.value)} data-testid={testId}>
        <option value="">Todos</option>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>{optionLabel}</option>
        ))}
      </select>
    </label>
  );
}

export default function RequestsTable({ jobId, query }) {
  const filters = sanitizeRequestFilters(query);
  const queryString = buildQuery({ page_size: 50, ...filters });
  const { data, error, loading } = useApi(() => api.requests(jobId, queryString), `${jobId}${queryString}`);
  const [domain, setDomain] = useState(filters.domain || "");
  const [renderMs, setRenderMs] = useState(null);
  const received = useRef(0);

  // Tiempo desde que llegan los datos hasta que el navegador pinta la tabla.
  useEffect(() => {
    if (!data) return undefined;
    received.current = performance.now();
    const frame = requestAnimationFrame(() => setRenderMs(Math.round(performance.now() - received.current)));
    return () => cancelAnimationFrame(frame);
  }, [data]);

  const update = (changes) => navigate(["scan", jobId, "requests"], { ...filters, page: 1, ...changes });
  const page = filters.page || 1;
  const pageSize = filters.page_size || 50;
  const pages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1;
  const sort = filters.sort || "time";
  const sortLink = (key, label) => (
    <button type="button" className="link" onClick={() => update({ sort: sort === key ? `-${key}` : key })} data-testid={`sort-${key}`}>
      {label}{sort === key ? " ▲" : sort === `-${key}` ? " ▼" : ""}
    </button>
  );

  return (
    <div className="space-y-4">
    <WhatIsThis panel="traffic" />
    <Panel title="Tráfico: requests capturadas durante la visita" testId="requests">
      <form className="flex flex-wrap items-end gap-3 mb-3" onSubmit={(event) => { event.preventDefault(); update({ domain }); }}>
        <Select label="Banda" value={filters.band} onChange={(band) => update({ band })} options={BANDS.map((band) => [band, band])} testId="filter-band" />
        <Select label="Categoría" value={filters.category} onChange={(category) => update({ category })} options={Object.entries(CATEGORY_LABELS)} testId="filter-category" />
        <Select label="Mecanismo" value={filters.mechanism} onChange={(mechanism) => update({ mechanism })} options={MECHANISMS.map((item) => [item, item])} testId="filter-mechanism" />
        <Select label="Origen" value={filters.third_party} onChange={(value) => update({ third_party: value })} options={[["true", "Terceros"], ["false", "Propio del sitio"]]} testId="filter-third" />
        <Select label="Bloqueadas por el proxy" value={filters.blocked} onChange={(blocked) => update({ blocked })} options={[["true", "Sí"], ["false", "No"]]} testId="filter-blocked" />
        <label className="text-sm">
          <span className="block muted">Dominio contiene</span>
          <input className="border border-slate-400 rounded px-2 py-1 captured" value={domain} maxLength={255} onChange={(event) => setDomain(event.target.value)} data-testid="filter-domain" />
        </label>
        <button type="submit" className="rounded border border-slate-500 px-3 py-1">Buscar</button>
        <Select label="Por página" value={String(pageSize)} onChange={(size) => update({ page_size: size || 50 })} options={[["25", "25"], ["50", "50"], ["100", "100"], ["200", "200"]]} testId="page-size" />
      </form>

      {loading && <Loading what="las requests" />}
      <ErrorNotice error={error} />
      {data && (
        <>
          <p className="text-sm mb-2">
            <strong data-testid="requests-total">{data.total}</strong> requests · página <span data-testid="page-current">{page}</span> de <span data-testid="page-count">{pages}</span>
            {renderMs !== null && <span className="muted"> · render: <span data-testid="render-ms">{renderMs}</span> ms</span>}
          </p>
          {data.items.length === 0 ? <Empty>Ninguna request coincide con los filtros.</Empty> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-collapse" data-testid="requests-table">
                <thead>
                  <tr className="text-left border-b border-slate-400">
                    <th className="py-1 pr-2">{sortLink("time", "#")}</th><th className="pr-2">{sortLink("score", "Score")}</th>
                    <th className="pr-2">Método</th><th className="pr-2">Descripción · URL de la <Term id="request">request</Term></th><th className="pr-2">Categoría</th>
                    <th className="pr-2">Mecanismo (<Term id="pixel">pixel</Term>, <Term id="beacon">beacon</Term>…)</th>
                    <th className="pr-2">Origen (<Term id="tercero">tercero</Term> o propio)</th><th>Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.request_id} className="border-b border-slate-200 align-top" data-testid="request-row">
                      <td className="py-1 pr-2"><Link to={["scan", jobId, "request", item.request_id]} testId="request-link">{item.seq + 1}</Link></td>
                      <td className="pr-2"><BandBadge band={item.band} score={item.score} /></td>
                      <td className="pr-2 captured">{item.method}</td>
                      <td className="pr-2">
                        {item.plain && <Plain text={item.plain.text} level={item.plain.level} inline testId="request-plain" />}
                        <div className="mt-1"><Captured value={item.url} limit={90} /></div>
                      </td>
                      <td className="pr-2">{item.category ? categoryLabel(item.category) : "—"}</td>
                      <td className="pr-2">{item.mechanism || "—"}</td>
                      <td className="pr-2">{partyLabel(item, { short: true })}</td>
                      <td>{requestOutcome(item)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <nav className="flex items-center gap-3 mt-3" aria-label="Paginación">
            <button type="button" className="rounded border border-slate-500 px-3 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => update({ page: page - 1 })} data-testid="page-prev">Anterior</button>
            <button type="button" className="rounded border border-slate-500 px-3 py-1 disabled:opacity-40" disabled={page >= pages} onClick={() => update({ page: page + 1 })} data-testid="page-next">Siguiente</button>
            <button type="button" className="rounded border border-slate-500 px-3 py-1 disabled:opacity-40" disabled={page >= pages} onClick={() => update({ page: pages })} data-testid="page-last">Última</button>
          </nav>
        </>
      )}
    </Panel>
    </div>
  );
}
