// Historial (v1.2): scans y grupos de Opciones avanzadas, con filtros (fecha, sitio, estado) y
// los botones de borrar uno y borrar todo. Las URLs capturadas son texto, nunca enlaces externos.
import { useCallback, useEffect, useState } from "react";

import { DeleteAllHistory, DeletedNotice, DeleteScanButton } from "../components/HistoryControls.jsx";
import { BandBadge, Captured, Empty, Link, NO_MEASUREMENT, Panel, PARTIAL_SCAN } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { formatBytes, formatDate, scanStage, stageLabel } from "../lib/format.js";

const STATUS_OPTIONS = [["", "Todos"], ["done", "Finalizados"], ["active", "En curso"], ["failed", "Fallidos"]];
const GROUP_STATUS = { done: "Finalizado", active: "En curso", failed: "Fallido" };
const EMPTY_FILTERS = { site: "", status: "", date_from: "", date_to: "" };
const INPUT = "border border-slate-400 rounded px-2 py-1 bg-white text-sm";

function Filters({ value, onChange }) {
  const set = (key) => (event) => onChange({ ...value, [key]: event.target.value });
  const active = Object.values(value).some(Boolean);
  return (
    <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => event.preventDefault()} data-testid="history-filters">
      <label className="text-sm">
        <span className="block font-medium">Sitio</span>
        <input type="search" className={`${INPUT} captured`} value={value.site} onChange={set("site")} maxLength={200} placeholder="ejemplo.cl" autoComplete="off" spellCheck={false} data-testid="filter-site" />
      </label>
      <label className="text-sm">
        <span className="block font-medium">Estado</span>
        <select className={INPUT} value={value.status} onChange={set("status")} data-testid="filter-status">
          {STATUS_OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
      </label>
      <label className="text-sm">
        <span className="block font-medium">Desde</span>
        <input type="date" className={INPUT} value={value.date_from} onChange={set("date_from")} data-testid="filter-from" />
      </label>
      <label className="text-sm">
        <span className="block font-medium">Hasta</span>
        <input type="date" className={INPUT} value={value.date_to} onChange={set("date_to")} data-testid="filter-to" />
      </label>
      <button type="button" className="btn text-sm" disabled={!active} onClick={() => onChange(EMPTY_FILTERS)} data-testid="filter-clear">Quitar filtros</button>
    </form>
  );
}

function Site({ item, to, testId }) {
  return (
    <>
      <Link to={to} testId={testId}><Captured value={item.url} limit={70} expandable={false} /></Link>
      {item.source === "har_import" && <span className="muted text-xs" data-testid="history-har"> · captura importada (HAR)</span>}
      {item.source === "interactive" && <span className="muted text-xs" data-testid="history-interactive"> · captura interactiva</span>}
      {item.blocked && (
        <div data-testid="history-blocked">
          <span className="badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold bg-amber-100 text-amber-900 border-amber-700">
            visita posiblemente bloqueada
          </span>
        </div>
      )}
      {!item.blocked && item.partial_block && (
        <div data-testid="history-partial-block">
          <span className="badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold bg-sky-100 text-sky-900 border-sky-700">
            bloqueo parcial: un componente mostró verificación antibot
          </span>
        </div>
      )}
      {item.title && <div className="muted"><Captured value={item.title} limit={70} /></div>}
      {item.url_cleaned && (
        <div className="muted text-xs" data-testid="url-cleaned">
          URL limpiada: se quitaron {item.removed_params.map((name, index) => <span key={name}>{index > 0 && ", "}<span className="captured">{name}</span></span>)}
        </div>
      )}
    </>
  );
}

export default function History() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [scans, setScans] = useState(null);
  const [groups, setGroups] = useState(null);
  const [stats, setStats] = useState(null);
  const [deleted, setDeleted] = useState(null);

  const load = useCallback((alive = () => true) => {
    api.listScans(100, filters).then((data) => alive() && setScans(data), () => alive() && setScans({ items: [], total: 0 }));
    api.listTests(50, filters).then((data) => alive() && setGroups(data.items), () => alive() && setGroups([]));
    api.history().then((data) => alive() && setStats(data), () => alive() && setStats(null));
  }, [filters]);

  useEffect(() => {
    let alive = true;
    const run = () => load(() => alive);
    // Pequeña espera: al escribir en «Sitio» no se consulta por cada tecla.
    const first = setTimeout(run, 200);
    const timer = setInterval(run, 5000);
    return () => { alive = false; clearTimeout(first); clearInterval(timer); };
  }, [load]);

  const onDeleted = (result) => { setDeleted(result); load(); };
  const canDelete = Boolean(stats && stats.delete_enabled);

  return (
    <div className="space-y-4" data-testid="history-view">
      <Panel title="Historial" subtitle="Scans y grupos de Opciones avanzadas guardados en esta instalación.">
        {/* Misma disposición que «Analizar un sitio»: imagen propia, servida localmente (CSP sin cambios). */}
        <div className="analyze-layout">
          <div>
            <Filters value={filters} onChange={setFilters} />
            <div className="mt-3"><DeletedNotice result={deleted} /></div>
          </div>
          <picture className="analyze-art" data-testid="history-art">
            <source srcSet="/historial-720.webp" type="image/webp" />
            <img src="/historial-720.jpg" width="720" height="720" loading="lazy" decoding="async"
              alt="Ilustración del Historial: un pingüino con gorro y audífonos revisa una larga lista de sitios en su portátil" />
          </picture>
        </div>
      </Panel>

      <Panel title="Scans" subtitle={scans ? `${scans.items.length} de ${scans.total} con estos filtros` : "Cargando…"} testId="recent">
        {scans === null ? <Empty>Cargando…</Empty> : scans.items.length === 0 ? <Empty>No hay scans con estos filtros.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="text-left border-b border-slate-300">
                  <th className="py-1 pr-2">Sitio</th><th className="pr-2">Estado</th><th className="pr-2">Exposición</th>
                  <th className="pr-2">Requests de rastreo</th><th className="pr-2">Fecha</th>{canDelete && <th>Borrar</th>}
                </tr>
              </thead>
              <tbody>
                {scans.items.map((scan) => (
                  <tr key={scan.job_id} className="border-b border-slate-200 align-top" data-testid="recent-row">
                    <td className="py-1 pr-2">
                      <Site item={scan} to={["scan", scan.job_id]} testId="recent-scan" />
                      {scan.group_id && <div className="text-xs"><Link to={["privacy", scan.group_id]} testId="scan-group">Parte de un grupo de Opciones avanzadas</Link></div>}
                    </td>
                    <td className="pr-2">{stageLabel(scanStage(scan))}{scan.error_code && <div className="captured text-xs">{String(scan.error_code)}</div>}</td>
                    <td className="pr-2">
                      {scan.measured === false
                        ? <span data-testid="history-no-measurement">{NO_MEASUREMENT}{scan.net_error && <div className="captured text-xs">{String(scan.net_error)}</div>}</span>
                        : scan.site_exposure_score === null ? <span className="muted">sin análisis</span> : <BandBadge band={scan.band} score={scan.site_exposure_score} partial={scan.source === "har_import"} />}
                      {scan.partial_navigation && <div className="text-xs" data-testid="history-partial-scan">{PARTIAL_SCAN.toLowerCase()}</div>}
                    </td>
                    <td className="pr-2">{scan.trackers === null ? "—" : scan.trackers}</td>
                    <td className="pr-2 whitespace-nowrap">{formatDate(scan.created_at)}</td>
                    {canDelete && <td><DeleteScanButton jobId={scan.job_id} onDeleted={onDeleted} compact /></td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Grupos de Opciones avanzadas" subtitle="Cada grupo reúne varios scans del mismo sitio (consentimiento × perfil × corridas)." testId="history-groups">
        {groups === null ? <Empty>Cargando…</Empty> : groups.length === 0 ? <Empty>No hay grupos con estos filtros.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="text-left border-b border-slate-300">
                  <th className="py-1 pr-2">Sitio</th><th className="pr-2">Estado</th><th className="pr-2">Scans</th><th className="pr-2">Fallidos</th><th className="pr-2">Fecha</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => (
                  <tr key={group.group_id} className="border-b border-slate-200 align-top" data-testid="group-row" data-status={group.status}>
                    <td className="py-1 pr-2"><Site item={group} to={["privacy", group.group_id]} testId="group-link" /></td>
                    <td className="pr-2">{GROUP_STATUS[group.status] || "Desconocido"}</td>
                    <td className="pr-2">{group.done} de {group.total}</td>
                    <td className="pr-2">{group.failed}</td>
                    <td className="pr-2 whitespace-nowrap">{formatDate(group.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {stats && (
        <Panel title="Datos guardados" testId="history">
          <p className="text-sm mb-2">
            <strong data-testid="history-scans">{stats.scans}</strong> scans · <strong>{stats.groups}</strong> grupos de Opciones avanzadas ·{" "}
            <strong>{stats.reports}</strong> archivos de reporte · <strong data-testid="history-disk">{formatBytes(stats.disk_bytes)}</strong> en disco
          </p>
          <DeleteAllHistory stats={stats} onDeleted={onDeleted} />
        </Panel>
      )}
    </div>
  );
}
