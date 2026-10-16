import { useEffect, useState } from "react";

import { DeletedNotice, DeleteScanButton } from "../components/HistoryControls.jsx";
import { Icon } from "../components/Icons.jsx";
import ReportDownloads from "../components/ReportDownloads.jsx";
import StageProgress from "../components/StageProgress.jsx";
import { Captured, ErrorNotice, Link, Loading, NoMeasurement, Panel, PartialScanNotice } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { errorMessage, formatDate, isFinished, scanStage, stageLabel } from "../lib/format.js";
import Compare from "./Compare.jsx";
import Dashboard from "./Dashboard.jsx";
import Findings from "./Findings.jsx";
import Fingerprinting from "./Fingerprinting.jsx";
import { loadTime } from "./HarImport.jsx";
import RequestDetail from "./RequestDetail.jsx";
import RequestsTable from "./RequestsTable.jsx";
import Trackers from "./Trackers.jsx";

// Menú del scan, en el orden de lectura sugerido (de arriba hacia abajo): nombre técnico y
// subtítulo técnico de una línea.
export const TABS = [
  { id: "", key: "summary", icon: "photo", title: "Resumen", technical: null, subtitle: "Índice de exposición, terceros contactados y categorías de datos" },
  { id: "findings", key: "findings", icon: "steps", title: "Hallazgos", technical: null, subtitle: "Ocho grupos técnicos, con nivel de evidencia y requests de respaldo" },
  { id: "trackers", key: "trackers", icon: "footprints", title: "Rastreadores", technical: null, subtitle: "Requests con señales de seguimiento, agrupadas por organización" },
  { id: "fingerprinting", key: "fingerprinting", icon: "device", title: "Fingerprinting", technical: null, subtitle: "Lectura de atributos del dispositivo mediante APIs del navegador" },
  { id: "requests", key: "requests", icon: "traffic", title: "Tráfico", technical: "requests", subtitle: "Todas las requests capturadas durante la visita" },
];

export function TabMenu({ jobId, active }) {
  return (
    <nav aria-label="Secciones del scan" data-testid="tab-menu">
      <ol className="tabmenu">
        {TABS.map((tab, index) => (
          <li key={tab.key}>
            <a className="tab" href={`#/scan/${encodeURIComponent(jobId)}${tab.id ? `/${tab.id}` : ""}`} aria-current={active === tab.id ? "page" : undefined} data-testid={`tab-${tab.key}`}>
              <span className="tab-number" aria-hidden="true">{index + 1}</span>
              <Icon name={tab.icon} className="tab-icon" />
              <span>
                <span className="tab-title" data-testid="tab-title">
                  {tab.title}{tab.technical && <span className="tab-technical" data-testid="tab-technical"> ({tab.technical})</span>}
                </span>
                <span className="tab-subtitle" data-testid="tab-subtitle">{tab.subtitle}</span>
              </span>
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}

export default function Scan({ jobId, tab, requestId, query }) {
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const [deleted, setDeleted] = useState(null);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer = null;
    setScan(null);
    setError(null);
    setDeleted(null);
    const poll = () => {
      api.scan(jobId).then(
        (data) => {
          if (!alive) return;
          setScan(data);
          if (!isFinished(data)) timer = setTimeout(poll, 700);
        },
        (failure) => alive && setError(failure),
      );
    };
    poll();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [jobId]);

  if (deleted) {
    return (
      <div className="space-y-3">
        <DeletedNotice result={deleted} />
        <p><Link to={[]} testId="back-home">← Volver al inicio</Link></p>
      </div>
    );
  }
  if (error) return <ErrorNotice error={error} />;
  if (!scan) return <Loading what="el scan" />;
  const stage = scanStage(scan);
  const failure = stage === "failed" ? scan.error || {} : null;
  // v1.4.8 (docs/adr/035): un scan fallido no es una medición. Lo capturado antes del fallo se ve como tráfico,
  // pero sin índice, resumen ni pestañas que digan «no se observó».
  const unmeasured = scan.status === "failed";
  const hasAnalysis = scan.analysis_status === "completed" && !unmeasured;
  // v1.3: captura importada (HAR) y exportación a HAR.
  const imported = scan.source === "har_import";
  const importMeta = imported && scan.result ? scan.result.import : null;
  const hasCapture = scan.status === "completed";

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold" data-testid="scan-url"><Captured value={scan.url} limit={90} /></h1>
            {scan.url_cleaned && (
              <p className="muted text-sm" data-testid="scan-url-cleaned">
                URL limpiada antes de escanear: se quitaron {scan.removed_params.map((name, index) => <span key={name}>{index > 0 && ", "}<span className="captured">{name}</span></span>)}.{" "}
                Original: <span data-testid="scan-original-url"><Captured value={scan.original_url} limit={70} /></span>
              </p>
            )}
            {scan.source === "interactive" && (
              <p className="text-sm font-bold" data-testid="scan-interactive-label">
                captura interactiva{scan.result && scan.result.interactive && Array.isArray(scan.result.interactive.timeline)
                  ? ` · ${scan.result.interactive.timeline.length} ${scan.result.interactive.timeline.length === 1 ? "página" : "páginas"}` : ""}
              </p>
            )}
            {scan.result && scan.result.title ? <p className="muted" data-testid="scan-title">Título: <Captured value={scan.result.title} limit={100} /></p> : null}
            <p className="muted text-sm">Creado: {formatDate(scan.created_at)} · estado: <span data-testid="scan-stage" data-stage={stage}>{stageLabel(stage)}</span></p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {hasAnalysis && (
              <a className="btn btn-primary" href={api.reportUrl(jobId)} download={`reporte-${jobId}.json`} data-testid="export">
                Exportar reporte (JSON)
              </a>
            )}
            {hasCapture && (
              <a className="btn" href={api.harExportUrl(jobId)} download={`scan-${jobId}.har`} data-testid="export-har"
                title="Sin las cabeceras Cookie, Set-Cookie ni Authorization">
                Descargar HAR
              </a>
            )}
            {hasAnalysis && (
              <button type="button" className="btn" onClick={() => setComparing(!comparing)} aria-expanded={comparing} data-testid="compare-toggle">
                {imported ? "Comparar con un scan" : "Comparar con HAR importado"}
              </button>
            )}
            {scan.can_delete !== false && <DeleteScanButton jobId={jobId} onDeleted={setDeleted} />}
          </div>
        </div>
        {imported && (
          <p className="mt-3 text-sm" role="note" data-testid="har-banner">
            <strong>Captura importada: navegador real del usuario.</strong> Sin fingerprinting instrumentado (un HAR solo registra tráfico de red).
            {importMeta && (
              <>
                {" "}Carga analizada: {loadTime((importMeta.load || {}).started_at)} · {importMeta.entries_load} requests ·{" "}
                <span data-testid="har-blocked">{importMeta.blocked_by_client} bloqueadas por una extensión del navegador</span> ·{" "}
                <span data-testid="har-removed">
                  cabeceras sensibles descartadas: Cookie {(importMeta.sensitive_removed || {}).cookie}, Set-Cookie {(importMeta.sensitive_removed || {}).set_cookie},
                  Authorization {(importMeta.sensitive_removed || {}).authorization}
                </span>.
              </>
            )}
          </p>
        )}
        <PartialScanNotice partial={scan.partial_navigation} />
        {hasAnalysis && <div className="mt-3"><ReportDownloads subject="scan" subjectId={jobId} /></div>}
        {hasAnalysis && comparing && <div className="mt-3 border-t border-slate-300 pt-3"><Compare jobId={jobId} source={scan.source} /></div>}
      </Panel>

      {(stage !== "done" || !hasAnalysis) && (
        <StageProgress progress={scan.progress}>
          {failure && <NoMeasurement failure={scan.failure || failure} message={errorMessage(failure)} />}
        </StageProgress>
      )}

      {unmeasured && scan.analysis_status === "completed" && (
        <Panel title="Requests capturadas antes del fallo" subtitle="Tráfico registrado hasta que la navegación falló; no es una medición del sitio." testId="failed-capture">
          {requestId ? <RequestDetail jobId={jobId} requestId={requestId} /> : <RequestsTable jobId={jobId} query={query} />}
        </Panel>
      )}

      {hasAnalysis && (
        <div className="grid gap-4 lg:grid-cols-[17rem_minmax(0,1fr)] items-start">
          <TabMenu jobId={jobId} active={requestId ? "requests" : tab || ""} />
          <div className="min-w-0">
            {requestId ? <RequestDetail jobId={jobId} requestId={requestId} />
              : tab === "requests" ? <RequestsTable jobId={jobId} query={query} />
              : tab === "trackers" ? <Trackers jobId={jobId} />
              : tab === "fingerprinting" ? <Fingerprinting jobId={jobId} query={query} />
              : tab === "findings" ? <Findings jobId={jobId} query={query} />
              : <Dashboard jobId={jobId} progress={scan.progress} />}
          </div>
        </div>
      )}
    </div>
  );
}
