import { WhatIsThis } from "../components/Term.jsx";
import { BandBadge, Captured, Empty, ErrorNotice, EvidenceBadge, Link, Loading, Panel, Plain, ServiceTag, TechDetail } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { categoryLabel, entityLabel } from "../lib/format.js";
import { useApi } from "../lib/useApi.js";

const TELEMETRY_KINDS = { path: "ruta de eventos", status_204: "respuesta 204 con datos", known: "analítica propia conocida", script: "script de analítica propia" };

/** Telemetría propia (v1.3.4): eventos enviados al propio sitio o a su misma organización. No son terceros. */
export function FirstPartyTelemetry({ telemetry }) {
  if (!telemetry) return null;  // análisis anterior a v1.3.4: sin la medición, no se inventa «0»
  const rows = [...(telemetry.endpoint_list || []), ...(telemetry.script_list || [])];
  return (
    <Panel title="Telemetría propia" tone="neutral" testId="first-party-telemetry"
      subtitle="Eventos enviados al propio sitio o a su misma organización; no son terceros."
      info={<><strong>Telemetría propia</strong>: se reconoce por la ruta (/count, /metrics, /collect…), por respuestas 204 a envíos con datos y por scripts de analítica propia conocidos. Es una inferencia a partir del patrón, no del contenido.</>}>
      <p className="text-sm mb-2" data-testid="telemetry-counts">
        <EvidenceBadge level="INFERENCIA" /> {telemetry.requests} {telemetry.requests === 1 ? "request de eventos" : "requests de eventos"} hacia {telemetry.endpoints} {telemetry.endpoints === 1 ? "endpoint" : "endpoints"};{" "}
        {telemetry.scripts} {telemetry.scripts === 1 ? "script de analítica propia" : "scripts de analítica propia"}.
      </p>
      {rows.length === 0 ? <Empty>No se detectó telemetría propia en esta captura.</Empty> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left"><th className="pr-2">Host</th><th className="pr-2">Ruta</th><th className="pr-2">Tipo</th><th className="pr-2">Requests</th></tr></thead>
            <tbody>
              {rows.map((item, index) => (
                <tr key={index} className="border-t border-slate-200" data-testid="telemetry-row" data-kind={item.kind}>
                  <td className="py-1 pr-2"><Captured value={item.host} limit={50} expandable={false} /></td>
                  <td className="pr-2"><Captured value={item.path} limit={70} /></td>
                  <td className="pr-2">{TELEMETRY_KINDS[item.kind] || "otro"}{item.name ? <> · <Captured value={item.name} limit={60} expandable={false} /></> : null}</td>
                  <td className="pr-2">{item.requests}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/**
 * Servicios de terceros sin señales de rastreo (v1.4.5): organización, tipo de servicio y requests.
 * Se muestra siempre que el análisis lo midió, también (y sobre todo) cuando no hay rastreadores.
 * Organización, dominios y tipo vienen del análisis: se pintan como texto.
 */
export function ThirdPartyServices({ jobId, services, compact = false }) {
  if (!services || !Array.isArray(services.items)) return null;  // análisis anterior a v1.4.5: no se inventa «0»
  const items = compact ? services.items.slice(0, 8) : services.items;
  return (
    <Panel title="Servicios de terceros sin señales de rastreo" tone="neutral" testId="third-party-services"
      subtitle="Otras organizaciones que la página contacta para funcionar: mapas, fuentes, librerías, antibot, clima, redes sociales."
      info={<><strong>Servicios de terceros sin señales de rastreo</strong>: requests a otra organización que no alcanzaron la banda de rastreador. No mostrar señales no significa que no reciban datos: cada servicio recibe al menos la dirección IP y el navegador del visitante. El tipo de servicio es contexto, no evidencia del uso concreto.</>}>
      <p className="text-sm mb-2" data-testid="third-party-services-counts">
        <EvidenceBadge level={services.level || "EVIDENCIA"} /> {services.requests} {services.requests === 1 ? "request" : "requests"} a {services.organizations}{" "}
        {services.organizations === 1 ? "organización" : "organizaciones"} sin señales de rastreo.
      </p>
      {services.items.length === 0 ? <Empty>En esta visita no hubo requests a terceros sin señales de rastreo.</Empty> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left border-b border-slate-400"><th className="py-1 pr-3">Organización</th><th className="py-1 pr-3">Tipo de servicio</th><th className="py-1 pr-3">Dominios</th><th className="py-1 pr-3">Requests</th>{jobId && !compact ? <th className="py-1">Evidencia</th> : null}</tr></thead>
            <tbody>
              {items.map((item, index) => (
                <tr key={index} className="border-b border-slate-200 align-top" data-testid="third-party-service" data-service={item.service_type || "desconocido"}>
                  <td className="py-1 pr-3" data-testid="third-party-service-org">
                    {entityLabel(item.organization)}
                    {item.in_trackers ? <span className="muted text-xs"> (también en rastreadores)</span> : null}
                    {item.library && item.library.benign ? <span className="muted text-xs" data-testid="third-party-service-benign"> (librería conocida: {item.library.benign_label})</span> : null}
                  </td>
                  <td className="py-1 pr-3"><ServiceTag label={item.service_label} /></td>
                  <td className="py-1 pr-3"><Captured value={(item.hosts && item.hosts.length ? item.hosts : item.domains || []).join(", ")} limit={80} /></td>
                  <td className="py-1 pr-3">{item.requests}</td>
                  {jobId && !compact ? (
                    <td className="py-1">{(item.evidence_refs || []).map((ref) => <span key={ref}><Link to={["scan", jobId, "request", ref]} testId="third-party-service-ref">#{ref}</Link>{" "}</span>)}</td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {compact && services.items.length > items.length ? <p className="muted text-sm mt-1">Se muestran {items.length} de {services.items.length}; la lista completa está en Rastreadores.</p> : null}
      {services.truncated ? <p className="muted text-sm mt-1">La lista se truncó por volumen.</p> : null}
    </Panel>
  );
}

export default function Trackers({ jobId }) {
  const { data, error, loading } = useApi(() => api.report(jobId), `report-${jobId}`);
  if (loading) return <Loading what="los trackers" />;
  if (error) return <ErrorNotice error={error} />;
  const groups = data.trackers;
  return (
    <div className="space-y-4">
    <WhatIsThis panel="trackers" />
    <Panel title="Rastreadores: requests con señales de seguimiento, por organización" subtitle="Requests en banda Moderado o superior." testId="trackers"
      info={<><strong>Rastreadores</strong>: la organización viene de un mapa de dominios; cuando no se conoce, cada dominio se muestra por separado.</>}>
      {groups.length === 0 ? <Empty>Ninguna request alcanzó la banda Moderado en este scan.{data.site.summary.third_party_services ? " Los terceros contactados sin señales de rastreo figuran más abajo." : ""}</Empty> : (
        <div className="space-y-2">
          {groups.map((group, index) => (
            <details key={index} className="panel p-2" data-testid="tracker-group">
              <summary className="cursor-pointer">
                <strong>{entityLabel(group.entity, group.brand)}</strong>{" "}
                <BandBadge band={group.max_band} score={group.max_score} />{" "}
                <span className="muted text-sm">
                  {group.request_count} requests · {group.categories.map(categoryLabel).join(", ")} ·{" "}
                </span>
                <span className="captured text-sm">{group.domains.join(", ")}</span>
                <div><ServiceTag label={group.service_label} /></div>
              </summary>
              <p className="muted text-sm mt-2" data-testid="tracker-rows">
                {groupTrackerRequests(group.requests).length} {groupTrackerRequests(group.requests).length === 1 ? "fila" : "filas"} para {group.requests.length} requests (mismo tipo de señal en una fila).
              </p>
              {groupTrackerRequests(group.requests).map((bundle) => (bundle.requests.length === 1 ? null : (
                <details key={bundle.signal} className="panel p-2 mt-2 text-sm" data-testid="tracker-bundle" data-signal={bundle.signal}>
                  <summary className="cursor-pointer">
                    {bundle.requests[0].plain && <Plain text={bundle.requests[0].plain.text} level={bundle.requests[0].plain.level} inline testId="tracker-bundle-plain" />}{" "}
                    <strong data-testid="tracker-bundle-count">× {bundle.requests.length}</strong>{" "}
                    <span className="muted">({bundle.requests.length} requests · {bundle.values} direcciones distintas)</span>
                  </summary>
                  <TrackerRequests jobId={jobId} requests={bundle.requests} />
                </details>
              )))}
              <TrackerRequests jobId={jobId} requests={groupTrackerRequests(group.requests).filter((bundle) => bundle.requests.length === 1).map((bundle) => bundle.requests[0])} />
            </details>
          ))}
        </div>
      )}
    </Panel>
    <ThirdPartyServices jobId={jobId} services={data.site.summary.third_party_services} />
    <FirstPartyTelemetry telemetry={data.site.summary.first_party_telemetry} />
    <AccountIds jobId={jobId} items={(data.site.summary && data.site.summary.account_ids) || []} />
    </div>
  );
}

/**
 * Requests de una organización agrupadas por tipo de señal (v1.4.2): las repetidas van en una fila con su conteo
 * y cuántas direcciones distintas (URL sin query) reúnen.
 */
export function groupTrackerRequests(requests) {
  const bundles = new Map();
  for (const request of requests) {
    const signal = (request.plain && request.plain.signal) || "sin_senal";
    if (!bundles.has(signal)) bundles.set(signal, { signal, requests: [], urls: new Set() });
    const bundle = bundles.get(signal);
    bundle.requests.push(request);
    bundle.urls.add(String(request.url || "").split("?")[0]);
  }
  return [...bundles.values()].map((bundle) => ({ signal: bundle.signal, requests: bundle.requests, values: bundle.urls.size }));
}

/** Filas visibles de «Rastreadores» para un reporte: una por grupo de señal dentro de cada organización. */
export function trackerRowCount(groups) {
  return groups.reduce((total, group) => total + groupTrackerRequests(group.requests).length, 0);
}

function TrackerRequests({ jobId, requests }) {
  if (requests.length === 0) return null;
  return (
              <table className="w-full text-sm mt-2">
                <tbody>
                  {requests.map((request) => (
                    <tr key={request.request_id} className="border-t border-slate-200 align-top">
                      <td className="py-1 pr-2"><BandBadge band={request.band} score={request.score} /></td>
                      <td className="pr-2"><Link to={["scan", jobId, "request", request.request_id]}>ver</Link></td>
                      <td>
                        {request.plain && <Plain text={request.plain.text} level={request.plain.level} inline testId="tracker-plain" />}
                        <div className="mt-1">
                          <TechDetail testId="tracker-detail">
                            <div>
                              <Captured value={request.url} limit={110} />
                              <ul className="mt-1">
                                {request.reasons.slice(0, 4).map((reason, reasonIndex) => (
                                  <li key={reasonIndex}><EvidenceBadge level={reason.level} /> <Captured value={reason.detail} limit={160} /></li>
                                ))}
                              </ul>
                            </div>
                          </TechDetail>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
  );
}

/** «ID de cuenta del sitio» (v1.2): identifican al sitio ante el proveedor, no al visitante. Valores capturados = texto. */
function AccountIds({ jobId, items }) {
  if (!items.length) return null;
  return (
    <Panel title="ID de cuenta del sitio" subtitle="Identifican al sitio ante cada proveedor; son iguales para todo visitante." testId="account-ids"
      info={<><strong>ID de cuenta del sitio</strong>: ID de medición, contenedor o pixel que el sitio configuró con su proveedor. No sirve para reconocer a una persona, así que no cuenta como identificador persistente ni como sincronización entre organizaciones.</>}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="text-left border-b border-slate-400"><th className="py-1 pr-3">Proveedor</th><th className="py-1 pr-3">Tipo</th><th className="py-1 pr-3">Valor</th><th className="py-1 pr-3">Nivel</th><th className="py-1">Evidencia</th></tr></thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.rule}-${item.value}`} className="border-b border-slate-200 align-top" data-testid="account-id" data-rule={item.rule}>
                <td className="py-1 pr-3">{item.vendor}</td>
                <td className="py-1 pr-3">{item.label}</td>
                <td className="py-1 pr-3"><Captured value={item.value} limit={48} /></td>
                <td className="py-1 pr-3"><EvidenceBadge level={item.level} /></td>
                <td className="py-1">
                  {(item.evidence_refs || []).map((ref) => <span key={ref}><Link to={["scan", jobId, "request", ref]} testId="account-id-ref">#{ref}</Link>{" "}</span>)}
                  <span className="muted">{item.requests} {item.requests === 1 ? "request" : "requests"}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
