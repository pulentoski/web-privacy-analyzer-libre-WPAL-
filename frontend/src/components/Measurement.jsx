// Condiciones de la medición, protocolo de visita y cobertura por contexto (v1.5.0, docs/adr/038).
// Todo viene del reporte (sección `measurement`); los textos de motivos ya llegan redactados desde la api.
import { Captured, Panel } from "./ui.jsx";
import { formatDate } from "../lib/format.js";

const MODE_LABELS = { headful: "con ventana (headful)", headless: "headless", no_aplica: "no aplica", no_disponible: "no disponible" };
const STAGE_LABELS = { carga: "Carga", espera: "Espera", scroll: "Scroll hasta el final", cierre: "Cierre de la pestaña" };

const value = (text) => (text === null || text === undefined || text === "no_disponible" ? "no disponible" : text);

function planned(stage) {
  const plan = stage.planned || {};
  if (plan.duration_s !== undefined) return `${plan.duration_s} s`;
  if (plan.max_s !== undefined) return `máx. ${plan.max_s} s`;
  if (plan.observe_s !== undefined) return `${plan.observe_s} s tras cerrar`;
  return "load + red en calma";
}

export function countryText(country) {
  if (!country || country.status !== "ok") return `desconocido${country && country.reason ? ` (${country.reason})` : ""}`;
  return `${country.country} (${country.country_code})${country.source ? ` · ${country.source}` : ""}`;
}

export function MeasurementPanel({ measurement }) {
  if (!measurement) return null;
  const conditions = measurement.conditions || {};
  const browser = conditions.browser || {};
  const protocol = measurement.visit_protocol || {};
  return (
    <Panel title="Condiciones de la medición" subtitle="Navegador, modo, fecha, versiones, país de la IP de salida y protocolo de visita." testId="measurement"
      info={<>El país sale de la IP de salida del analizador (consultada una vez por scan a través del egress-proxy y geolocalizada con DB-IP Lite; la IP no se guarda). Nunca se deduce del idioma ni de la zona horaria del navegador.</>}>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-sm" data-testid="measurement-conditions">
        <div><dt className="muted">Navegador</dt><dd data-testid="measurement-browser">{[browser.name, value(browser.version)].filter(Boolean).join(" ")}</dd></div>
        <div><dt className="muted">Modo</dt><dd data-testid="measurement-mode">{MODE_LABELS[conditions.browser_mode] || value(conditions.browser_mode)}</dd></div>
        <div><dt className="muted">Fecha y hora de la visita</dt><dd>{conditions.measured_at && conditions.measured_at !== "no_disponible" ? formatDate(conditions.measured_at) : "no disponible"}</dd></div>
        <div><dt className="muted">País de la IP de salida</dt><dd data-testid="measurement-country">{countryText(conditions.egress_country)}</dd></div>
        <div><dt className="muted">Analizador</dt><dd className="captured">{value(conditions.analyzer_version)}</dd></div>
        <div><dt className="muted">Listas</dt><dd className="captured">{value(conditions.lists_version)}{(conditions.lists || []).length > 0 && ` (${conditions.lists.map((item) => `${item.id} ${value(item.version)}`).join(", ")})`}</dd></div>
      </dl>
      <div className="mt-3" data-testid="visit-protocol" data-protocol={protocol.protocol_version ?? "ninguno"}>
        <h3 className="font-semibold">{protocol.applies ? `Protocolo de visita ${protocol.protocol_version}` : "Protocolo de visita"}</h3>
        {!protocol.applies ? <p className="text-sm" data-testid="visit-protocol-note">{protocol.note}</p> : (
          <table className="text-sm w-full">
            <thead><tr className="text-left"><th className="pr-3">Etapa</th><th className="pr-3">Previsto</th><th className="pr-3">Completada</th><th className="pr-3">Inicio</th><th className="pr-3">Requests</th><th>Motivo</th></tr></thead>
            <tbody>
              {(protocol.stages || []).map((stage) => (
                <tr key={stage.order} data-testid="visit-stage" data-stage={stage.name} data-completed={stage.completed ? "true" : "false"}>
                  <td className="pr-3">{stage.order}. {STAGE_LABELS[stage.name] || stage.name}</td>
                  <td className="pr-3">{planned(stage)}</td>
                  <td className="pr-3">{stage.completed ? "sí" : <strong>no</strong>}</td>
                  <td className="pr-3">{stage.started_at ? formatDate(stage.started_at) : "—"}</td>
                  <td className="pr-3">{stage.requests}</td>
                  <td>{stage.reason_text}{(stage.includes || []).length > 0 && ` (${stage.includes.join("; ")})`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {protocol.applies && (
          <div className="text-sm mt-2" data-testid="closing-sends">
            Envíos observados durante el cierre: {(protocol.closing_sends || []).length === 0 ? "ninguno." : (
              <ul className="list-disc pl-5">
                {protocol.closing_sends.map((item) => (
                  <li key={item.seq}>#{item.seq} {item.method} <Captured value={`${item.host || ""}${item.path || ""}`} limit={80} expandable={false} /> ({item.resource_type})</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <p className="muted text-xs mt-1" data-testid="closing-notice">{protocol.closing_notice}</p>
      </div>
    </Panel>
  );
}

/** Tabla de cobertura por contexto (dentro de «Límites de la medición»). */
export function CoverageTable({ coverage }) {
  if (!coverage || !(coverage.contexts || []).length) return null;
  return (
    <div className="mt-2" data-testid="coverage-table">
      <p className="font-semibold">Cobertura por contexto</p>
      <table className="text-sm">
        <thead><tr className="text-left"><th className="pr-3">Contexto</th><th className="pr-3">Instrumentación instalada</th><th className="pr-3">APIs observadas</th><th>Tráfico capturado</th></tr></thead>
        <tbody>
          {coverage.contexts.map((row) => (
            <tr key={row.id} data-testid="coverage-row" data-context={row.id}>
              <td className="pr-3">{row.label}</td>
              <td className="pr-3">{row.instrumentation ? "sí" : "no"}</td>
              <td className="pr-3">{row.apis_observed.length ? row.apis_observed.join(", ") : "ninguna"}</td>
              <td>{row.traffic_captured ? "sí" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted text-xs">Resultado de la auditoría reproducible {coverage.audited_with}. APIs de prueba: {(coverage.probe_apis || []).join(", ")}.</p>
    </div>
  );
}
