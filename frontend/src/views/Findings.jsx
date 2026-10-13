// Hallazgos (F10): los hallazgos del scan en ocho grupos técnicos (v1.4.2 añade «Registro de interacción»).
// Cada grupo: frase técnica, conteo, nivel de evidencia y, debajo, sus hallazgos con el detalle
// técnico y la evidencia. Al final sigue estando la lista técnica completa, con su filtro
// por nivel. Todo lo capturado se pinta como texto.
import { useEffect } from "react";

import { Icon } from "../components/Icons.jsx";
import { Term, WhatIsThis } from "../components/Term.jsx";
import { Captured, Empty, ErrorNotice, EvidenceBadge, EvidenceLegend, EvidenceRefs, Loading, Panel, Plain, TechDetail } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { formatDate, levelInfo, LEVELS } from "../lib/format.js";
import { navigate } from "../lib/router.js";
import { useApi } from "../lib/useApi.js";

export function filterFindings(items, level) {
  return LEVELS[level] ? items.filter((item) => item.level === level) : items;
}

const STEP_TERMS = { interaccion: "registro_interaccion", etiquetado: "cookie_persistente", equipo: "fingerprinting", navegacion: "referer", datos: "exfiltracion", identificador: "sincronizacion", consentimiento: "cmp_tcf" };

function StepItems({ jobId, step }) {
  return (
    <ul className="space-y-3">
      {step.items.map((item, index) => (
        <li key={item.key || `${item.type}-${index}`} data-testid="story-item" data-level={item.level}>
          <Plain text={item.plain} level={item.level} inline testId="story-item-plain" />
          <div className="mt-1 ml-2 text-sm">
            <span className="muted">Detalle técnico:</span> <Captured value={item.claim} limit={400} />
            <div><EvidenceRefs jobId={jobId} requests={item.evidence_refs.requests} calls={item.evidence_refs.calls} /></div>
          </div>
        </li>
      ))}
      {step.total_items > step.items.length && (
        <li className="muted text-sm">Se muestran {step.items.length} de {step.total_items}. El resto está en la lista técnica de más abajo.</li>
      )}
    </ul>
  );
}

export function Step({ jobId, step }) {
  return (
    <li className="panel p-3 step" data-testid="story-step" data-step={step.id} data-observed={String(step.observed)}>
      <div className="flex items-start gap-3">
        <span className="step-number" aria-hidden="true">{step.number}</span>
        <div className="min-w-0 flex-1">
          <h3 className="text-lg font-bold flex flex-wrap items-center gap-2">
            <Icon name={step.icon} /> <span data-testid="story-title">{step.number}. {step.title}</span>
          </h3>
          <p className="muted text-sm" data-testid="story-technical">
            {STEP_TERMS[step.id] ? <Term id={STEP_TERMS[step.id]}>{step.technical}</Term> : step.technical}
            {!step.fixed && <> · <span data-testid="story-count">{step.count}</span> {step.count === 1 ? "hallazgo" : "hallazgos"}</>}
          </p>
          <div className="mt-2 space-y-2">
            {step.sentences.map((sentence, index) => (
              sentence.level
                ? <Plain key={index} text={sentence.text} level={sentence.level} testId="story-sentence" />
                : <p key={index} className="muted italic" data-testid="story-none">{sentence.text}</p>
            ))}
          </div>
          {step.items.length > 0 && (
            <div className="mt-2">
              <TechDetail testId="story-detail" label={`detalle técnico (${step.total_items})`}>
                <StepItems jobId={jobId} step={step} />
              </TechDetail>
            </div>
          )}
        </div>
      </div>
    </li>
  );
}

const findingKey = (item) => `${item.kind}-${item.id}`;

/**
 * Agrupa hallazgos repetidos (v1.4.2): mismo tipo, mismo nivel y mismas organizaciones en una fila.
 * `values` = hallazgos del grupo (cada uno es un valor, parámetro o script distinto); `requests` = requests distintas que los respaldan.
 */
export function groupFindings(items) {
  const groups = new Map();
  for (const item of items) {
    const organizations = item.organizations || [];
    const key = `${item.type}|${item.level}|${organizations.join("|")}`;
    if (!groups.has(key)) groups.set(key, { type: item.type, level: item.level, organizations, items: [], requestIds: new Set() });
    const group = groups.get(key);
    group.items.push(item);
    for (const ref of (item.evidence_refs && item.evidence_refs.requests) || []) group.requestIds.add(ref);
  }
  return [...groups.values()].map((group) => ({ ...group, values: group.items.length, requests: group.requestIds.size }));
}

function FindingRow({ jobId, item, focused, nested = false }) {
  const key = findingKey(item);
  return (
    <li id={`finding-${key}`} className={`${nested ? "border-t border-slate-200 pt-2" : "panel p-2"} text-sm ${focused === key ? "row-highlight" : ""}`}
      data-testid={focused === key ? "finding-focused" : "finding"}>
      <Plain text={item.plain} level={item.level} inline testId="finding-plain" />
      <div className="mt-1"><span className="muted">Detalle técnico:</span> <Captured value={item.claim} limit={500} /></div>
      <div className="mt-1"><EvidenceRefs jobId={jobId} requests={item.evidence_refs.requests} calls={item.evidence_refs.calls} /></div>
    </li>
  );
}

function FindingGroup({ jobId, group, focused }) {
  const holdsFocus = group.items.some((item) => findingKey(item) === focused);
  return (
    <li className="panel p-2 text-sm" data-testid="finding-group" data-type={group.type} data-count={group.values}>
      <details open={holdsFocus || undefined}>
        <summary className="cursor-pointer">
          <Plain text={group.items[0].plain} level={group.level} inline testId="finding-group-plain" />{" "}
          <strong data-testid="finding-group-count">× {group.values}</strong>{" "}
          <span className="muted">
            ({group.values} valores o elementos distintos · {group.requests} {group.requests === 1 ? "request" : "requests"}
            {group.organizations.length > 0 && <> · {group.organizations.slice(0, 3).join(", ")}{group.organizations.length > 3 ? "…" : ""}</>})
          </span>
        </summary>
        <ul className="space-y-2 mt-2 ml-2">
          {group.items.map((item) => <FindingRow key={findingKey(item)} jobId={jobId} item={item} focused={focused} nested />)}
        </ul>
      </details>
    </li>
  );
}

const INTERACTION_KINDS = { click: "clic", scroll: "desplazamiento", key: "tecla" };

/** Registro de interacción (v1.4.2): correlación entre lo que hizo el usuario y los envíos, con línea de tiempo. Organizaciones y dominios = texto. */
export function InteractionPanel({ interaction }) {
  if (!interaction) return null;  // análisis anterior a v1.4.2: sin la medición
  const payloads = interaction.payloads || [];
  const flagged = (interaction.organizations || []).filter((item) => item.flagged);
  const kinds = interaction.interactions || {};
  return (
    <Panel title="Registro de interacción" tone="neutral" testId="interaction"
      subtitle="Escucha de eventos, datos de interacción en los envíos y, en capturas interactivas, envíos tras cada clic, desplazamiento o tecla."
      info={<><strong>Registro de interacción</strong>: de la interacción del usuario solo se guarda la hora y el tipo; nunca qué se tecleó ni dónde se hizo clic. Que un envío siga a un clic es un hecho observado; qué contiene, no siempre.</>}>
      {!interaction.available ? (
        <p className="text-sm" data-testid="interaction-unavailable">
          Esta captura no registró la interacción del usuario (lo hacen las capturas interactivas desde v1.4.2): no hay línea de tiempo que correlacionar.
        </p>
      ) : (
        <>
          <p className="text-sm" data-testid="interaction-counts">
            <EvidenceBadge level="EVIDENCIA" /> Interacciones registradas: <strong>{kinds.click || 0}</strong> clics, <strong>{kinds.scroll || 0}</strong> desplazamientos,{" "}
            <strong>{kinds.key || 0}</strong> teclas. Se buscan envíos a otras organizaciones en los {interaction.window_s} s siguientes.
          </p>
          {flagged.length === 0 ? <Empty>Ninguna organización recibió envíos tras la interacción por encima de su ritmo normal en la sesión.</Empty> : (
            <table className="w-full text-sm mt-2" data-testid="interaction-organizations">
              <thead><tr className="text-left"><th className="pr-2">Organización</th><th className="pr-2">Interacciones seguidas de envío</th><th className="pr-2">Envíos</th><th>Esperados por ritmo normal</th></tr></thead>
              <tbody>
                {flagged.map((item) => (
                  <tr key={item.organization} className="border-t border-slate-200" data-testid="interaction-organization">
                    <td className="py-1 pr-2"><Captured value={item.organization} limit={50} expandable={false} /></td>
                    <td className="pr-2">{item.interactions}</td><td className="pr-2">{item.requests}</td><td>{item.expected}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {(interaction.timeline || []).length > 0 && (
            <TechDetail testId="interaction-timeline" label={`línea de tiempo (${interaction.total})`}>
              <table className="w-full text-sm">
                <thead><tr className="text-left"><th className="pr-2">Hora</th><th className="pr-2">Interacción</th><th>Envíos en la ventana siguiente</th></tr></thead>
                <tbody>
                  {interaction.timeline.map((entry, index) => (
                    <tr key={index} className="border-t border-slate-200 align-top" data-testid="interaction-row" data-kind={entry.kind}>
                      <td className="py-1 pr-2 whitespace-nowrap">{formatDate(entry.ts * 1000)}</td>
                      <td className="pr-2">{INTERACTION_KINDS[entry.kind] || "otra"}</td>
                      <td>
                        {entry.navigation ? <span className="muted">abrió otra página (no se cuenta)</span>
                          : entry.sends.length === 0 ? <span className="muted">sin envíos</span>
                            : entry.sends.map((send, sendIndex) => <span key={sendIndex}>{sendIndex > 0 && ", "}<Captured value={send.organization} limit={40} expandable={false} /> ({send.requests})</span>)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {interaction.timeline_truncated && <p className="muted text-sm mt-1">Se muestran las primeras {interaction.timeline.length} interacciones.</p>}
            </TechDetail>
          )}
        </>
      )}
      {payloads.length > 0 && (
        <div className="mt-3" data-testid="interaction-payloads">
          <p className="text-sm"><EvidenceBadge level="INFERENCIA" /> Parámetros con nombre de dato de interacción (el nombre no prueba el contenido):</p>
          <table className="w-full text-sm mt-1">
            <thead><tr className="text-left"><th className="pr-2">Dominio</th><th className="pr-2">Dato</th><th className="pr-2">Parámetros</th><th>Requests</th></tr></thead>
            <tbody>
              {payloads.map((item, index) => (
                <tr key={index} className="border-t border-slate-200 align-top" data-testid="interaction-payload">
                  <td className="py-1 pr-2"><Captured value={item.domain} limit={40} expandable={false} /></td>
                  <td className="pr-2">{item.label}</td>
                  <td className="pr-2"><Captured value={(item.parameters || []).join(", ")} limit={80} /></td>
                  <td>{item.requests}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function TechnicalList({ jobId, data, level, focused }) {
  const items = filterFindings(data.items, level);
  const groups = groupFindings(items);
  return (
    <Panel title="Lista técnica completa de hallazgos" subtitle="Descripción, detalle técnico y evidencia de cada hallazgo." testId="findings">
      <div className="mb-3"><EvidenceLegend /></div>
      <div className="flex flex-wrap gap-2 mb-3" role="group" aria-label="Filtrar por nivel">
        <button type="button" className={`btn text-sm ${level === "" ? "btn-primary" : ""}`} onClick={() => navigate(["scan", jobId, "findings"])} data-testid="level-all">
          Todos ({data.items.length})
        </button>
        {Object.keys(LEVELS).map((key) => (
          <button key={key} type="button" className={`btn text-sm ${level === key ? "btn-primary" : ""}`} onClick={() => navigate(["scan", jobId, "findings"], { level: key })} data-testid={`level-${key}`}>
            {levelInfo(key).label} ({data.by_level[key] || 0})
          </button>
        ))}
      </div>
      {items.length === 0 ? <Empty>No hay hallazgos de este nivel.</Empty> : (
        <>
          <p className="muted text-sm mb-2" data-testid="findings-rows">
            <span data-testid="findings-row-count">{groups.length}</span> {groups.length === 1 ? "fila" : "filas"} para {items.length} {items.length === 1 ? "hallazgo" : "hallazgos"}:
            los repetidos (mismo tipo, mismo nivel y mismas organizaciones) van en una sola fila, desplegable.
          </p>
          <ul className="space-y-2">
            {groups.map((group) => (group.items.length === 1
              ? <FindingRow key={findingKey(group.items[0])} jobId={jobId} item={group.items[0]} focused={focused} />
              : <FindingGroup key={`${group.type}|${group.level}|${group.organizations.join("|")}`} jobId={jobId} group={group} focused={focused} />))}
          </ul>
        </>
      )}
    </Panel>
  );
}

export default function Findings({ jobId, query }) {
  const report = useApi(() => api.report(jobId), `report-${jobId}`);
  const findings = useApi(() => api.findings(jobId), `findings-${jobId}`);
  const level = query && LEVELS[query.level] ? query.level : "";
  const focused = (query && query.f) || null;
  useEffect(() => {
    if (!findings.data || !focused) return;
    const node = document.getElementById(`finding-${focused}`);
    if (node && node.scrollIntoView) node.scrollIntoView({ block: "center" });
  }, [findings.data, focused]);
  return (
    <div className="space-y-4">
      <WhatIsThis panel="story" />
      <Panel title="Hallazgos por grupo" subtitle="Ocho grupos; cada frase indica su nivel de evidencia." testId="story"
        info={<><strong>Niveles</strong>: Evidencia corresponde a un hecho observado; Inferencia, a una conclusión a partir de un patrón, no observada directamente.</>}>
        {report.loading ? <Loading what="los grupos de hallazgos" /> : report.error ? <ErrorNotice error={report.error} /> : (
          <ol className="space-y-3">
            {report.data.story.steps.map((step) => <Step key={step.id} jobId={jobId} step={step} />)}
          </ol>
        )}
      </Panel>
      {report.data && <InteractionPanel interaction={report.data.site.summary.interaction} />}
      {findings.loading ? <Loading what="los hallazgos" /> : findings.error ? <ErrorNotice error={findings.error} /> : (
        <TechnicalList jobId={jobId} data={findings.data} level={level} focused={focused} />
      )}
    </div>
  );
}
