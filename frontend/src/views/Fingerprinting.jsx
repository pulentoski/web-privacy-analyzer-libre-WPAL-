import { useEffect } from "react";

import { Term, WhatIsThis } from "../components/Term.jsx";
import { Captured, Empty, ErrorNotice, EvidenceBadge, EvidenceRefs, Link, Loading, Panel, Plain, ServiceTag, StatusBadge } from "../components/ui.jsx";
import { groupByLabel } from "../exposure/scanAttributes.js";
import { api } from "../lib/api.js";
import { entityLabel } from "../lib/format.js";
import { useApi } from "../lib/useApi.js";

const ATTRIBUTES = {
  canvas: "Canvas", fonts: "Fuentes", webgl_vendor: "Fabricante de GPU (WebGL)", webgl_renderer: "Modelo de GPU (WebGL)",
  webgl_parameters: "Parámetros de WebGL", audio: "Audio", webrtc: "WebRTC", user_agent: "User agent",
  user_agent_client_hints: "Client Hints detallados", platform: "Plataforma", hardware_concurrency: "Núcleos de CPU",
  device_memory: "Memoria del dispositivo", languages: "Idiomas", plugins: "Plugins", webdriver: "Indicador de automatización",
  max_touch_points: "Puntos táctiles", screen: "Pantalla", timezone: "Zona horaria", media_queries: "Media queries",
  media_devices: "Dispositivos multimedia", battery: "Batería", permissions: "Permisos", gpu_adapter: "Adaptador WebGPU",
  speech_voices: "Voces de síntesis", storage_estimate: "Estimación de almacenamiento",
};

function describe(details) {
  if (!details) return "";
  if (details.value !== undefined) return `valor leído: ${details.value}`;
  if (details.distinct_fonts !== undefined) return `${details.distinct_fonts} fuentes distintas`;
  if (details.reads) return details.reads.map((read) => `${read.kind} ${read.canvas_width ? `${read.canvas_width}x${read.canvas_height}` : ""} sha256 ${String(read.sha256 || "sin hash").slice(0, 16)}…`).join("; ");
  return "";
}

/**
 * «Atributos de su navegador que leyó este sitio» (v1.2): atributo · leído por (script y organización) · enviado a.
 * Los nombres son los de «Mi exposición». Todo lo que viene del sitio (URL del script, organización) se pinta como texto.
 */
function BrowserAttributes({ jobId, rows }) {
  const grouped = groupByLabel(rows);
  return (
    <div data-testid="browser-attributes">
      <h3 className="font-semibold">Atributos de su navegador que leyó este sitio</h3>
      {grouped.length === 0 ? <Empty>Ningún script leyó atributos del navegador en esta visita.</Empty> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-400">
                <th className="py-1 pr-3">Atributo</th><th className="py-1 pr-3">Leído por (script y organización)</th><th className="py-1">Enviado a</th>
              </tr>
            </thead>
            <tbody>
              {grouped.map((row) => (
                <tr key={row.label} className="border-b border-slate-200 align-top" data-testid="browser-attribute" data-sent={String(row.sent_to.length > 0)}>
                  <th className="text-left font-medium py-1 pr-3" data-testid="browser-attribute-name">{row.label}</th>
                  <td className="py-1 pr-3">
                    <ul className="space-y-1">
                      {row.read_by.slice(0, 6).map((item) => (
                        <li key={item.script_url} data-testid="browser-attribute-reader">
                          <Captured value={item.script_url} limit={70} />{" "}
                          <span className="muted">· {entityLabel(item.is_entity ? item.organization : null)}</span>
                          {item.call_ref !== null && item.call_ref !== undefined && <>{" "}<Link to={["scan", jobId, "fingerprinting"]} query={{ call: item.call_ref }} testId="browser-attribute-call">llamada #{item.call_ref}</Link></>}
                        </li>
                      ))}
                      {row.read_by.length > 6 && <li className="muted">y {row.read_by.length - 6} scripts más</li>}
                      {row.read_by.length === 0 && <li className="muted">sin script identificado</li>}
                    </ul>
                  </td>
                  <td className="py-1">
                    {row.sent_to.length === 0 ? <span className="muted">no se observó envío</span> : (
                      <ul className="space-y-1">
                        {row.sent_to.map((item) => (
                          <li key={`${item.organization}-${item.domain}`} data-testid="browser-attribute-sent">
                            <EvidenceBadge level={item.level} /> <Captured value={item.organization} limit={40} />
                            {item.is_entity && <span className="muted"> (<span className="captured">{item.domain}</span>)</span>}{" "}
                            {item.request_ref !== null && item.request_ref !== undefined && <Link to={["scan", jobId, "request", item.request_ref]} testId="browser-attribute-request">request #{item.request_ref}</Link>}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function Fingerprinting({ jobId, query }) {
  const { data, error, loading } = useApi(() => api.fingerprinting(jobId), `fp-${jobId}`);
  // Las frases técnicas de cada hallazgo salen de la lista de hallazgos (misma plantilla en toda la app).
  const findings = useApi(() => api.findings(jobId), `findings-${jobId}`);
  const plainOf = (item) => {
    const match = ((findings.data && findings.data.items) || []).find(
      (finding) => finding.kind === "fingerprinting" && finding.type === item.heuristic && finding.claim === item.claim && finding.script_url === item.script_url,
    );
    return match ? match.plain : null;
  };
  const highlighted = query && query.call ? String(query.call) : null;
  useEffect(() => {
    if (!data || !highlighted) return;
    const row = document.getElementById(`call-${highlighted}`);
    if (row && row.scrollIntoView) row.scrollIntoView({ block: "center" });
  }, [data, highlighted]);
  if (loading) return <Loading what="el fingerprinting" />;
  if (error) return <ErrorNotice error={error} />;
  if (!data.instrumented) {
    return (
      <div className="space-y-4">
        <WhatIsThis panel="fingerprinting" />
        <Panel title="Fingerprinting: lectura de atributos del dispositivo" testId="fingerprinting"><Empty>Este scan se hizo sin instrumentación: no se midió el uso de APIs. Eso no significa que el sitio no las use.</Empty></Panel>
      </div>
    );
  }
  return (
    <div className="space-y-4" data-testid="fingerprinting">
      <WhatIsThis panel="fingerprinting" />
      <Panel title="Fingerprinting: lectura de atributos del dispositivo" testId="fp-intro"
        subtitle={<>Scripts que llaman a APIs que distinguen un dispositivo (<Term id="canvas">canvas</Term>, <Term id="webgl">WebGL</Term>, audio, pantalla).</>}
        info={<><strong>Fingerprinting</strong>: se registra qué scripts llaman a APIs como canvas, WebGL, audio o pantalla. Que un script siga un patrón «compatible con fingerprinting» es una inferencia; lo observado es la llamada y, si aparece, el valor leído dentro de una request.</>}>
        {data.truncated && <p className="text-sm" data-testid="fp-truncated"><strong>El registro de este scan quedó truncado por volumen.</strong></p>}
        <BrowserAttributes jobId={jobId} rows={data.browser_attributes || []} />
      </Panel>

      <Panel title="Exfiltración de atributos" testId="exfiltrations">
        {data.exfiltrations.length === 0 ? (
          <Empty>No se observó ningún valor leído dentro de una request. Esto no significa que no salgan datos: solo se reconocen valores enviados tal cual o con sha256, sha1 o md5.</Empty>
        ) : (
          <ul className="space-y-2">
            {data.exfiltrations.map((item, index) => (
              <li key={index} className="text-sm" data-testid="exfiltration">
                <Plain text={plainOf(item)} level={item.level} inline testId="exfiltration-plain" />
                <span className="muted">Detalle técnico:</span> <EvidenceBadge level={item.level} /> <Captured value={item.claim} limit={400} />
                <div><EvidenceRefs jobId={jobId} requests={item.evidence_refs.requests} calls={item.evidence_refs.calls} /></div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Scripts" testId="fp-scripts">
        {data.scripts.length === 0 ? <Empty>Ningún script llamó a las APIs instrumentadas.</Empty> : (
          <div className="space-y-2">
            {data.scripts.map((script, index) => (
              <details key={index} className="panel p-2" open={script.fingerprinting_inferred} data-testid="fp-script" data-inferred={String(script.fingerprinting_inferred)}>
                <summary className="cursor-pointer">
                  <Captured value={script.script_url || "(script no identificado)"} limit={110} />{" "}
                  <span className="muted text-sm">· {entityLabel(script.entity)} · {script.total_calls} llamadas · <ServiceTag label={script.service_label} /></span>
                  {script.fingerprinting_inferred && <span className="badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold ml-2 bg-violet-100 text-violet-900 border-violet-700">patrón de fingerprinting (inferencia)</span>}
                </summary>
                {script.heuristics.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {script.heuristics.map((heuristic, heuristicIndex) => (
                      <li key={heuristicIndex} className="text-sm" data-testid="fp-heuristic">
                        <Plain text={plainOf(heuristic)} level={heuristic.level} inline testId="fp-plain" />
                        <span className="muted">Detalle técnico:</span> <EvidenceBadge level={heuristic.level} /> <Captured value={heuristic.claim} limit={400} />
                        <div><EvidenceRefs jobId={jobId} requests={heuristic.evidence_refs.requests} calls={heuristic.evidence_refs.calls} /></div>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="text-sm mt-2 muted">APIs usadas:</p>
                <ul className="text-sm flex flex-wrap gap-x-4">
                  {script.apis.map((entry) => (
                    <li key={entry.api}><span className="captured">{entry.api}</span> ×{entry.count}</li>
                  ))}
                </ul>
              </details>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Estado por atributo" testId="fp-attributes">
        <table className="w-full text-sm">
          <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Atributo</th><th className="pr-2">Estado</th><th className="pr-2">Valor leído</th><th>Evidencia</th></tr></thead>
          <tbody>
            {data.attributes.map((attribute) => (
              <tr key={attribute.attribute} className="border-b border-slate-200 align-top">
                <td className="py-1 pr-2">{ATTRIBUTES[attribute.attribute] || attribute.attribute}</td>
                <td className="pr-2"><StatusBadge status={attribute.status} /></td>
                <td className="pr-2">{attribute.value ? <Captured value={attribute.value} limit={70} /> : <span className="muted">—</span>}</td>
                <td>{attribute.evidence_refs.calls.length || attribute.evidence_refs.requests.length ? <EvidenceRefs jobId={jobId} requests={attribute.evidence_refs.requests} calls={attribute.evidence_refs.calls} max={4} /> : <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="Llamadas registradas" subtitle="Agregadas por API, script y frame; de canvas y audio solo se guarda un hash." testId="fp-calls">
        <div className="overflow-x-auto max-h-[32rem] overflow-y-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">#</th><th className="pr-2">API</th><th className="pr-2">Veces</th><th className="pr-2">Script</th><th>Detalle</th></tr></thead>
            <tbody>
              {data.calls.map((call) => (
                <tr key={call.call_id} id={`call-${call.call_id}`} className={`border-b border-slate-200 align-top ${highlighted === String(call.call_id) ? "row-highlight" : ""}`} data-testid={highlighted === String(call.call_id) ? "call-highlighted" : "call-row"}>
                  <td className="py-1 pr-2">{call.call_id}</td>
                  <td className="pr-2 captured">{call.api}</td>
                  <td className="pr-2">{call.count}</td>
                  <td className="pr-2"><Captured value={call.script_url || `(inline o eval en ${call.frame_url})`} limit={70} /></td>
                  <td><Captured value={describe(call.details)} limit={90} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
