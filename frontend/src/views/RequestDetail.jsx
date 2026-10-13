import { Term } from "../components/Term.jsx";
import { BandBadge, Captured, Empty, ErrorNotice, EvidenceBadge, ExternalUrl, Link, Loading, Panel, Plain, TechDetail, TextViewer } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { categoryLabel, entityLabel, formatBytes, formatDate, orUnavailable, partyLabel } from "../lib/format.js";
import { useApi } from "../lib/useApi.js";

const REFERER = {
  full_url: "URL completa de la página (con ruta y parámetros)",
  origin_only: "Solo el origen del sitio",
  absent: "No se envió",
};
const SOURCES = {
  query: "Query", post_form: "Formulario", post_body: "Cuerpo", referer: "Referer", cookie: "Cookie enviada", set_cookie: "Cookie recibida",
  query_decoded: "Query (decodificado)", post_form_decoded: "Formulario (decodificado)", post_body_decoded: "Cuerpo (decodificado)",
};

function Row({ label, children }) {
  return (
    <tr className="border-b border-slate-200 align-top">
      <th className="text-left font-medium py-1 pr-3 whitespace-nowrap">{label}</th>
      <td className="py-1">{children}</td>
    </tr>
  );
}

function Headers({ headers }) {
  if (!headers || headers.length === 0) return <Empty>Sin cabeceras registradas.</Empty>;
  return (
    <table className="w-full text-sm">
      <tbody>
        {headers.map((header, index) => (
          <tr key={index} className="border-b border-slate-200 align-top">
            <th className="text-left font-medium pr-3 captured">{header.name}</th>
            <td>
              {header.redacted
                ? <span className="muted" data-testid="header-redacted">valor descartado al importar ({header.length ?? "?"} caracteres)</span>
                : <Captured value={header.value} limit={160} />}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function RequestDetail({ jobId, requestId }) {
  const { data, error, loading } = useApi(() => api.requestDetail(jobId, requestId), `${jobId}-${requestId}`);
  if (loading) return <Loading what="la request" />;
  if (error) return <ErrorNotice error={error} />;
  const r = data;
  const cookies = (r.parameters || []).filter((p) => p.source === "cookie" || p.source === "set_cookie");
  const params = (r.parameters || []).filter((p) => p.source !== "cookie" && p.source !== "set_cookie" && p.source !== "referer");
  const initiator = r.initiator;

  return (
    <div className="space-y-4" data-testid="request-detail">
      <p><Link to={["scan", jobId, "requests"]}>← Volver a la tabla</Link></p>
      <Panel title={`Conexión #${r.seq + 1}: qué pasó`} testId="request-summary">
        {r.plain
          ? <Plain text={r.plain.text} level={r.plain.level} testId="request-plain" />
          : <Empty>Esta conexión todavía no tiene análisis.</Empty>}
        <p className="text-sm mt-2">
          Destino: <span className="captured">{orUnavailable(r.host)}</span> · {entityLabel(r.entity)} ·{" "}
          {r.party === "third_party" || (!r.party && r.third_party) ? <><Term id="tercero">tercero</Term> (empresa distinta del sitio)</> : partyLabel(r)}{" "}
          <BandBadge band={r.band} score={r.score} />
        </p>
        {r.findings && r.findings.length > 0 && (
          <ul className="mt-2 space-y-2" data-testid="request-findings-plain">
            {r.findings.map((finding) => (
              <li key={`${finding.kind}-${finding.id}`}><Plain text={finding.plain} level={finding.level} inline testId="related-plain" /></li>
            ))}
          </ul>
        )}
      </Panel>

      <TechDetail testId="request-tech" remember>
      <Panel title={`Request #${r.seq + 1}`}>
        <table className="w-full text-sm">
          <tbody>
            <Row label="URL"><ExternalUrl value={r.url} limit={300} /></Row>
            <Row label="Método y estado"><span className="captured">{r.method}</span> → {r.blocked_by_proxy ? "bloqueada por el proxy" : r.failure_text ? <Captured value={r.failure_text} /> : orUnavailable(r.response_status)}</Row>
            <Row label="Tipo">{orUnavailable(r.resource_type)} · {orUnavailable(r.mime_type)} · mecanismo: {orUnavailable(r.mechanism)}</Row>
            <Row label="Origen → destino">
              <Captured value={r.frame_url} limit={80} /> → <span className="captured">{orUnavailable(r.host)}</span>{" "}
              ({partyLabel(r)})
            </Row>
            <Row label="Organización">{entityLabel(r.entity)} · dominio registrable: <span className="captured">{orUnavailable(r.registrable_domain)}</span></Row>
            <Row label="Categoría">{r.category ? categoryLabel(r.category) : "sin análisis"}</Row>
            <Row label="Iniciada por">
              {initiator ? (
                <span>{orUnavailable(initiator.type)}: <Captured value={initiator.script_url} limit={120} /></span>
              ) : <span className="muted">no disponible</span>}
            </Row>
            <Row label={<><Term id="referer">Referer</Term> enviado</>}>{r.referer ? REFERER[r.referer] || r.referer : <span className="muted">no aplica (request propia del sitio o sin análisis)</span>}</Row>
            <Row label="Fecha">{formatDate(r.timestamp)}</Row>
            <Row label="Tamaño de respuesta">{formatBytes(r.sizes && r.sizes.responseBodySize)}</Row>
          </tbody>
        </table>
      </Panel>

      <Panel title="Puntaje de tracking" testId="score-panel">
        <p className="mb-2"><BandBadge band={r.band} score={r.score} /> <span className="muted text-sm">Estimación a partir de las señales de abajo; no es un veredicto.</span></p>
        {!r.reasons || r.reasons.length === 0 ? <Empty>Ninguna señal presente.</Empty> : (
          <table className="w-full text-sm" data-testid="reasons">
            <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Nivel</th><th className="pr-2">Peso</th><th>Razón</th></tr></thead>
            <tbody>
              {r.reasons.map((reason, index) => (
                <tr key={index} className="border-b border-slate-200 align-top">
                  <td className="py-1 pr-2"><EvidenceBadge level={reason.level} /></td>
                  <td className="pr-2 whitespace-nowrap">{reason.weight > 0 ? `+${reason.weight}` : reason.weight}</td>
                  <td><Captured value={reason.detail} limit={300} /> <span className="muted captured text-xs">({reason.signal})</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Hallazgos relacionados" testId="related-findings">
        {!r.findings || r.findings.length === 0 ? <Empty>Ningún hallazgo cita esta request.</Empty> : (
          <ul className="space-y-1">
            {r.findings.map((finding) => (
              <li key={`${finding.kind}-${finding.id}`} className="text-sm">
                <EvidenceBadge level={finding.level} />{" "}
                <Link to={["scan", jobId, "findings"]} query={{ f: `${finding.kind}-${finding.id}` }} testId="related-finding"><Captured value={finding.claim} limit={220} expandable={false} /></Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Parámetros" testId="parameters">
        {params.length === 0 ? <Empty>Sin parámetros.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Fuente</th><th className="pr-2">Nombre</th><th className="pr-2">Valor</th><th className="pr-2">Categoría del nombre</th><th>Forma del valor</th></tr></thead>
              <tbody>
                {params.map((p, index) => (
                  <tr key={index} className="border-b border-slate-200 align-top">
                    <td className="py-1 pr-2 whitespace-nowrap">{SOURCES[p.source] || p.source}</td>
                    <td className="pr-2"><Captured value={p.name} limit={60} /></td>
                    <td className="pr-2"><Captured value={p.value} limit={100} /></td>
                    <td className="pr-2">{p.category || "—"}</td>
                    <td>{(p.shapes || []).join(", ") || "—"}{p.identifier_like ? " · forma de identificador" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted text-xs mt-1">La categoría sale del nombre del parámetro y es una inferencia: un nombre no prueba qué contiene.</p>
          </div>
        )}
      </Panel>

      <Panel title={<>Decodificaciones (<Term id="base64">Base64</Term>, <Term id="url_codificada">URL codificada</Term>, JSON…)</>} testId="decodings">
        {!r.decoded_values || r.decoded_values.length === 0 ? <Empty>No se decodificó ningún valor.</Empty> : (
          <ul className="space-y-3">
            {r.decoded_values.map((d, index) => (
              <li key={index} className="text-sm">
                <div><strong><Captured value={d.name || "(cuerpo)"} limit={60} /></strong>{d.path ? <span className="muted"> · <Captured value={d.path} limit={60} /></span> : null}</div>
                <div className="muted">Valor original:</div>
                <TextViewer value={d.raw_value} label="valor original" />
                <div className="muted">Cadena: <span className="captured">{(d.encoding_chain || []).join(" → ")}</span> · confianza {Math.round((d.confidence || 0) * 100)} %</div>
                <TextViewer value={d.decoded_value} label="valor decodificado" />
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {r.post_data && (
        <Panel title="Cuerpo enviado">
          <p className="muted text-sm">{formatBytes(r.post_data.size)} · sha256 <span className="captured">{r.post_data.sha256}</span>{r.post_data.truncated ? " · truncado" : ""}</p>
          <TextViewer value={r.post_data.data} label="cuerpo enviado" />
        </Panel>
      )}

      <Panel title={<><Term id="cookie">Cookies</Term></>} testId="cookies">
        {cookies.length === 0 ? <Empty>La request no envió ni recibió cookies.</Empty> : (
          <table className="w-full text-sm">
            <tbody>
              {cookies.map((cookie, index) => (
                <tr key={index} className="border-b border-slate-200 align-top">
                  <td className="py-1 pr-2 whitespace-nowrap">{SOURCES[cookie.source]}</td>
                  <th className="text-left font-medium pr-2"><Captured value={cookie.name} limit={60} /></th>
                  <td><Captured value={cookie.value} limit={100} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Cabeceras de la request"><Headers headers={r.request_headers} /></Panel>
      <Panel title="Cabeceras de la respuesta"><Headers headers={r.response_headers} /></Panel>
      </TechDetail>
    </div>
  );
}
