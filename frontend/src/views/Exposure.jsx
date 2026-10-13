// Mi exposición: qué revela el navegador de quien abre esta página.
// Todo se calcula aquí. Lo único que sale del navegador está listado en el aviso de privacidad.
import { useCallback, useEffect, useRef, useState } from "react";

import { Captured, Empty, ErrorNotice, Info, Link, Loading, Panel } from "../components/ui.jsx";
import { CATALOG, GROUPS } from "../exposure/catalog.js";
import { collect, displayValue, DISPONIBLE, fingerprint } from "../exposure/collector.js";
import { api } from "../lib/api.js";
import { errorMessage, formatDate } from "../lib/format.js";

// Cabecera -> [etiqueta, explicación del tooltip].
const HEADERS = {
  "user-agent": ["User-Agent", "Navegador, versión y sistema operativo declarados en cada request."],
  "accept-language": ["Accept-Language", "Idiomas preferidos, en orden y con su peso."],
  "accept-encoding": ["Accept-Encoding", "Formatos de compresión que acepta el navegador."],
  "sec-ch-ua": ["Sec-CH-UA (Client Hints)", "Marca y versión mayor del navegador."],
  "sec-ch-ua-mobile": ["Sec-CH-UA-Mobile", "Indica si el navegador se declara móvil."],
  "sec-ch-ua-platform": ["Sec-CH-UA-Platform", "Nombre del sistema operativo."],
  dnt: ["DNT (Do Not Track)", "Preferencia de no seguimiento; casi ningún sitio la respeta."],
  "sec-gpc": ["Sec-GPC (Global Privacy Control)", "Señal de «no vender ni compartir mis datos»."],
  "sec-fetch-site": ["Sec-Fetch-Site", "Relación entre el origen de la página y el destino de la request."],
  "sec-fetch-mode": ["Sec-Fetch-Mode", "Modo de la request (navegación, cors, etc.)."],
  "sec-fetch-dest": ["Sec-Fetch-Dest", "Tipo de recurso solicitado."],
  "sec-fetch-user": ["Sec-Fetch-User", "Indica si la navegación la inició una acción de la persona."],
};
const PUBLIC_IP_SERVICE = "https://api.ipify.org?format=json";
const BADGE = "badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap";
const LEVEL_STYLE = {
  alto: "bg-red-100 text-red-900 border-red-700",
  medio: "bg-amber-100 text-amber-900 border-amber-700",
  bajo: "bg-slate-100 text-slate-800 border-slate-500",
};
const BUTTON = "rounded border border-slate-500 px-3 py-1";
const ROW = "border-b border-slate-200 align-top";

/** Badge del nivel de identificabilidad (data/identifiability.yaml). Sin dato: «—», nunca un nivel supuesto. */
function LevelBadge({ entry, levels }) {
  const level = entry && levels && levels[entry.level] ? entry.level : null;
  if (!level) return <span className="muted" data-testid="level" data-level="no_disponible">—</span>;
  return <span className={`${BADGE} ${LEVEL_STYLE[level]}`} data-testid="level" data-level={level}>{levels[level].label}</span>;
}

/** Contenido del tooltip: qué es el atributo + por qué tiene ese nivel. */
function Why({ title, why, entry, levels }) {
  const level = entry && levels && levels[entry.level];
  return (
    <>
      <strong>{title}</strong>: {why}
      {level && <em>Identificabilidad {level.label.toLowerCase()} (estimación cualitativa): {entry.rationale}</em>}
    </>
  );
}

function GridHead({ first = "Atributo" }) {
  return (
    <thead>
      <tr className="text-left border-b border-slate-400 text-xs">
        <th className="py-1 pr-3 font-semibold">{first}</th>
        <th className="py-1 pr-3 font-semibold">Valor</th>
        <th className="py-1 pr-2 font-semibold w-24">Identificabilidad</th>
        <th className="py-1 w-6"><span className="sr-only">Información</span></th>
      </tr>
    </thead>
  );
}

function SummaryCard({ label, value, hint, testId }) {
  return (
    <div className="vignette" data-testid={testId}>
      <div className="vignette-caption">{label}</div>
      <div className="vignette-body">
        <div className="font-bold vignette-value break-words">{value}</div>
        {hint && <div className="muted text-xs mt-0.5 break-words">{hint}</div>}
      </div>
    </div>
  );
}

function IpIntel({ intel }) {
  if (!intel) return null;
  if (!intel.applies) return <span data-testid="ip-intel">Ubicación y proveedor: <strong>{intel.note}</strong></span>;
  return (
    <span data-testid="ip-intel">
      País: <strong>{intel.country}</strong> ({intel.country_code}) · Red: <strong>{intel.asn}</strong> {intel.organization}.{" "}
      <span className="muted">Precisión: {intel.precision}. Fuente: {intel.source}.{" "}
        <a className="link" href={intel.attribution_url} target="_blank" rel="noopener noreferrer">{intel.attribution}</a>
      </span>
    </span>
  );
}

/** Tipo de IP para la tarjeta de resumen. Una IP interna nunca se presenta como la de quien visita. */
function ipSummary(server) {
  if (!server) return { value: "—", hint: null };
  const { ip, ip_intel: intel } = server;
  if (ip.access === "local") return { value: "Acceso local", hint: "Red interna o loopback: no es la IP de quien visita" };
  if (ip.access === "lan") return { value: ip.observed, hint: "IP privada (misma red local)" };
  if (ip.access === "public") return { value: ip.observed, hint: intel && intel.applies ? `Pública · ${intel.country_code} · ${intel.asn}` : "Pública" };
  return { value: ip.observed, hint: ip.kind };
}

function ServerView({ server, error, levels }) {
  const [publicIp, setPublicIp] = useState({ status: "idle" });

  const askThirdParty = async () => {
    setPublicIp({ status: "loading" });
    try {
      const response = await fetch(PUBLIC_IP_SERVICE, { referrerPolicy: "no-referrer", credentials: "omit" });
      const body = await response.json();
      const ip = typeof body.ip === "string" ? body.ip.slice(0, 45) : "";
      const lookup = await api.exposureIpLookup(ip);
      setPublicIp({ status: "done", ip, intel: lookup.ip_intel });
    } catch (failure) {
      setPublicIp({ status: "error", message: failure && failure.error_code ? errorMessage(failure) : "No se pudo consultar el servicio externo." });
    }
  };

  if (error) return <ErrorNotice error={error} />;
  if (!server) return <Loading what="los datos de la conexión" />;
  const { ip, ip_intel: intel, headers } = server;
  const ipLevel = levels && levels.connection ? levels.connection.ip : null;
  return (
    <div className="space-y-2" data-testid="server-view">
      <div className="text-sm" data-testid="observed-ip" data-access={ip.access}>
        {ip.access === "local" ? (
          <>
            <strong>{ip.label}</strong>{" "}
            <span className="muted">Dirección interna observada: <span className="captured">{ip.observed}</span>.</span>
          </>
        ) : (
          <>
            {ip.label}: <span className="captured font-semibold">{ip.observed}</span>{" "}
            {ip.is_public && <LevelBadge entry={ipLevel} levels={levels && levels.levels} />}
          </>
        )}{" "}
        <Info label="IP observada">
          <strong>IP observada</strong>: dirección desde la que llegó la request. {server.note} El servidor la devuelve y no la guarda.
          {ipLevel && <em>Una IP pública tiene identificabilidad alta (estimación cualitativa): {ipLevel.rationale}</em>}
        </Info>
      </div>
      <p className="text-sm"><IpIntel intel={intel} /></p>
      {!ip.is_public && (
        <details className="panel p-2 text-sm" data-testid="public-ip">
          <summary className="cursor-pointer font-semibold">IP pública: consulta opcional a un tercero</summary>
          <p className="mt-1">
            Este servidor no ve la IP pública porque la visita llega por una red privada; un sitio en internet <strong>sí</strong> la vería.
            <strong> Al pulsar el botón, ese tercero (api.ipify.org) verá su IP pública.</strong> No se consulta de forma automática.
          </p>
          <button type="button" className={`${BUTTON} mt-2`} onClick={askThirdParty} disabled={publicIp.status === "loading"} data-testid="public-ip-button">
            Consultar la IP pública con api.ipify.org
          </button>
          {publicIp.status === "loading" && <span className="muted ml-2">Consultando…</span>}
          {publicIp.status === "error" && <p role="alert" className="mt-2">{publicIp.message}</p>}
          {publicIp.status === "done" && (
            <p className="mt-2" data-testid="public-ip-result">
              IP pública según api.ipify.org: <span className="captured font-semibold">{publicIp.ip}</span>. <IpIntel intel={publicIp.intel} />
            </p>
          )}
        </details>
      )}
      <table className="w-full text-sm" data-testid="server-headers">
        <GridHead first="Cabecera HTTP" />
        <tbody>
          {Object.keys(headers).map((name) => {
            const [label, why] = HEADERS[name] || [name, "Cabecera enviada por el navegador."];
            const entry = levels && levels.headers ? levels.headers[name] : null;
            return (
              <tr key={name} className={ROW} data-testid={`header-${name}`}>
                <th className="text-left font-medium py-1 pr-3 whitespace-nowrap">{label}</th>
                <td className="py-1 pr-3">{headers[name] === null ? <span className="muted">no enviada</span> : <Captured value={headers[name]} limit={80} />}</td>
                <td className="py-1 pr-2"><LevelBadge entry={entry} levels={levels && levels.levels} /></td>
                <td className="py-1 tip-right"><Info label={label}><Why title={label} why={why} entry={entry} levels={levels && levels.levels} /></Info></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Atributos de scan (F4) de una entrada del catálogo -> quién los leyó y a quién se enviaron en el scan elegido. */
function compareParties(usage, scanAttributes, kind) {
  const seen = new Map();
  scanAttributes.forEach((name) => ((usage[name] || {})[kind] || []).forEach((item) => {
    if (!seen.has(item.label)) seen.set(item.label, item);
  }));
  return [...seen.values()];
}

/** «Comparar con un scan»: marca si el sitio de ese scan leyó el atributo y a quién lo envió. Cada nombre enlaza a su evidencia. */
function CompareMark({ usage, scanAttributes }) {
  if (!usage) return null;
  const read = compareParties(usage, scanAttributes, "read");
  const sent = compareParties(usage, scanAttributes, "sent");
  if (!read.length && !sent.length) return null;
  const target = (example) => (example.request_ref
    ? { to: ["scan", example.job_id, "request", example.request_ref] }
    : { to: ["scan", example.job_id, "fingerprinting"], query: { call: example.call_ref } });
  const names = (items) => items.map((item, index) => (
    <span key={item.label}>{index > 0 && ", "}<Link {...target(item.example)} testId="compare-link"><Captured value={item.label} limit={40} expandable={false} /></Link></span>
  ));
  return (
    <div className="text-xs mt-1 space-y-0.5" data-testid="compare-mark" data-read={String(read.length > 0)} data-sent={String(sent.length > 0)}>
      {read.length > 0 && <div data-testid="compare-read"><span className={`${BADGE} bg-amber-100 text-amber-900 border-amber-700`}>Leído</span> por {names(read)}</div>}
      {sent.length > 0 && <div data-testid="compare-sent"><span className={`${BADGE} bg-red-100 text-red-900 border-red-700`}>Enviado</span> a {names(sent)}</div>}
    </div>
  );
}

/** Host de una URL capturada, como texto; si no parsea, la URL recortada. */
function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return String(url).slice(0, 60);
  }
}

/** Selector opcional «Comparar con un scan». Sin scan elegido la página muestra solo el navegador del visitante. */
function CompareSelector({ value, onChange, usage }) {
  const [scans, setScans] = useState(null);
  useEffect(() => {
    api.listScans(100, { status: "done" }).then((data) => setScans(data.items.filter((scan) => scan.analysis_status === "completed")), () => setScans([]));
  }, []);
  if (!scans || scans.length === 0) return null;
  const marked = usage ? CATALOG.filter((item) => compareParties(usage, item.scan, "read").length > 0).length : 0;
  const sent = usage ? CATALOG.filter((item) => compareParties(usage, item.scan, "sent").length > 0).length : 0;
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="compare">
      <label htmlFor="compare-scan" className="font-medium">Comparar con un scan</label>
      <select id="compare-scan" className="border border-slate-400 rounded px-2 py-1 bg-white max-w-full" value={value} onChange={(event) => onChange(event.target.value)} data-testid="compare-select">
        <option value="">Sin comparación</option>
        {scans.map((scan) => <option key={scan.job_id} value={scan.job_id}>{`${hostOf(scan.url)} · ${formatDate(scan.created_at)}`}</option>)}
      </select>
      <Info label="Comparar con un scan">
        <strong>Comparar con un scan</strong>: marca, sobre los atributos de este navegador, cuáles leyó el sitio de ese scan y a qué
        organizaciones los envió. La lectura y el envío se observaron en el navegador del worker, no en el suyo.
      </Info>
      {usage && <span className="muted" data-testid="compare-summary">Ese sitio leyó <strong>{marked}</strong> de {CATALOG.length} atributos y envió <strong>{sent}</strong>.</span>}
    </div>
  );
}

function Group({ collected }) {
  const [consent, setConsent] = useState(false);
  const [state, setState] = useState({ status: "idle" });
  const [token, setToken] = useState("");
  const [purge, setPurge] = useState(null);
  const admin = new URLSearchParams((window.location.hash.split("?")[1] || "")).get("admin") === "1";

  const compare = async () => {
    setState({ status: "loading" });
    try {
      const info = await api.exposureRoom();
      // Solo hashes (con la sal de este grupo): ningún valor en claro sale del navegador.
      const { hashes, combined } = fingerprint(collected.attributes, info.salt);
      const attributes = {};
      info.attributes.forEach((name) => { if (hashes[name]) attributes[name] = hashes[name]; });
      let participant = null;
      try { participant = window.sessionStorage.getItem(`grupo-${info.salt}`); } catch { participant = null; }
      const result = await api.exposureCompare({ consent: true, combined, attributes, ...(participant ? { participant } : {}) });
      try { window.sessionStorage.setItem(`grupo-${info.salt}`, result.participant); } catch { /* sin storage: cada envío cuenta aparte */ }
      setState({ status: "done", result });
    } catch (error) {
      setState({ status: "error", error });
    }
  };
  const doPurge = () => api.exposurePurge(token).then((data) => { setPurge(`Grupo purgado: ${data.purged} participante(s) eliminados.`); setState({ status: "idle" }); }, (error) => setPurge(errorMessage(error)));

  const result = state.result;
  return (
    <div className="space-y-2" data-testid="room">
      <p className="text-sm">
        Opcional. Solo se envían <strong>hashes</strong> (uno por atributo y el combinado), nunca los valores.{" "}
        <Info label="Comparación en grupo">
          <strong>Comparación en grupo</strong>: los hashes se guardan en la memoria del servidor (no en disco ni en base de datos) y se
          eliminan a las 2 horas o cuando el administrador purga el grupo. Un hash no es anonimato: quien conozca los valores posibles puede probarlos.
        </Info>
      </p>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} data-testid="room-consent" className="mt-1" />
        <span>Acepto enviar los hashes de mi huella para compararla con la de las demás personas del grupo.</span>
      </label>
      <button type="button" className="rounded bg-blue-700 text-white px-4 py-1.5 font-semibold disabled:opacity-50" disabled={!consent || !collected || state.status === "loading"} onClick={compare} data-testid="room-compare">
        Comparar mi huella con el grupo
      </button>
      {state.status === "error" && <ErrorNotice error={state.error} />}
      {result && (
        <div data-testid="room-result">
          <p>
            <strong data-testid="room-participants">{result.participants}</strong> {result.participants === 1 ? "persona participó" : "personas participaron"}.{" "}
            {result.combined.unique
              ? <span data-testid="room-verdict">Su huella combinada es <strong>única en este grupo</strong>.</span>
              : <span data-testid="room-verdict">Su huella combinada la comparten <strong>{result.combined.same}</strong> participantes (incluido usted).</span>}
          </p>
          <p className="muted text-xs">Válido solo para este grupo y este momento: no dice nada sobre el resto de internet.</p>
          <table className="w-full text-sm mt-2">
            <thead><tr className="text-left border-b border-slate-400 text-xs"><th className="pr-2">Atributo</th><th>Participantes con el mismo valor (incluido usted)</th></tr></thead>
            <tbody>
              {CATALOG.filter((item) => result.attributes[item.id]).map((item) => (
                <tr key={item.id} className="border-b border-slate-200">
                  <td className="py-0.5 pr-2">{item.label}</td>
                  <td data-testid={`room-attr-${item.id}`}>{result.attributes[item.id].same} de {result.attributes[item.id].reported}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {admin && (
        <div className="panel p-3 text-sm" data-testid="presenter">
          <strong>Administrador:</strong> purgar el grupo borra todos los hashes y cambia la sal.
          <div className="flex gap-2 mt-2">
            <input type="password" className="border border-slate-400 rounded px-2 py-1" placeholder="Token de administrador" value={token} onChange={(event) => setToken(event.target.value)} data-testid="presenter-token" autoComplete="off" />
            <button type="button" className={BUTTON} onClick={doPurge} data-testid="presenter-purge">Purgar grupo</button>
          </div>
          {purge && <p className="mt-2" role="status" data-testid="presenter-status">{purge}</p>}
        </div>
      )}
    </div>
  );
}

/** GPU para la tarjeta de resumen: el renderer sin enmascarar si el navegador lo entrega. */
function gpuSummary(collected) {
  const attribute = collected && collected.attributes.webgl;
  if (!attribute || attribute.status !== DISPONIBLE || !attribute.value) return { value: "No disponible", hint: attribute ? attribute.reason : null };
  const { unmasked_renderer: unmasked, renderer, unmasked_vendor: unmaskedVendor, vendor } = attribute.value;
  return { value: String(unmasked || renderer || "No disponible"), hint: String(unmaskedVendor || vendor || "") || null };
}

const EMPTY = { server: null, serverError: null, collected: null, readAt: null };

export default function Exposure({ mode = "full" }) {
  const [data, setData] = useState(EMPTY);
  const [levels, setLevels] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = useRef(0);

  // Vuelve a leer TODO: conexión (el servidor responde con no-store) y atributos del navegador.
  const refresh = useCallback(async () => {
    const current = ++run.current;
    setLoading(true);
    const [server, collected] = await Promise.allSettled([api.exposureServer(), collect()]);
    if (current !== run.current) return;
    setData({
      server: server.status === "fulfilled" ? server.value : null,
      serverError: server.status === "rejected" ? server.reason : null,
      collected: collected.status === "fulfilled" ? collected.value : null,
      readAt: new Date(),
    });
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
    // Niveles de identificabilidad: texto fijo del proyecto. Sin ellos la página funciona igual, sin badges.
    api.exposureIdentifiability().then(setLevels, () => setLevels(null));
    return () => { run.current += 1; };
  }, [refresh]);

  // «Comparar con un scan» (opcional): sin scan elegido no se consulta nada de los scans.
  const [compareId, setCompareId] = useState("");
  const [usage, setUsage] = useState(null);
  useEffect(() => {
    let alive = true;
    setUsage(null);
    if (compareId) api.exposureScanUsage(compareId).then((body) => alive && setUsage(body.attributes), () => alive && setUsage({}));
    return () => { alive = false; };
  }, [compareId]);

  const { server, serverError, collected, readAt } = data;
  const print = collected ? fingerprint(collected.attributes) : null;
  const available = collected ? Object.values(collected.attributes).filter((item) => item.status === DISPONIBLE).length : 0;
  const levelNames = levels && levels.levels;
  const ip = ipSummary(server);
  const gpu = gpuSummary(collected);

  return (
    <div className="space-y-3" data-testid="exposure">
      <Panel
        title="Mi exposición"
        subtitle="Datos que cualquier sitio web puede obtener de este navegador."
        actions={(
          <span className="flex items-center gap-2 text-sm">
            <span className="muted" data-testid="read-at">{readAt ? `Lectura: ${readAt.toLocaleTimeString("es-CL")}` : "Leyendo…"}</span>
            <button type="button" className={BUTTON} onClick={refresh} disabled={loading} data-testid="refresh">{loading ? "Actualizando…" : "Actualizar"}</button>
          </span>
        )}
      >
        <div className="text-sm space-y-2" data-testid="privacy-notice">
          <details>
            <summary className="cursor-pointer link" data-testid="privacy-more">Los valores se calculan en el navegador y <strong>no se guardan</strong>. Más información</summary>
            <ul className="list-disc ml-5 mt-1 space-y-1">
              <li><strong>Qué se recolecta:</strong> los atributos de las secciones 1 y 2, leídos por un script en este navegador. No se pide ningún permiso ni se intenta obtener la IP local.</li>
              <li><strong>Qué NO sale del navegador:</strong> ninguno de esos valores. El cálculo, incluidos los hashes, ocurre aquí.</li>
              <li><strong>Qué sale:</strong> (1) la visita misma: el servidor ve la IP y las cabeceras de la sección 1, las devuelve y no las guarda ni las registra en sus logs; (2) solo con su autorización, hashes para la comparación en grupo; (3) solo con su autorización, una consulta a un tercero para conocer la IP pública.</li>
            </ul>
          </details>
          {mode === "full" && <CompareSelector value={compareId} onChange={setCompareId} usage={usage} />}
        </div>
      </Panel>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2" data-testid="summary">
        <SummaryCard label="Atributos expuestos" testId="summary-attributes" value={collected ? <><span data-testid="available-count">{available}</span> de {CATALOG.length}</> : "—"} hint="accesibles por un script" />
        <SummaryCard label="Huella combinada" testId="summary-hash" value={print ? <span className="captured" data-testid="combined-short">{print.combined.slice(0, 12)}</span> : "—"} hint="hash corto (12 de 64)" />
        <SummaryCard label="GPU detectada" testId="summary-gpu" value={collected ? <Captured value={gpu.value} limit={48} /> : "—"} hint={collected ? gpu.hint : null} />
        <SummaryCard label="IP observada" testId="summary-ip" value={ip.value} hint={ip.hint} />
        <SummaryCard label="Contexto seguro" testId="summary-secure" value={collected ? (collected.secure ? "Sí" : "No") : "—"} hint={collected ? (collected.secure ? "https o localhost" : "sin https: hay APIs no disponibles") : null} />
        <SummaryCard label="Hora de lectura" testId="summary-read-at" value={readAt ? readAt.toLocaleTimeString("es-CL") : "—"} hint={readAt ? readAt.toLocaleDateString("es-CL") : null} />
      </div>

      {levels && (
        <p className="text-xs muted" data-testid="level-legend">
          Identificabilidad:{" "}
          {["alto", "medio", "bajo"].map((name) => (
            <span key={name} className="mr-2"><LevelBadge entry={{ level: name }} levels={levelNames} /> {levelNames[name].description}</span>
          ))}
          <strong>{levels.note}</strong>
        </p>
      )}

      <Panel title="1. Datos expuestos en la conexión (IP y cabeceras HTTP)"><ServerView server={server} error={serverError} levels={levels} /></Panel>

      <Panel title="2. Atributos accesibles mediante APIs del navegador">
        {!collected ? <Loading what="los atributos del navegador" /> : (
          <div className="space-y-2">
            {!collected.secure && (
              <p className="panel p-2 text-sm border-amber-600 bg-amber-50" data-testid="insecure-context">
                Esta página no se abrió en un contexto seguro (https o localhost): algunas APIs no están disponibles.{" "}
                <Info label="Contexto seguro">
                  <strong>Contexto seguro</strong>: sin https el navegador no ofrece criptografía (crypto.subtle), Client Hints detallados,
                  memoria del dispositivo, WebGPU ni, en algunos navegadores, permisos. En un sitio https un script sí las tendría.
                </Info>
              </p>
            )}
            <div className="grid lg:grid-cols-2 gap-x-6 gap-y-3">
              {GROUPS.map(([group, label]) => (
                <div key={group} data-testid={`group-${group}`}>
                  <h3 className="font-semibold">{label}</h3>
                  <table className="w-full text-sm">
                    <GridHead />
                    <tbody>
                      {CATALOG.filter((item) => item.group === group).map((item) => {
                        const attribute = collected.attributes[item.id];
                        const isAvailable = attribute.status === DISPONIBLE;
                        const entry = levels && levels.attributes ? levels.attributes[item.id] : null;
                        return (
                          <tr key={item.id} className={ROW} data-testid={`attr-${item.id}`} data-status={attribute.status}>
                            <th className="text-left font-medium py-1 pr-3 w-1/4">{item.label}</th>
                            <td className="py-1 pr-3" data-testid="value-cell">
                              {isAvailable
                                ? <Captured value={displayValue(attribute.value)} limit={72} block />
                                : <span className="muted"><span className={`${BADGE} bg-white text-slate-600 border-slate-400`}>No disponible</span> {attribute.reason}</span>}
                              <CompareMark usage={usage} scanAttributes={item.scan} />
                            </td>
                            <td className="py-1 pr-2"><LevelBadge entry={entry} levels={levelNames} /></td>
                            <td className="py-1 tip-right"><Info label={item.label}><Why title={item.label} why={item.why} entry={entry} levels={levelNames} /></Info></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ))}
              <div data-testid="group-lan">
                <h3 className="font-semibold">Red local</h3>
                <table className="w-full text-sm">
                  <GridHead />
                  <tbody>
                    <tr className={ROW} data-testid="lan-ip">
                      <th className="text-left font-medium py-1 pr-3 w-1/4">IP de la red local</th>
                      <td className="py-1 pr-3"><span className={`${BADGE} bg-white text-slate-600 border-slate-400`}>No se intenta obtener</span></td>
                      <td className="py-1 pr-2"><span className="muted">—</span></td>
                      <td className="py-1 tip-right">
                        <Info label="IP de la red local">
                          <strong>IP de la red local</strong>: antes un sitio podía descubrirla con WebRTC. Los navegadores actuales no la revelan
                          (entregan un nombre aleatorio terminado en .local). Esta página no usa WebRTC.
                        </Info>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </Panel>

      <Panel title="3. Huella del navegador (hash combinado)">
        {!print ? <Empty>Calculando…</Empty> : (
          <div>
            <p className="captured text-sm break-all" data-testid="combined-hash">{print.combined}</p>
            <p className="text-sm mt-1">
              SHA-256 de los atributos de la sección 2, calculado en el navegador. <strong>No se puede afirmar que sea única</strong> sin una población de referencia.{" "}
              <Info label="Hash combinado">
                <strong>Hash combinado</strong>: no incluye el tamaño de la ventana, porque cambia al redimensionar. Esta página no dispone de una
                población de referencia; lo que muestra es que la combinación de datos corrientes produce un valor muy específico.
              </Info>
            </p>
          </div>
        )}
      </Panel>

      <Panel title="4. Comparación de huellas en grupo"><Group collected={collected} /></Panel>
    </div>
  );
}
