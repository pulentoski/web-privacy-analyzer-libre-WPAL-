// Panel (inicio, v1.2): lo que muestran en conjunto los scans guardados y la tarjeta de «Mi exposición».
// Los datos de los scans salen de GET /api/panel (scan más reciente de cada sitio, sin fixtures ni
// tests). La tarjeta de «Mi exposición» se calcula en este navegador, igual que su página de detalle.
import { useEffect, useState } from "react";

import { BandBadge, Captured, Empty, ErrorNotice, EvidenceBadge, Link, Loading, Logo, Panel, ServiceTag, StatCard } from "../components/ui.jsx";
import { CATALOG } from "../exposure/catalog.js";
import { collect, DISPONIBLE, fingerprint } from "../exposure/collector.js";
import { scanAttributeLabel } from "../exposure/scanAttributes.js";
import { api } from "../lib/api.js";
import { formatDate } from "../lib/format.js";
import { useApi } from "../lib/useApi.js";

const IP_ACCESS = {
  local: "Red interna del servidor",
  lan: "Privada (misma red local)",
  public: "Pública",
  other: "Otro tipo",
};

/** «presente en k de N sitios», con una barra proporcional (ancho en el atributo SVG: sin estilos en línea). */
function Presence({ sites, of }) {
  const ratio = of > 0 ? Math.max(0, Math.min(1, sites / of)) : 0;
  return (
    <span className="presence" data-testid="presence">
      <svg className="presence-bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">
        <rect className="presence-track" x="0" y="0" width="100" height="8" />
        <rect className="presence-fill" x="0" y="0" width={ratio * 100} height="8" />
      </svg>
      <span>presente en <strong>{sites}</strong> de {of} {of === 1 ? "sitio" : "sitios"}</span>
    </span>
  );
}

/**
 * Una fila por nombre de «Mi exposición»: varios atributos de scan pueden compartir etiqueta
 * (fabricante y modelo de GPU son «Tarjeta gráfica (WebGL)»). Se conserva el que está en más sitios.
 */
export function mergeByLabel(items) {
  const merged = new Map();
  (items || []).forEach((item) => {
    const label = scanAttributeLabel(item.attribute);
    const known = merged.get(label);
    if (!known) merged.set(label, { ...item, label, organizations: [...item.organizations] });
    else {
      if (item.sites > known.sites) known.sites = item.sites;
      item.organizations.forEach((name) => { if (!known.organizations.includes(name) && known.organizations.length < 3) known.organizations.push(name); });
    }
  });
  return [...merged.values()].sort((a, b) => b.sites - a.sites);
}

function AttributeList({ items: raw, verb, testId, empty }) {
  const items = mergeByLabel(raw);
  if (!items.length) return <Empty>{empty}</Empty>;
  return (
    <ol className="text-sm space-y-1" data-testid={testId}>
      {items.map((item) => (
        <li key={item.label} className="flex flex-wrap items-baseline justify-between gap-x-3" data-testid={`${testId}-item`}>
          <span className="font-medium">{item.label}</span>
          <span className="muted">
            {verb} en <strong>{item.sites}</strong> de {item.of}
            {item.organizations.length > 0 && <> · {item.organizations.map((name, index) => <span key={name}>{index > 0 && ", "}<Captured value={name} limit={28} expandable={false} /></span>)}</>}
          </span>
        </li>
      ))}
    </ol>
  );
}

/** Tarjeta resumida de «Mi exposición»: atributos expuestos (N de M), huella corta, GPU y tipo de IP observada. */
function ExposureCard() {
  const [state, setState] = useState({ collected: null, server: null, done: false });
  useEffect(() => {
    let alive = true;
    Promise.allSettled([collect(), api.exposureServer()]).then(([collected, server]) => {
      if (!alive) return;
      setState({
        collected: collected.status === "fulfilled" ? collected.value : null,
        server: server.status === "fulfilled" ? server.value : null,
        done: true,
      });
    });
    return () => { alive = false; };
  }, []);
  const { collected, server, done } = state;
  const available = collected ? Object.values(collected.attributes).filter((item) => item.status === DISPONIBLE).length : null;
  const print = collected ? fingerprint(collected.attributes) : null;
  const webgl = collected && collected.attributes.webgl;
  const gpu = webgl && webgl.status === DISPONIBLE && webgl.value ? String(webgl.value.unmasked_renderer || webgl.value.renderer || "") : "";
  const access = server && server.ip ? IP_ACCESS[server.ip.access] || IP_ACCESS.other : null;
  return (
    <Panel
      title="Mi exposición" subtitle="Lo que este navegador expone a cualquier sitio; se calcula aquí y no se guarda." testId="panel-exposure"
      actions={<Link to={["exposure"]} testId="exposure-detail" className="btn text-sm">Ver detalle</Link>}
    >
      {!done ? <Loading what="los atributos del navegador" /> : (
        <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
          <div data-testid="panel-exposure-attributes"><dt className="muted">Atributos expuestos</dt><dd className="text-xl font-bold">{available === null ? "—" : <>{available} de {CATALOG.length}</>}</dd></div>
          <div data-testid="panel-exposure-hash"><dt className="muted">Huella corta</dt><dd className="text-xl font-bold captured">{print ? print.combined.slice(0, 12) : "—"}</dd></div>
          <div data-testid="panel-exposure-gpu"><dt className="muted">GPU</dt><dd className="font-bold">{gpu ? <Captured value={gpu} limit={60} /> : "No disponible"}</dd></div>
          <div data-testid="panel-exposure-ip"><dt className="muted">Tipo de IP observada</dt><dd className="font-bold">{access || "No disponible"}</dd></div>
        </dl>
      )}
    </Panel>
  );
}

function ScanData({ includeTests }) {
  const panel = useApi(() => api.panel(includeTests), `panel-${includeTests}`);
  if (panel.loading) return <Loading what="el panel" />;
  if (panel.error) return <ErrorNotice error={panel.error} />;
  const data = panel.data;
  const { totals } = data;
  if (totals.sites === 0) {
    return (
      <Panel title="Sitios analizados" subtitle={data.basis} testId="panel-empty">
        <Empty>Todavía no hay sitios analizados.</Empty>
        <p className="mt-2"><Link to={["analyze"]} testId="panel-analyze" className="btn btn-primary">Analizar un sitio</Link></p>
      </Panel>
    );
  }
  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3" data-testid="panel-totals">
        <StatCard label="Sitios analizados" value={totals.sites} hint={`${totals.scans} ${totals.scans === 1 ? "scan guardado" : "scans guardados"}`} testId="total-sites" />
        <StatCard label="Requests" value={totals.requests} hint="en el scan más reciente de cada sitio" testId="total-requests" />
        <StatCard label="Organizaciones distintas" value={totals.organizations} hint="identificadas entre los destinos" testId="total-organizations" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2 items-start">
        <Panel title="Organizaciones más presentes" subtitle="En cuántos de los sitios analizados aparece cada una." testId="panel-organizations"
          info={<><strong>Base</strong>: {data.basis} La organización de cada dominio sale de las listas de entidades; un dominio sin organización conocida no se cuenta aquí.</>}>
          {data.organizations.length === 0 ? <Empty>Ninguna organización identificada.</Empty> : (
            <ol className="text-sm space-y-1">
              {data.organizations.map((item) => (
                <li key={item.entity} className="flex flex-wrap items-center justify-between gap-x-3" data-testid="panel-organization">
                  <span className="font-medium">
                    <Captured value={item.entity} limit={40} expandable={false} />{" "}
                    <ServiceTag label={item.service_label} />
                  </span>
                  <Presence sites={item.sites} of={item.of} />
                </li>
              ))}
            </ol>
          )}
        </Panel>

        <Panel title="Ranking de sitios" subtitle="Por índice de exposición (0–99; mayor = más expuesto)." testId="panel-ranking"
          info={<><strong>Índice de exposición</strong>: estimación del scan más reciente de cada sitio. No es un veredicto: resume cuántos terceros, rastreadores y lecturas de atributos se observaron.</>}>
          <ol className="text-sm space-y-1">
            {data.ranking.map((item) => (
              <li key={item.site} className="flex flex-wrap items-center justify-between gap-x-3" data-testid="panel-ranking-item">
                <Link to={["scan", item.job_id]} testId="panel-ranking-link"><Captured value={item.site} limit={48} expandable={false} /></Link>
                <span className="flex items-center gap-2">
                  <span className="muted text-xs">{formatDate(item.created_at)}</span>
                  <BandBadge band={item.band} score={item.site_exposure_score} />
                </span>
              </li>
            ))}
          </ol>
          {data.ranking.length === 0 && <Empty>Ningún sitio con índice comparable.</Empty>}
          {(data.partial_sites || []).length > 0 && (
            <div className="text-xs mt-2" data-testid="panel-partial-sites">
              <p className="muted">Fuera del ranking (índice no comparable con el de una visita automática): capturas HAR importadas y capturas interactivas.</p>
              <ul className="space-y-1 mt-1">
                {data.partial_sites.map((item) => (
                  <li key={item.site} className="flex flex-wrap items-center justify-between gap-x-3" data-testid="panel-partial-item" data-source={item.source || "har_import"}>
                    <Link to={["scan", item.job_id]} testId="panel-partial-link"><Captured value={item.site} limit={48} expandable={false} /></Link>
                    {item.source === "interactive"
                      ? <span data-testid="panel-interactive-index"><BandBadge band={item.band} score={item.site_exposure_score} /> <span className="muted text-xs">captura interactiva (toda la sesión)</span></span>
                      : <BandBadge band={item.band} score={item.site_exposure_score} partial />}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(data.blocked_sites || []).length > 0 && (
            <p className="muted text-xs mt-2" data-testid="panel-blocked-sites">
              Excluidos del ranking por detección antibot (visita posiblemente no representativa): {data.blocked_sites.join(", ")}.
            </p>
          )}
        </Panel>
      </div>

      <Panel title="Atributos del navegador" subtitle="Los más leídos por scripts y los más enviados en requests." testId="panel-attributes"
        info={<><strong>Leído</strong>: un script llamó a la API del navegador que expone el atributo. <strong>Enviado</strong>: el valor leído apareció en una request (solo casos con evidencia). Los nombres son los de «Mi exposición».</>}>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="font-semibold mb-1">Más leídos <EvidenceBadge level="EVIDENCIA" /></h3>
            <AttributeList items={data.attributes.read} verb="leído" testId="panel-read" empty="Ningún atributo leído en estos scans." />
          </div>
          <div>
            <h3 className="font-semibold mb-1">Más enviados <EvidenceBadge level="EVIDENCIA" /></h3>
            <AttributeList items={data.attributes.sent} verb="enviado" testId="panel-sent" empty="Ningún envío reconocido en estos scans." />
          </div>
        </div>
      </Panel>
    </>
  );
}

export default function PanelView({ includeTests = false }) {
  return (
    <div className="space-y-4" data-testid="panel">
      <div className="flex items-center gap-4">
        <Logo size="hero" testId="panel-logo" />
        <div>
          <h1 className="text-2xl font-bold display" data-testid="panel-heading">Panel de recolección de datos</h1>
          <p className="muted text-sm" data-testid="panel-heading-subtitle">Métodos, destinos y organizaciones observados en los sitios analizados</p>
        </div>
      </div>
      <ScanData includeTests={includeTests} />
      <ExposureCard />
    </div>
  );
}
