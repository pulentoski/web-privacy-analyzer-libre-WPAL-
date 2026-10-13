// Resultado de un grupo de «Opciones avanzadas» (ex Privacy Test, F7): qué cambia, qué permanece y
// qué sigue siendo observable al cambiar el consentimiento o el perfil del navegador. El formulario
// está en Analyze.jsx. Los textos describen lo observado: aquí no se promete que un perfil impida
// reconocer el navegador.
import { useEffect, useState } from "react";

import ReportDownloads from "../components/ReportDownloads.jsx";
import StageProgress from "../components/StageProgress.jsx";
import { Captured, Empty, ErrorNotice, EvidenceBadge, Info, Link, Loading, Panel, Plain } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { ATTRIBUTE_CHANGE, CONSENT_STATUS, entityLabel, errorMessage, formatStats, SCENARIO_LABELS } from "../lib/format.js";

const BADGE = "badge inline-block rounded border px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap";
const cellLabel = (cell, profiles) => `${SCENARIO_LABELS[cell.scenario] || "Sin escenario"} · ${profileLabel(cell.profile, profiles)}`;
const profileLabel = (name, profiles) => (name === "real" ? "Navegador real" : (profiles.find((p) => p.name === name) || {}).label || name);

function Evidence({ items }) {
  return (
    <span className="text-xs">
      {items.slice(0, 4).map((item, index) => (
        <span key={index}><Link to={["scan", item.job_id, "request", item.request_id]} testId="privacy-evidence">#{item.request_id}</Link>{" "}</span>
      ))}
    </span>
  );
}

function ResourceList({ finding, testId, empty }) {
  return (
    <div data-testid={testId}>
      <p className="text-sm"><EvidenceBadge level={finding.level} /> <strong>{finding.claim}</strong> <span className="muted">({finding.runs} corrida(s) consideradas)</span></p>
      {finding.items.length === 0 ? <Empty>{empty}</Empty> : (
        <ul className="text-sm ml-4 list-disc">
          {finding.items.map((item) => (
            <li key={item.resource} data-testid={`${testId}-item`}>
              <span className="captured">{item.resource}</span> · {entityLabel(item.entity)} · en {item.runs} de {item.of} corridas. Evidencia: <Evidence items={item.evidence} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Consent({ consent }) {
  if (!consent) return null;
  return (
    <Panel title="Consentimiento" testId="consent">
      <p className="text-sm mb-2">
        {consent.not_applicable
          ? <strong data-testid="consent-not-applicable">No se reconoció ningún banner de una plataforma conocida: los escenarios quedan «no aplicables» y no se pulsó ningún botón.</strong>
          : <span>Plataforma reconocida: <strong>{consent.cmp}</strong> (banner detectado en {consent.banner_detected_runs} de {consent.runs} corridas).</span>}{" "}
        <Info label="Consentimiento"><strong>Consentimiento</strong>: <span data-testid="consent-note">{consent.note}</span></Info>
      </p>
      <table className="w-full text-sm mb-3">
        <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Escenario</th><th className="pr-2">Corrida</th><th className="pr-2">Resultado</th><th>Estado verificado</th></tr></thead>
        <tbody>
          {consent.scenarios.map((row) => (
            <tr key={row.job_id} className="border-b border-slate-200 align-top" data-testid="consent-run" data-status={row.status}>
              <td className="py-1 pr-2">{SCENARIO_LABELS[row.scenario]}</td><td className="pr-2">{row.run}</td>
              <td className="pr-2">{CONSENT_STATUS[row.status] || row.status}{row.reason ? <div className="muted text-xs">{row.reason}</div> : null}</td>
              <td>{row.verified === true ? `sí (${row.verified_by === "tcf" ? "API TCF del sitio" : "cookie de la plataforma"})` : row.verified === false ? "no coincide con la decisión" : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {consent.banner_job_id && (
        <figure className="mb-3">
          <img src={api.bannerUrl(consent.banner_job_id)} alt="Captura del banner de consentimiento tal como lo mostró el sitio" className="border border-slate-400 max-w-full" data-testid="consent-banner" />
          <figcaption className="muted text-xs">Captura del banner tomada por el navegador del worker.</figcaption>
        </figure>
      )}
      {!consent.not_applicable && (
        <div className="space-y-3">
          <ResourceList finding={consent.findings.pre_consent} testId="pre-consent" empty="No se observaron requests de tracking antes de interactuar." />
          <ResourceList finding={consent.findings.post_reject} testId="post-reject" empty="No se observaron requests de tracking después de rechazar (o no hubo corridas de rechazo)." />
          <ResourceList finding={consent.findings.only_after_accept} testId="only-accept" empty="Ningún recurso apareció solo después de aceptar." />
        </div>
      )}
    </Panel>
  );
}

function Profiles({ data, profiles }) {
  if (!data) return null;
  const others = data.profiles.filter((profile) => profile.name !== "real");
  const flagged = data.profiles.filter((profile) => (data.inconsistencies[profile.name] || []).length > 0);
  return (
    <Panel title="Perfiles: navegador real frente a cada perfil" testId="profiles">
      <p className="panel p-2 text-sm mb-3 border-amber-600 bg-amber-50" data-testid="ip-unchanged"><strong>{data.ip_note}</strong></p>
      {flagged.map((profile) => (
        <div key={profile.name} role="alert" className="panel p-3 mb-3 border-red-700 bg-red-50" data-testid="inconsistent" data-profile={profile.name}>
          <p className="text-lg font-bold">⚠ FINGERPRINT INCONSISTENTE — {profileLabel(profile.name, profiles)}</p>
          <ul className="text-sm mt-1 space-y-1">
            {data.inconsistencies[profile.name].map((item, index) => (
              <li key={index} data-testid="inconsistency" data-rule={item.rule}>
                <EvidenceBadge level={item.level} /> <strong>{item.title}:</strong>{" "}
                {Object.entries(item.observed).map(([source, value]) => <span key={source} className="block ml-4"><span className="muted">{source}:</span> <Captured value={value} limit={110} /></span>)}
                <span className="block ml-4"><EvidenceBadge level={item.inference_level} /> {item.inference}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {data.profiles.filter((profile) => (data.inconsistencies[profile.name] || []).length === 0 && data.inconsistencies[profile.name] !== null).length > 0 && (
        <p className="text-sm mb-2" data-testid="consistent-profiles">
          Sin inconsistencias detectadas por estas reglas: {data.profiles.filter((profile) => (data.inconsistencies[profile.name] || []).length === 0 && data.inconsistencies[profile.name] !== null).map((profile) => profileLabel(profile.name, profiles)).join(", ")}.
          <span className="muted"> Que no haya inconsistencias no significa que el perfil sea indistinguible de un equipo real.</span>
        </p>
      )}
      {others.length > 0 && (
        <>
          {!data.has_real_reference && <p className="muted text-sm">No se incluyó el navegador real en el test: se muestran los valores de cada perfil, sin referencia.</p>}
          <div className="overflow-x-auto">
            <table className="w-full text-sm" data-testid="attribute-table">
              <thead>
                <tr className="text-left border-b border-slate-400"><th className="pr-2">Atributo</th><th className="pr-2">Real</th>{others.map((profile) => <th key={profile.name} className="pr-2">{profileLabel(profile.name, profiles)}</th>)}</tr>
              </thead>
              <tbody>
                {data.attributes.map((row) => (
                  <tr key={row.attribute} className="border-b border-slate-200 align-top" data-testid={`attr-row-${row.attribute}`}>
                    <th className="text-left font-medium py-1 pr-2">{row.label}</th>
                    <td className="pr-2"><Captured value={row.real === null ? "" : String(row.real)} limit={48} /></td>
                    {others.map((profile) => {
                      const change = ATTRIBUTE_CHANGE[row.status[profile.name]] || ATTRIBUTE_CHANGE.SIN_REFERENCIA;
                      return (
                        <td key={profile.name} className="pr-2" data-status={row.status[profile.name]}>
                          <span className={`${BADGE} ${change.className}`}>{change.label}</span>{" "}
                          {row.potentially_identifying.includes(profile.name) && <span className={`${BADGE} bg-red-100 text-red-900 border-red-700`} title="No cambió y sirve para reconocer este equipo">sigue observable</span>}
                          <div><Captured value={row.values[profile.name] === null ? "" : String(row.values[profile.name])} limit={48} /></div>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {others.map((profile) => {
            const summary = data.summary[profile.name];
            return (
              <div key={profile.name} className="text-sm mt-3" data-testid="profile-summary" data-profile={profile.name}>
                <strong>{profileLabel(profile.name, profiles)}</strong>
                <ul className="ml-4 list-disc">
                  <li><strong>Cambiaron ({summary.changed.length}):</strong> {summary.changed.join(", ") || "nada"}</li>
                  <li><strong>Permanecieron ({summary.remained.length}):</strong> {summary.remained.join(", ") || "nada"}</li>
                  <li><strong>Nuevos ({summary.new.length}):</strong> {summary.new.join(", ") || "nada"}</li>
                  <li><strong>Potencialmente identificadores que siguen observables ({summary.potentially_identifying.length}):</strong> {summary.potentially_identifying.join(", ") || "ninguno de los medidos"}</li>
                </ul>
              </div>
            );
          })}
        </>
      )}
    </Panel>
  );
}

function PersistentIds({ data, accountIds = [] }) {
  return (
    <Panel title="Identificadores que persisten sin cookies" subtitle="Valores con forma de identificador repetidos entre corridas limpias." testId="persistent-ids"
      info={<><strong>Identificadores que persisten</strong>: <span data-testid="persistent-note">{data.note}</span> Los IDs de cuenta del sitio no cuentan: son iguales para todo visitante.</>}>
      {accountIds.length > 0 && (
        <p className="text-sm mb-2" data-testid="account-ids-excluded">
          <strong>ID de cuenta del sitio</strong> ({accountIds.length}, no se cuentan como identificadores):{" "}
          {accountIds.map((item, index) => (
            <span key={`${item.rule}-${item.value}`} data-testid="account-id" data-rule={item.rule}>{index > 0 && " · "}{item.vendor}: <Captured value={item.value} limit={40} expandable={false} /></span>
          ))}
        </p>
      )}
      {data.items.length === 0 ? <Empty>{data.comparable_profiles.length === 0 ? "Hacen falta al menos 2 corridas del mismo perfil para comparar." : "Ningún valor con forma de identificador se repitió entre corridas limpias."}</Empty> : (
        <ul className="space-y-2">
          {data.items.map((item, index) => (
            <li key={index} className="panel p-2 text-sm" data-testid="persistent-id" data-parameter={item.parameter} data-changes={String(item.changes_with_profile)}>
              <EvidenceBadge level={item.level} /> <Captured value={item.claim} limit={400} /> <span className="muted">Perfil: {item.profile}. {entityLabel(item.entity)}.</span>
              <div><EvidenceBadge level={item.inference_level} /> {item.inference}</div>
              {item.across_profiles.map((other) => (
                <div key={other.profile} className="ml-4" data-testid="persistent-id-profile" data-result={other.result}>
                  Con el perfil <span className="captured">{other.profile}</span>:{" "}
                  {other.result === "SE_MANTIENE" ? "el valor se mantiene" : other.result === "CAMBIA" ? "el valor cambia por completo" : `cambia, pero se mantiene la parte ${other.kept_parts.join(", ")}`}.
                </div>
              ))}
              <div>Evidencia: <Evidence items={item.evidence} /></div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/** Motivo de los scans que no terminaron: código y mensaje, agrupados. El mensaje viene del worker: es texto. */
function Failures({ items }) {
  if (!items.length) return <span className="muted">ninguno</span>;
  return (
    <ul className="space-y-1">
      {items.map((item) => (
        <li key={`${item.error_code}-${item.message}`} data-testid="failure" data-code={item.error_code}>
          <strong>{item.count}</strong> × <span className="captured text-xs">{String(item.error_code)}</span>{" "}
          <span>{errorMessage({ error_code: item.error_code, message: item.message })}</span>
        </li>
      ))}
    </ul>
  );
}

function Result({ data, profiles }) {
  const result = data.result;
  return (
    <div className="space-y-4" data-testid="privacy-result">
      {result.conclusion && (
        <div data-testid="conclusion" data-kind={result.conclusion.kind}>
          <Plain text={result.conclusion.text} level={result.conclusion.level} testId="conclusion-text" />
        </div>
      )}
      <Panel title="Reporte" testId="privacy-report">
        <ReportDownloads subject="group" subjectId={data.group_id} />
      </Panel>
      <Panel title="Resumen por combinación" subtitle="Mediana de las corridas, con su rango entre paréntesis." testId="cells">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Combinación</th><th className="pr-2">Corridas</th><th className="pr-2">Requests</th><th className="pr-2">Dominios de terceros</th><th className="pr-2">Requests de rastreo</th><th>Scans fallidos</th></tr></thead>
            <tbody>
              {result.cells.map((cell) => (
                <tr key={cell.key} className="border-b border-slate-200 align-top" data-testid="cell" data-key={cell.key}>
                  <td className="py-1 pr-2">{cellLabel(cell, profiles)}</td><td className="pr-2">{cell.completed} de {cell.runs}</td>
                  <td className="pr-2">{formatStats(cell.requests)}</td><td className="pr-2">{formatStats(cell.third_party_domains)}</td><td className="pr-2">{formatStats(cell.tracker_requests)}</td>
                  <td data-testid="cell-failures"><Failures items={cell.failures || []} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.cells.map((cell) => (
          <details key={cell.key} className="mt-2" data-testid="stability" data-key={cell.key}>
            <summary className="link text-sm">Trackers de «{cellLabel(cell, profiles)}» y su estabilidad</summary>
            {cell.tracker_domains.length === 0 ? <Empty>Sin dominios de tracking.</Empty> : (
              <ul className="text-sm ml-4 list-disc">
                {cell.tracker_domains.map((domain) => (
                  <li key={domain.domain} data-testid="stability-item"><span className="captured">{domain.domain}</span> · {entityLabel(domain.entity)} · apareció en {domain.appeared} de {domain.of} corridas</li>
                ))}
              </ul>
            )}
          </details>
        ))}
      </Panel>

      {result.tracker_differences.length > 0 && (
        <Panel title="Diferencias de rastreadores entre combinaciones" subtitle="Dominios cuya presencia no fue igual en todas." testId="differences"
          info={<><strong>Diferencias</strong>: con pocas corridas, una diferencia puede ser variación normal del sitio.</>}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left border-b border-slate-400"><th className="pr-2">Dominio</th>{result.cells.map((cell) => <th key={cell.key} className="pr-2">{cellLabel(cell, profiles)}</th>)}</tr></thead>
              <tbody>
                {result.tracker_differences.map((row) => (
                  <tr key={row.domain} className="border-b border-slate-200" data-testid="difference">
                    <td className="py-1 pr-2"><span className="captured">{row.domain}</span> <span className="muted">{entityLabel(row.entity)}</span></td>
                    {result.cells.map((cell) => <td key={cell.key} className="pr-2">{row.by_cell[cell.key].appeared} de {row.by_cell[cell.key].of}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Consent consent={result.consent} />
      <Profiles data={result.profiles} profiles={profiles} />
      <PersistentIds data={result.persistent_ids} accountIds={result.account_ids || []} />

      <details className="panel p-3 border-amber-600 bg-amber-50 text-sm" data-testid="privacy-limits">
        <summary className="cursor-pointer font-bold">Límites de la medición</summary>
        <ul className="list-disc ml-5 mt-2" data-testid="privacy-limitations">{result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </details>
    </div>
  );
}

function Group({ groupId }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [profiles, setProfiles] = useState([]);
  useEffect(() => {
    let alive = true;
    let timer = null;
    setData(null);
    api.privacyProfiles().then((meta) => alive && setProfiles(meta.profiles), () => {});
    const poll = () => api.privacyTest(groupId).then(
      (next) => { if (!alive) return; setData(next); if (next.status !== "completed") timer = setTimeout(poll, 1000); },
      (failure) => alive && setError(failure),
    );
    poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [groupId]);
  if (error) return <ErrorNotice error={error} />;
  if (!data) return <Loading what="el test" />;
  return (
    <div className="space-y-4">
      <Panel title="Análisis con opciones avanzadas" subtitle="Varias visitas al mismo sitio, comparadas.">
        <p data-testid="privacy-url"><Captured value={data.url} limit={100} /></p>
        {data.url_cleaned && (
          <p className="muted text-xs" data-testid="url-cleaned">
            URL limpiada: se quitaron {data.removed_params.map((name, index) => <span key={name}>{index > 0 && ", "}<span className="captured">{name}</span></span>)}. Original: <Captured value={data.original_url} limit={80} />
          </p>
        )}
        <p className="text-sm" data-testid="privacy-progress" data-status={data.status}>
          {data.status === "completed" ? "Completado" : "En curso"}: <strong>{data.progress.done}</strong> de <strong>{data.progress.total}</strong> scans terminados
          {data.progress.failed > 0 && <span> ({data.progress.failed} fallidos)</span>}.
        </p>
        <ol className="flex flex-wrap gap-1 mt-2">
          {data.jobs.map((job) => {
            const done = job.status === "failed" || (job.status === "completed" && ["completed", "failed"].includes(job.analysis_status));
            return (
              <li key={job.job_id} className={`rounded border px-2 py-0.5 text-xs ${job.status === "failed" ? "bg-red-100 border-red-700" : done ? "bg-emerald-100 border-emerald-700" : "border-slate-400 muted"}`} data-testid="group-job" data-done={String(done)}>
                {done ? <Link to={["scan", job.job_id]}>{SCENARIO_LABELS[job.scenario]} · {profileLabel(job.profile, profiles)} · #{job.run}</Link> : <span>{SCENARIO_LABELS[job.scenario]} · {profileLabel(job.profile, profiles)} · #{job.run}</span>}
              </li>
            );
          })}
        </ol>
      </Panel>
      {/* Mismo componente que un scan suelto: la etapa real de la corrida que se está midiendo. */}
      {data.status !== "completed" && (data.progress.active || []).map((run) => (
        <StageProgress key={run.job_id} testId="group-progress" title="Progreso de la corrida en curso" progress={run} run={{ index: run.index, of: run.of }}>
          <p className="muted text-sm mt-2" data-testid="group-progress-run">
            {SCENARIO_LABELS[run.scenario] || "Sin escenario"} · {profileLabel(run.profile, profiles)} · corrida #{run.run}
          </p>
        </StageProgress>
      ))}
      {data.result && <Result data={data} profiles={profiles} />}
    </div>
  );
}

export default function PrivacyTest({ groupId }) {
  return <Group groupId={groupId} />;
}
