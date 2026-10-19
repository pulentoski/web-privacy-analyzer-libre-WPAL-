// Analizar un sitio (v1.2). Sin opciones avanzadas = scan simple (una visita). Con ellas =
// grupo de scans: respuestas al banner de consentimiento × perfiles de navegador × corridas
// (lo que antes era la página «Privacy Test»).
import { useEffect, useRef, useState } from "react";

import { Icon } from "../components/Icons.jsx";
import { Captured, ErrorNotice, Info, Panel } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { SCENARIO_LABELS, testSize, validateScanUrl } from "../lib/format.js";
import { navigate } from "../lib/router.js";
import HarImport from "./HarImport.jsx";
import InteractiveCapture from "./InteractiveCapture.jsx";
import { VisitComparisonStart } from "./VisitComparison.jsx";

const DEFAULT_SCENARIOS = ["sin_interaccion"];
const DEFAULT_PROFILES = ["real"];

/** true si la selección equivale a un scan simple: una visita, sin interacción, con el navegador real. */
export function isSimpleScan(scenarios, profiles, runs) {
  return Number(runs) === 1 && scenarios.length === 1 && scenarios[0] === "sin_interaccion" && profiles.length === 1 && profiles[0] === "real";
}

function Toggle({ checked, onChange, children, testId }) {
  return (
    <label className="flex items-start gap-2 text-sm">
      <input type="checkbox" className="mt-1" checked={checked} onChange={(event) => onChange(event.target.checked)} data-testid={testId} />
      <span>{children}</span>
    </label>
  );
}

/** Aviso de parámetros de seguimiento en la URL, con «Limpiar URL» y la opción de mantenerla. */
function TrackingNotice({ inspection, keep, onClean, onKeep }) {
  if (!inspection || !inspection.has_tracking_params) return null;
  return (
    <div className="panel p-3 border-amber-600 bg-amber-50 text-sm space-y-2" role="status" data-testid="tracking-notice">
      <p>
        <strong>La URL trae parámetros de seguimiento:</strong>{" "}
        <span data-testid="tracking-params">{inspection.tracking_params.map((name, index) => <span key={name}>{index > 0 && ", "}<span className="captured">{name}</span></span>)}</span>.{" "}
        <Info label="Parámetros de seguimiento">
          <strong>Parámetros de seguimiento</strong>: identificadores de clic y etiquetas de campaña (gclid, fbclid, utm_*…) que quedan en la URL
          al llegar desde un anuncio o un correo. Si se escanea con ellos, el sitio los reenvía a sus proveedores y el resultado describe esa
          visita etiquetada, no una visita directa. Se guardan la URL original y la escaneada.
        </Info>
      </p>
      <p data-testid="tracking-decision">
        {keep
          ? <>Se escaneará <strong>tal como está</strong>, con esos parámetros.</>
          : <>Se escaneará <strong>sin ellos</strong>: <Captured value={inspection.cleaned_url} limit={110} /></>}
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="btn text-sm" onClick={onClean} data-testid="clean-url">Limpiar URL</button>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={keep} onChange={(event) => onKeep(event.target.checked)} data-testid="keep-url" />
          <span>Mantener la URL original</span>
        </label>
      </div>
    </div>
  );
}

function Health() {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let alive = true;
    const load = () => api.health().then((data) => alive && setHealth(data), () => alive && setHealth({ status: "sin conexión", database: false, worker: false }));
    load();
    const timer = setInterval(load, 5000);
    return () => { alive = false; clearInterval(timer); };
  }, []);
  if (health === null) return null;
  return (
    <section className="mode p-3" data-mode="status" data-testid="mode-status">
      <h3 className="mode-title text-sm"><Icon name="pulse" /> Estado del sistema</h3>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm muted" data-testid="health">
        <li>Sistema: <strong>{health.status === "ok" ? "operativo" : String(health.status)}</strong></li>
        <li>Base de datos: <strong>{health.database ? "disponible" : "no disponible"}</strong></li>
        <li>Worker: <strong>{health.worker ? "activo" : "sin señal"}</strong></li>
      </ul>
    </section>
  );
}

export default function Analyze({ advanced = false }) {
  const [url, setUrl] = useState("");
  const [inspection, setInspection] = useState(null);
  const [keep, setKeep] = useState(false);
  const [open, setOpen] = useState(advanced);
  const [meta, setMeta] = useState(null);
  const [scenarios, setScenarios] = useState(DEFAULT_SCENARIOS);
  const [profiles, setProfiles] = useState(DEFAULT_PROFILES);
  const [runs, setRuns] = useState(1);
  const [fieldError, setFieldError] = useState(null);
  const [error, setError] = useState(null);
  const [sending, setSending] = useState(false);
  const sequence = useRef(0);

  useEffect(() => { setOpen(advanced); }, [advanced]);
  useEffect(() => { api.privacyProfiles().then(setMeta, () => setMeta(null)); }, []);

  // La detección la hace el servidor (misma lista que usa al crear el scan); aquí solo se muestra.
  useEffect(() => {
    const text = url.trim();
    const current = ++sequence.current;
    if (!/^https?:\/\/.+\?/i.test(text)) {
      setInspection(null);
      return undefined;
    }
    const timer = setTimeout(() => {
      api.inspectUrl(text).then((data) => current === sequence.current && setInspection(data), () => current === sequence.current && setInspection(null));
    }, 250);
    return () => clearTimeout(timer);
  }, [url]);

  const toggle = (list, setList, value) => (on) => setList(on ? [...list, value] : list.filter((item) => item !== value));
  const size = testSize(scenarios, profiles, runs);
  const simple = !open || isSimpleScan(scenarios, profiles, runs);
  const tooBig = !simple && meta !== null && size > meta.max_group_jobs;

  const submit = (event) => {
    event.preventDefault();
    setError(null);
    const problem = validateScanUrl(url) || (!simple && size === 0 ? "Elija al menos un escenario y un perfil." : null);
    setFieldError(problem);
    if (problem || tooBig) return;
    setSending(true);
    const fail = (failure) => { setError(failure); setSending(false); };
    if (simple) api.createScan(url.trim(), !keep).then((scan) => navigate(["scan", scan.job_id]), fail);
    else api.privacyCreate({ url: url.trim(), scenarios, profiles, runs, clean_url: !keep }).then((group) => navigate(["privacy", group.group_id]), fail);
  };

  return (
    <div className="space-y-4" data-testid="analyze">
      <Panel title="Analizar un sitio" subtitle="Una visita con un navegador automatizado, sin iniciar sesión.">
        <div className="analyze-layout">
        <form onSubmit={submit} noValidate className="space-y-3 min-w-0">
          <section className="mode p-3 space-y-3" data-mode="scan" data-testid="mode-scan">
          <h3 className="mode-title"><Icon name="search" /> Scan simple</h3>
          <div>
            <label htmlFor="url" className="block text-sm font-medium">URL del sitio (http o https)</label>
            <div className="flex gap-2">
              <input
                id="url" name="url" type="url" inputMode="url" autoComplete="off" spellCheck={false} maxLength={2048}
                className="flex-1 border border-slate-400 rounded px-2 py-1.5 captured" placeholder="https://ejemplo.cl"
                value={url} onChange={(event) => setUrl(event.target.value)} aria-invalid={Boolean(fieldError)}
              />
              <button type="submit" disabled={sending || tooBig || (!simple && size === 0)} className="btn btn-primary btn-mode" data-testid="analyze-submit">
                {sending ? "Enviando…" : simple ? "Analizar" : `Analizar (${size} scans)`}
              </button>
            </div>
          </div>
          {fieldError && <p role="alert" className="text-red-800 text-sm" data-testid="field-error">{fieldError}</p>}
          <TrackingNotice inspection={inspection} keep={keep} onKeep={setKeep}
            onClean={() => { setKeep(false); setUrl(inspection.cleaned_url); }} />
          </section>

          <details className="panel mode p-3" data-mode="advanced" open={open} onToggle={(event) => setOpen(event.currentTarget.open)} data-testid="advanced">
            <summary className="cursor-pointer font-bold mode-title" data-testid="advanced-toggle"><Icon name="sliders" /> Opciones avanzadas</summary>
            {meta === null ? <p className="muted text-sm mt-2">Las opciones avanzadas no están disponibles en este momento.</p> : (
              <div className="mt-3 space-y-3">
                <div className="grid gap-4 md:grid-cols-3">
                  <fieldset className="mode p-2" data-mode="consent" data-testid="mode-consent">
                    <legend className="font-medium text-sm mode-title">
                      <Icon name="check" className="w-4 h-4" /> Consentimiento{" "}
                      <Info label="Consentimiento">
                        <strong>Consentimiento</strong>: respuesta al banner de cookies en cada visita. Solo se pulsa un botón si el banner es de
                        una plataforma reconocida; si no, el escenario queda «no aplicable» y no se pulsa nada.
                      </Info>
                    </legend>
                    {meta.scenarios.map((scenario) => (
                      <Toggle key={scenario} checked={scenarios.includes(scenario)} onChange={toggle(scenarios, setScenarios, scenario)} testId={`scenario-${scenario}`}>
                        {SCENARIO_LABELS[scenario]}
                      </Toggle>
                    ))}
                  </fieldset>
                  <fieldset className="mode p-2" data-mode="profile" data-testid="mode-profile">
                    <legend className="font-medium text-sm mode-title">
                      <Icon name="user" className="w-4 h-4" /> Perfil del navegador{" "}
                      <Info label="Perfil del navegador">
                        <strong>Perfil</strong>: lo que el navegador del worker declara ser (User-Agent, pantalla, zona horaria, GPU). <span data-testid="ip-note">{meta.note}</span>
                      </Info>
                    </legend>
                    {meta.profiles.map((profile) => (
                      <Toggle key={profile.name} checked={profiles.includes(profile.name)} onChange={toggle(profiles, setProfiles, profile.name)} testId={`profile-${profile.name}`}>
                        {profile.coherent ? profile.label
                          : <span className="mode-warning" data-testid="profile-incoherent">{profile.label} <strong>⚠ incoherente</strong></span>}
                      </Toggle>
                    ))}
                  </fieldset>
                  <div className="mode p-2" data-mode="runs" data-testid="mode-runs">
                    <label htmlFor="privacy-runs" className="font-medium text-sm mode-title"><Icon name="repeat" className="w-4 h-4" /> Corridas por combinación</label>{" "}
                    <Info label="Corridas">
                      <strong>Corridas</strong>: un sitio no responde igual en cada visita. Con una sola corrida no se puede distinguir un cambio
                      real de la variación normal. Cada visita empieza con un navegador limpio, sin cookies.
                    </Info>
                    <div>
                      <select id="privacy-runs" className="border border-slate-400 rounded px-2 py-1 bg-white" value={runs} onChange={(event) => setRuns(Number(event.target.value))} data-testid="runs">
                        {Array.from({ length: meta.max_runs }, (_, i) => i + 1).map((n) => <option key={n} value={n}>{n}</option>)}
                      </select>
                    </div>
                  </div>
                </div>
                <p className="text-sm" data-testid="test-size" data-simple={String(simple)}>
                  {simple
                    ? <>Selección por defecto: <strong>scan simple</strong> (1 visita).</>
                    : <>Esta selección son <strong>{size}</strong> scans (máximo {meta.max_group_jobs}).{tooBig && <strong className="text-red-800"> Reduzca escenarios, perfiles o corridas.</strong>}</>}
                </p>
              </div>
            )}
          </details>
        </form>
        {/* Imagen propia, servida localmente (CSP sin cambios). Decorativa: el texto está en el título. */}
        <picture className="analyze-art" data-testid="analyze-art">
          <source srcSet="/analizar-720.webp" type="image/webp" />
          <img src="/analizar-720.jpg" width="720" height="720" loading="lazy" decoding="async"
            alt="Ilustración de Web Privacy & Tracker Analyzer: un pingüino con una lupa y un portátil" />
        </picture>
        </div>
        <div className="mt-3"><ErrorNotice error={error} /></div>
        <div className="mt-3"><Health /></div>
      </Panel>
      <VisitComparisonStart url={url} cleanUrl={!keep} />
      <InteractiveCapture url={url} cleanUrl={!keep} />
      <HarImport />
    </div>
  );
}
