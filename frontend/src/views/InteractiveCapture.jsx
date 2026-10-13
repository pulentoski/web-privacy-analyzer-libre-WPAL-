// Captura interactiva (v1.4, docs/adr/029): el usuario navega en el Chromium del worker (visto
// por noVNC) y al detener se analiza toda la sesión con el mismo analizador que un scan.
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";

import { Captured, ErrorNotice, Panel, ScanSpinner } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { validateScanUrl } from "../lib/format.js";
import { navigate } from "../lib/router.js";

const VncScreen = lazy(() => import("../components/VncScreen.jsx"));
const POLL_MS = 2000;
const KEY = (jobId) => `interactive:${jobId}`;

export const INTERACTIVE_WARNING =
  "Lo que escriba en ese navegador (búsquedas, formularios) y las cookies de la sesión quedan guardados en la captura. " +
  "Las contraseñas y otros campos de credenciales se enmascaran antes de guardar, pero las cookies de una sesión iniciada no. " +
  "No inicie sesión con cuentas reales si va a compartir el reporte.";

/** mm:ss de un número de segundos; «—» si no se conoce. */
export function clock(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "—";
  const whole = Math.floor(seconds);
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, "0")}`;
}

function readCredentials(jobId) {
  try {
    const raw = JSON.parse(window.sessionStorage.getItem(KEY(jobId)) || "null");
    return raw && typeof raw.token === "string" && typeof raw.password === "string" ? raw : null;
  } catch {
    return null;
  }
}

function storeCredentials(jobId, value) {
  try {
    if (value) window.sessionStorage.setItem(KEY(jobId), JSON.stringify(value));
    else window.sessionStorage.removeItem(KEY(jobId));
  } catch {
    /* sin almacenamiento: la sesión solo se ve mientras dure esta vista */
  }
}

export default function InteractiveCapture({ url, cleanUrl = true }) {
  const [status, setStatus] = useState(null);
  const [credentials, setCredentials] = useState(null);
  const [busy, setBusy] = useState(null);
  const [problem, setProblem] = useState(null);
  const [error, setError] = useState(null);
  const followed = useRef(null);

  const refresh = useCallback(() => api.interactiveStatus().then(setStatus, () => setStatus({ enabled: true, session: null, unreachable: true })), []);
  const session = status ? status.session : null;
  const jobId = session ? session.job_id : null;

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (!jobId) return undefined;
    followed.current = jobId;
    setCredentials((current) => current || readCredentials(jobId));
    const timer = setInterval(refresh, POLL_MS);
    return () => clearInterval(timer);
  }, [jobId, refresh]);
  // La sesión terminó (botón, inactividad o duración máxima): su resultado está en la página del scan.
  useEffect(() => {
    if (status && !session && followed.current) {
      const finished = followed.current;
      followed.current = null;
      storeCredentials(finished, null);
      navigate(["scan", finished]);
    }
  }, [status, session]);

  const start = () => {
    setError(null);
    const issue = validateScanUrl(url);
    setProblem(issue);
    if (issue) return;
    setBusy("start");
    api.interactiveStart(url.trim(), cleanUrl).then(
      (created) => {
        const value = { token: created.token, password: created.vnc_password };
        storeCredentials(created.job_id, value);
        setCredentials(value);
        setBusy(null);
        refresh();
      },
      (failure) => { setError(failure); setBusy(null); refresh(); },
    );
  };

  const stop = () => {
    setBusy("stop");
    api.interactiveStop(jobId).then(refresh, (failure) => { setError(failure); setBusy(null); });
  };

  if (status === null || status.enabled === false) return null;
  const ready = session && session.state === "ready";
  const stopping = session && session.state === "stopping";

  return (
    <Panel title="Captura interactiva" testId="interactive" mode="interactive" icon="pointer"
      subtitle="Usted navega en el navegador del analizador; al detener, se analiza toda la sesión con el mismo analizador que un scan.">
      <p className="panel hazard p-3 border-amber-600 bg-amber-50 text-sm" role="status" data-testid="interactive-warning">
        <strong>Antes de empezar:</strong> {INTERACTIVE_WARNING}
      </p>
      {!session && (
        <div className="mt-3 space-y-2">
          <p className="text-sm muted">
            Usa la URL escrita arriba. Una sesión a la vez; se cierra sola tras 10 minutos sin actividad o a los 30 minutos (valores por defecto).
          </p>
          <button type="button" className="btn btn-primary btn-mode" disabled={busy === "start"} onClick={start} data-testid="interactive-start">
            {busy === "start" ? "Iniciando…" : "Iniciar captura interactiva"}
          </button>
          {problem && <p role="alert" className="text-red-800 text-sm" data-testid="interactive-problem">{problem}</p>}
        </div>
      )}
      {session && (
        <div className="mt-3 space-y-3" data-testid="interactive-session" data-state={session.state}>
          <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <ul className="flex flex-wrap gap-x-4 gap-y-1">
              <li>Sitio inicial: <Captured value={session.url} limit={60} expandable={false} /></li>
              <li>Requests capturadas: <strong data-testid="interactive-requests">{session.requests ?? "—"}</strong></li>
              <li>Tiempo restante: <strong data-testid="interactive-remaining">{clock(session.remaining_s)}</strong></li>
              <li>Cierre por inactividad en: <strong data-testid="interactive-idle">{clock(session.idle_remaining_s)}</strong></li>
            </ul>
            <button type="button" className="btn btn-primary" disabled={busy === "stop" || stopping} onClick={stop} data-testid="interactive-stop">
              {busy === "stop" || stopping ? "Deteniendo…" : "Detener y analizar"}
            </button>
          </div>
          {!ready && !stopping && <div className="flex items-center gap-3"><ScanSpinner label="Abriendo el navegador" testId="interactive-spinner" /><p className="text-sm">Abriendo el navegador…</p></div>}
          {stopping && <p className="text-sm" data-testid="interactive-stopping">Cerrando el navegador y guardando la captura…</p>}
          {ready && credentials && (
            <Suspense fallback={<p className="text-sm muted">Cargando el visor…</p>}>
              <VncScreen jobId={session.job_id} token={credentials.token} password={credentials.password} />
            </Suspense>
          )}
          {ready && !credentials && (
            <p className="text-sm" data-testid="interactive-elsewhere">
              Esta captura se inició en otra pestaña o ventana: la pantalla solo se muestra allí. Desde aquí puede detenerla.
            </p>
          )}
        </div>
      )}
      <div className="mt-3"><ErrorNotice error={error} /></div>
    </Panel>
  );
}
