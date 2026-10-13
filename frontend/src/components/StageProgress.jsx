// Barra de progreso por etapas (F10). Todo lo que muestra es un dato publicado por el worker
// o derivado del reloj: etapa actual, requests capturadas, segundos transcurridos frente al
// máximo configurado (SCAN_TIMEOUT_S). No hay porcentajes estimados.
// La usan un scan suelto y los grupos de Privacy Test (corrida k de N).
import { useEffect, useState } from "react";

import { PROGRESS_STAGES, stageIndex } from "../lib/format.js";
import { ScanSpinner } from "./ui.jsx";

/** Segundos de captura: entre consultas a la API, el reloj local sigue contando (solo en curso). */
function useElapsed(progress) {
  const running = progress.stage === "opening" || progress.stage === "capturing";
  const base = typeof progress.capture_elapsed_s === "number" ? progress.capture_elapsed_s : null;
  const [extra, setExtra] = useState(0);
  useEffect(() => {
    setExtra(0);
    if (!running || base === null) return undefined;
    const started = Date.now();
    const timer = setInterval(() => setExtra((Date.now() - started) / 1000), 250);
    return () => clearInterval(timer);
  }, [running, base]);
  return base === null ? null : base + (running ? extra : 0);
}

function Counter({ progress }) {
  const { stage, requests } = progress;
  if (stage === "queued") {
    return typeof progress.queue_position === "number" ? <span className="stage-counter" data-testid="queue-position">puesto {progress.queue_position} en la cola</span> : null;
  }
  if (typeof requests !== "number") return null;
  return (
    <span className="stage-counter">
      <strong data-testid="progress-requests">{requests}</strong> {requests === 1 ? "request capturada" : "requests capturadas"}
      {stage === "capturing" ? " hasta ahora" : ""}
    </span>
  );
}

function TimeMeter({ progress }) {
  const elapsed = useElapsed(progress);
  const max = typeof progress.capture_max_s === "number" && progress.capture_max_s > 0 ? progress.capture_max_s : null;
  if (elapsed === null) return null;
  const running = progress.stage === "opening" || progress.stage === "capturing";
  const shown = max === null ? elapsed : Math.min(elapsed, max);
  return (
    <div className="text-sm" data-testid="progress-time">
      {running ? "Tiempo de captura: " : "La captura tomó "}
      <strong data-testid="progress-elapsed">{shown.toFixed(running ? 0 : 1)}</strong> s
      {max !== null && <> de un máximo de <strong data-testid="progress-max">{max}</strong> s</>}
      {max !== null && (
        <div className="timebar mt-1" role="meter" aria-label="Tiempo de captura transcurrido" aria-valuemin={0} aria-valuemax={max} aria-valuenow={Math.round(shown)}>
          {/* Ancho = segundos medidos / máximo configurado. No es una estimación de avance. */}
          <div className="timebar-fill" style={{ width: `${(shown / max) * 100}%` }} />
        </div>
      )}
    </div>
  );
}

export default function StageProgress({ progress, title = "Progreso del scan", run, children, testId = "progress" }) {
  if (!progress) return null;
  const failed = progress.stage === "failed";
  const running = !failed && progress.stage !== "done";
  const current = stageIndex(progress.stage);
  const failedAt = failed ? stageIndex(progress.failed_at) : -1;
  const info = PROGRESS_STAGES[Math.max(0, current)];
  return (
    <section className="panel p-4" data-testid={testId} data-stage={progress.stage}>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3 panel-head" data-tone={failed ? "danger" : "alert"}>
        <h2 className="text-lg font-semibold">{title}</h2>
        {run && <span className="font-bold" data-testid="progress-run">Corrida {run.index} de {run.of}</span>}
      </div>
      <div className={running ? "progress-layout" : undefined}>
      {/* Gira solo mientras el proceso está en curso: desaparece al terminar o fallar. */}
      {running && <ScanSpinner />}
      <div className="min-w-0">
      <ol className="stages" aria-label="Etapas">
        {PROGRESS_STAGES.map((item, index) => {
          let state = "pending";
          if (failed) state = failedAt >= 0 && index < failedAt ? "done" : failedAt === index ? "failed" : "pending";
          else if (index < current || progress.stage === "done") state = "done";
          else if (index === current) state = "current";
          return (
            <li key={item.id} className="stage" data-state={state} data-testid={`stage-${item.id}`} aria-current={state === "current" ? "step" : undefined}>
              <span aria-hidden="true">{index + 1}.</span> {item.label}
            </li>
          );
        })}
        {failed && <li className="stage" data-state="failed" data-testid="stage-failed" aria-current="step">Falló</li>}
      </ol>
      {!failed && <p className="mt-2 text-sm" role="status" data-testid="progress-description">{info.description}</p>}
      <div className="mt-2 space-y-2">
        <Counter progress={progress} />
        <TimeMeter progress={progress} />
      </div>
      </div>
      </div>
      {children}
    </section>
  );
}
