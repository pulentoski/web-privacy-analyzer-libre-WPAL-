// Borrado del historial (F10): un scan o todo. Es definitivo, así que «todo» pide escribir
// la palabra de confirmación. En modo demo la API lo rechaza (403) y aquí ni se ofrece.
import { useState } from "react";

import { api } from "../lib/api.js";
import { formatBytes } from "../lib/format.js";
import { Icon } from "./Icons.jsx";
import { ErrorNotice } from "./ui.jsx";

/** "Se borraron 3 scans y 2 reportes. Se liberaron 1.2 MB." */
export function deletedSummary(deleted) {
  if (!deleted) return "";
  const scans = `${deleted.scans} ${deleted.scans === 1 ? "scan" : "scans"}`;
  const groups = deleted.groups ? `, ${deleted.groups} ${deleted.groups === 1 ? "grupo de Opciones avanzadas" : "grupos de Opciones avanzadas"}` : "";
  const reports = ` y ${deleted.reports} ${deleted.reports === 1 ? "reporte exportado" : "reportes exportados"}`;
  const verb = deleted.scans === 1 && !deleted.groups && deleted.reports === 0 ? "Se borró" : "Se borraron";
  return `${verb} ${scans}${groups}${reports}. Se liberaron ${formatBytes(deleted.bytes_freed)} de datos.`;
}

export function DeletedNotice({ result }) {
  if (!result) return null;
  return (
    <div role="status" className="panel p-3 text-sm" data-testid="deleted-notice">
      <strong data-testid="deleted-summary">{deletedSummary(result.deleted)}</strong>{" "}
      <span className="muted">{result.note}</span>
    </div>
  );
}

/** Botón «Borrar este scan», con confirmación en el propio lugar. */
export function DeleteScanButton({ jobId, onDeleted, compact = false }) {
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const confirm = () => {
    setBusy(true);
    setError(null);
    api.deleteScan(jobId).then(
      (result) => onDeleted(result),
      (failure) => {
        setError(failure);
        setBusy(false);
      },
    );
  };
  if (!asking) {
    return (
      <button type="button" className="btn text-sm" onClick={() => setAsking(true)} data-testid="delete-scan">
        <span className="inline-flex items-center gap-1"><Icon name="trash" className="w-4 h-4" /> {compact ? "Borrar" : "Borrar este scan"}</span>
      </button>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-2 text-sm" data-testid="delete-scan-confirm">
      <span>¿Borrar este scan con su captura, análisis y reportes? No se puede deshacer.</span>
      <button type="button" className="btn btn-danger text-sm" disabled={busy} onClick={confirm} data-testid="delete-scan-yes">{busy ? "Borrando…" : "Sí, borrar"}</button>
      <button type="button" className="btn text-sm" disabled={busy} onClick={() => setAsking(false)} data-testid="delete-scan-no">Cancelar</button>
      <ErrorNotice error={error} />
    </span>
  );
}

/** «Borrar todo el historial»: hay que escribir la palabra exacta. */
export function DeleteAllHistory({ stats, onDeleted }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  if (!stats) return null;
  const word = stats.confirmation || "BORRAR";
  if (!stats.delete_enabled) {
    return <p className="muted text-sm" data-testid="delete-disabled">En modo demo no se puede borrar el historial.</p>;
  }
  const submit = (event) => {
    event.preventDefault();
    if (typed !== word) return;
    setBusy(true);
    setError(null);
    api.deleteAllScans(typed).then(
      (result) => {
        setBusy(false);
        setOpen(false);
        setTyped("");
        onDeleted(result);
      },
      (failure) => {
        setError(failure);
        setBusy(false);
      },
    );
  };
  return (
    <div data-testid="delete-all">
      {!open ? (
        <button type="button" className="btn text-sm" disabled={stats.scans === 0} onClick={() => setOpen(true)} data-testid="delete-all-open">
          <span className="inline-flex items-center gap-1"><Icon name="trash" className="w-4 h-4" /> Borrar todo el historial</span>
        </button>
      ) : (
        <form onSubmit={submit} className="panel p-3 space-y-2" data-testid="delete-all-form">
          <p className="text-sm">
            Se borrarán <strong data-testid="delete-all-count">{stats.scans}</strong> scans con sus capturas, análisis y reportes
            {stats.groups ? <>, y <strong>{stats.groups}</strong> grupos de Opciones avanzadas</> : null}. <strong>No se puede deshacer.</strong>{" "}
            Los respaldos de la carpeta backups/ no se tocan.
          </p>
          <label htmlFor="delete-all-word" className="block text-sm font-medium">Para confirmar, escriba {word}</label>
          <div className="flex flex-wrap gap-2">
            <input id="delete-all-word" type="text" className="border border-slate-400 rounded px-2 py-1 captured" autoComplete="off" spellCheck={false}
              maxLength={20} value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="delete-all-input" />
            <button type="submit" className="btn btn-danger text-sm" disabled={busy || typed !== word} data-testid="delete-all-confirm">{busy ? "Borrando…" : "Borrar todo"}</button>
            <button type="button" className="btn text-sm" disabled={busy} onClick={() => { setOpen(false); setTyped(""); }} data-testid="delete-all-cancel">Cancelar</button>
          </div>
          <ErrorNotice error={error} />
        </form>
      )}
    </div>
  );
}
