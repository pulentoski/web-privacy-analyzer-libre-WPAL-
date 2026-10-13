// Descarga del reporte exportable (F8): HTML autocontenido y PDF, de un scan o de un Privacy Test.
// Exportar crea una instantánea en el servidor; el PDF lo genera el worker y se espera aquí.
import { useState } from "react";

import { api } from "../lib/api.js";
import { ErrorNotice } from "./ui.jsx";

const POLL_MS = 1500;
const PDF_TIMEOUT_MS = 150000;
const BUTTON = "rounded border border-blue-700 text-blue-800 px-3 py-1.5 font-semibold disabled:opacity-50";

function save(url) {
  const link = document.createElement("a");
  link.href = url;
  link.download = "";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export default function ReportDownloads({ subject, subjectId }) {
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [sha256, setSha256] = useState(null);

  async function download(kind) {
    setBusy(kind);
    setError(null);
    try {
      let status = await api.exportCreate(subject, subjectId, reveal);
      const started = Date.now();
      while (kind === "pdf" && status.files.pdf.status !== "ready") {
        if (status.files.pdf.status === "failed") throw { error_code: "EXPORT_FAILED", message: "No se pudo generar el PDF." };
        if (Date.now() - started > PDF_TIMEOUT_MS) throw { error_code: "EXPORT_TIMEOUT", message: "El PDF está tardando demasiado. Intente de nuevo." };
        await wait(POLL_MS);
        status = await api.exportStatus(subject, subjectId, reveal);
      }
      setSha256(status.sha256);
      save(api.exportFileUrl(subject, subjectId, kind, reveal));
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-2" data-testid="report-downloads">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BUTTON} disabled={busy !== null} onClick={() => download("pdf")} data-testid="download-pdf">
          {busy === "pdf" ? "Generando PDF…" : "Descargar PDF"}
        </button>
        <button type="button" className={BUTTON} disabled={busy !== null} onClick={() => download("html")} data-testid="download-html">
          {busy === "html" ? "Generando HTML…" : "Descargar HTML"}
        </button>
        <label className="text-sm flex items-center gap-1">
          <input type="checkbox" checked={reveal} disabled={busy !== null} onChange={(event) => setReveal(event.target.checked)} data-testid="download-reveal" />
          Mostrar identificadores completos
        </label>
      </div>
      <p className="muted text-xs" data-testid="download-masking">
        {reveal
          ? "El reporte incluirá los valores completos: trátelo como un documento sensible."
          : "Por defecto los identificadores van enmascarados (prefijo y largo)."}
      </p>
      {sha256 && <p className="muted text-xs">sha256 del JSON del reporte: <span className="captured" data-testid="download-sha256">{sha256}</span></p>}
      <ErrorNotice error={error} />
    </div>
  );
}
