// Importar archivo HAR (v1.3): una captura hecha por el navegador real del usuario pasa por el
// mismo analizador que un scan. Todo lo que trae el HAR es dato no confiable: se muestra como texto.
import { useRef, useState } from "react";

import { Captured, ErrorNotice, Panel, ScanSpinner } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { navigate } from "../lib/router.js";

export const HAR_MAX_BYTES = 50 * 1024 * 1024;

/** Hora de la carga en UTC, como la escribe el HAR (así coincide con lo que muestra DevTools en UTC). */
export function loadTime(iso) {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(String(iso || ""));
  return match ? `${match[1]} ${match[2]} UTC` : "hora no disponible";
}

/** Mensaje de error del archivo elegido, o null si se puede enviar. */
export function harFileProblem(file) {
  if (!file) return "Elija un archivo HAR.";
  if (file.size === 0) return "El archivo está vacío.";
  if (file.size > HAR_MAX_BYTES) return "El archivo supera el máximo de 50 MB.";
  return null;
}

export default function HarImport() {
  const [file, setFile] = useState(null);
  const [info, setInfo] = useState(null);
  const [load, setLoad] = useState(null);
  const [busy, setBusy] = useState(null);
  const [problem, setProblem] = useState(null);
  const [error, setError] = useState(null);
  const input = useRef(null);

  const choose = (event) => {
    const chosen = event.target.files && event.target.files[0];
    setFile(chosen || null);
    setInfo(null);
    setLoad(null);
    setError(null);
    const issue = harFileProblem(chosen);
    setProblem(chosen ? issue : null);
    if (!chosen || issue) return;
    setBusy("inspect");
    api.harInspect(chosen).then(
      (data) => { setInfo(data); setLoad(data.default_load); setBusy(null); },
      (failure) => { setError(failure); setBusy(null); },
    );
  };

  const submit = () => {
    setBusy("import");
    setError(null);
    api.harImport(file, load).then((scan) => navigate(["scan", scan.job_id]), (failure) => { setError(failure); setBusy(null); });
  };

  const sensitive = info ? info.sensitive : null;
  const hasSensitive = sensitive && Object.values(sensitive).some((count) => count > 0);

  return (
    <Panel mode="har" icon="file" title="Importar archivo HAR" subtitle="Analice una captura hecha con su propio navegador (DevTools → Red → Exportar HAR). Máximo 50 MB." testId="har-import">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2" data-testid="har-picker">
          {/* El selector nativo se ve como texto plano: lo abre un botón propio (accesible por teclado). */}
          <input ref={input} id="har-file" type="file" accept=".har,application/json" onChange={choose} disabled={busy !== null}
            data-testid="har-file" aria-label="Archivo HAR" hidden tabIndex={-1} />
          <button type="button" className="btn" onClick={() => input.current && input.current.click()} disabled={busy !== null}
            aria-describedby="har-file-name" data-testid="har-choose">
            Seleccionar archivo .har
          </button>
          <span id="har-file-name" className="text-sm break-all" aria-live="polite" data-testid="har-file-name">
            {file ? <Captured value={file.name} limit={80} expandable={false} /> : <span className="muted">Ningún archivo seleccionado</span>}
          </span>
        </div>
        <p className="text-sm" data-testid="har-source-note">
          <strong>Captura importada: navegador real del usuario.</strong> Se aplica el mismo análisis que a un scan, pero{" "}
          <strong>sin fingerprinting instrumentado</strong>: un HAR solo registra tráfico de red.
        </p>
        {problem && <p role="alert" className="text-red-800 text-sm" data-testid="har-problem">{problem}</p>}
        {busy === "inspect" && <p className="muted text-sm" role="status">Revisando el archivo…</p>}
        {info && (
          <div className="space-y-3" data-testid="har-inspection">
            <p className="text-sm" role={hasSensitive ? "alert" : undefined} data-testid="har-sensitive" data-sensitive={String(Boolean(hasSensitive))}>
              {hasSensitive ? (
                <>
                  <strong>Atención: el archivo contiene datos de sesión.</strong> Cookie: {sensitive.cookie} · Set-Cookie: {sensitive.set_cookie} ·
                  Authorization: {sensitive.authorization} · cookies registradas: {sensitive.cookie_objects}. Sus valores se{" "}
                  <strong>descartan antes de guardar</strong>: solo se conservan el nombre de la cabecera y el largo del valor.
                </>
              ) : "El archivo no trae cabeceras Cookie, Set-Cookie ni Authorization (0 cookies)."}
            </p>
            <fieldset>
              <legend className="font-medium text-sm">
                {info.loads.length > 1 ? `El archivo contiene ${info.loads.length} cargas. Elija cuál analizar:` : "Carga encontrada en el archivo:"}
              </legend>
              <div className="overflow-x-auto">
                <table className="w-full text-sm" data-testid="har-loads">
                  <thead>
                    <tr className="text-left">
                      <th className="pr-2"></th><th className="pr-2">Hora de inicio</th><th className="pr-2">Página</th><th className="pr-2">Requests</th>
                      <th className="pr-2">Bloqueadas por una extensión del navegador</th><th className="pr-2">Origen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {info.loads.map((item) => (
                      <tr key={item.id} data-testid="har-load" data-load={item.id} data-selected={String(load === item.id)}>
                        <td className="pr-2">
                          <input type="radio" name="har-load" checked={load === item.id} onChange={() => setLoad(item.id)}
                            aria-label={`Carga de las ${loadTime(item.started_at)}`} data-testid={`har-load-${item.id}`} />
                        </td>
                        <td className="pr-2 whitespace-nowrap">{loadTime(item.started_at)}</td>
                        <td className="pr-2"><Captured value={item.page_url || "no_disponible"} limit={60} expandable={false} /></td>
                        <td className="pr-2">{item.requests}</td>
                        <td className="pr-2">{item.blocked_by_client}</td>
                        <td className="pr-2">{item.kind === "page" ? "página del HAR (pageref)" : "sin página: agrupadas por tiempo"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </fieldset>
            <p className="muted text-xs">
              Archivo: {info.entries_total} entradas{info.entries_ignored ? ` (${info.entries_ignored} ignoradas por no ser requests http/https válidas)` : ""}
              {info.creator ? <> · generado por <Captured value={info.creator} limit={60} expandable={false} /></> : null}.
              El archivo original no se guarda.
            </p>
          </div>
        )}
        <div>
          <button type="button" className="btn btn-primary btn-mode" onClick={submit} disabled={busy !== null || !file || !load} data-testid="har-submit"
            aria-describedby={file ? undefined : "har-submit-hint"}>
            {busy === "import" ? "Importando…" : "Importar y analizar"}
          </button>
          {busy === "import" && <span className="inline-block align-middle ml-3"><ScanSpinner label="Importación del HAR en curso" testId="har-spinner" /></span>}
          {!file && <span id="har-submit-hint" className="muted text-xs ml-2" data-testid="har-submit-hint">Primero seleccione un archivo.</span>}
        </div>
        <ErrorNotice error={error} />
      </div>
    </Panel>
  );
}
