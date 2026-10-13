// Indicador de recursos (v1.4; consola de mando retro desde v1.4.2, diseño propio): CPU y RAM del
// stack, scans activos y captura interactiva, en la esquina inferior de todas las páginas.
// Versión mini: tres cuadros. Al hacer clic se abre la vista completa (tres placas en triángulo
// alrededor de un círculo, bloque de estado y detalle por contenedor). Consulta GET /api/resources
// cada 5 s y solo con la pestaña visible. Un dato que no se pudo medir se muestra como «—», nunca como 0.
// v1.4.3: la consola reserva en el contenido un hueco igual a su alto (para no tapar el pie de las
// páginas largas) y se puede minimizar a un ícono; la preferencia se recuerda en localStorage.
import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../lib/api.js";

export const REFRESH_MS = 5000;
export const MINIMIZED_KEY = "resources-minimized";

const percent = (value) => (typeof value === "number" && Number.isFinite(value) ? `${value.toLocaleString("es-CL", { maximumFractionDigits: 1 })} %` : "—");

export function formatMemory(bytes) {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return "—";
  const mib = bytes / (1024 * 1024);
  return mib >= 1024 ? `${(mib / 1024).toLocaleString("es-CL", { maximumFractionDigits: 2 })} GB` : `${Math.round(mib)} MB`;
}

/** hh:mm:ss local de una fecha ISO; «—» si no se conoce. */
export function clockTime(iso) {
  const date = new Date(iso);
  if (!iso || Number.isNaN(date.getTime())) return "—";
  return [date.getHours(), date.getMinutes(), date.getSeconds()].map((part) => String(part).padStart(2, "0")).join(":");
}

/** Sondeo periódico que se detiene mientras la pestaña no está visible. */
export function useVisiblePolling(load, intervalMs = REFRESH_MS) {
  useEffect(() => {
    let timer = null;
    const start = () => {
      if (timer !== null || document.visibilityState !== "visible") return;
      load();
      timer = setInterval(load, intervalMs);
    };
    const stop = () => {
      if (timer !== null) clearInterval(timer);
      timer = null;
    };
    const onChange = () => (document.visibilityState === "visible" ? start() : stop());
    document.addEventListener("visibilitychange", onChange);
    start();
    return () => {
      document.removeEventListener("visibilitychange", onChange);
      stop();
    };
  }, [load, intervalMs]);
}

/** Preferencia «minimizada» recordada entre visitas; el almacenamiento puede no existir. */
export function readMinimized() {
  try {
    return window.localStorage.getItem(MINIMIZED_KEY) === "1";
  } catch {
    return false;
  }
}

function writeMinimized(value) {
  try {
    window.localStorage.setItem(MINIMIZED_KEY, value ? "1" : "0");
  } catch {
    /* sin almacenamiento: la preferencia dura lo que dure la pestaña */
  }
}

/**
 * Publica en `--rc-reserved` el alto del pie persistente (consola mini o ícono) para que el
 * contenido reserve ese hueco y no quede tapado al final de las páginas largas. Devuelve un ref
 * que se conecta al elemento a medir; al cambiar de elemento (minimizar / restaurar) se recalcula.
 */
export function useReservedSpace() {
  const observer = useRef(null);
  useEffect(() => () => {
    if (observer.current) observer.current.disconnect();
    try {
      document.documentElement.style.removeProperty("--rc-reserved");
    } catch {
      /* sin DOM: nada que limpiar */
    }
  }, []);
  return useCallback((node) => {
    if (observer.current) {
      observer.current.disconnect();
      observer.current = null;
    }
    const root = document.documentElement;
    if (!node) {
      root.style.removeProperty("--rc-reserved");
      return;
    }
    // La consola se fija a 0.5rem del borde inferior: el hueco es su alto más ese margen y un respiro.
    const update = () => root.style.setProperty("--rc-reserved", `${Math.ceil(node.getBoundingClientRect().height) + 16}px`);
    if (typeof ResizeObserver !== "undefined") {
      observer.current = new ResizeObserver(update);
      observer.current.observe(node);
    }
    update();
  }, []);
}

const yesNo = (value) => (value === null || value === undefined ? "—" : value ? "SÍ" : "NO");

export default function ResourceIndicator() {
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(false);
  const [minimized, setMinimized] = useState(readMinimized);
  const [load] = useState(() => () => api.resources().then(setData, () => setData(null)));
  useVisiblePolling(load);
  const measureRef = useReservedSpace();

  const collapse = () => {
    setOpen(false);
    setMinimized(true);
    writeMinimized(true);
  };
  const restore = () => {
    setMinimized(false);
    writeMinimized(false);
  };

  if (data === null) return null;
  const { totals, scans, interactive, services, alerts } = data;
  const status = data.status || {};
  const alert = alerts.length > 0;
  const alertText = `RAM sobre ${percent(data.memory_alert_percent)} del límite: ${alerts.map((item) => item.service).join(", ")}`;
  const stack = status.stack === "ok" ? "OK" : status.stack ? "DEGRADADO" : "—";
  const worker = status.worker === true ? "ACTIVO" : status.worker === false ? "SIN SEÑAL" : "—";
  return (
    <aside className="rc" data-testid="resources" data-alert={String(alert)} data-minimized={String(minimized)} aria-label="Consumo de recursos">
      {open && !minimized && (
        <div className="rc-full" data-testid="resources-detail">
          <div className="rc-meta"><span>MONITOR DE RECURSOS</span><span>SONDEO {data.refresh_s || 5} S</span></div>
          <div className="rc-console">
            <div className="rc-triangle" data-testid="resources-console">
              <div className="rc-core" aria-hidden="true" />
              <div className="rc-plate rc-plate-a" data-testid="plate-cpu"><span className="rc-value">{percent(totals.cpu_percent)}</span><span className="rc-name">CPU</span></div>
              <div className="rc-plate rc-plate-b" data-testid="plate-ram"><span className="rc-value">{formatMemory(totals.memory_bytes)}</span><span className="rc-name">RAM</span></div>
              <div className="rc-plate rc-plate-c" data-testid="plate-scans">
                <span className="rc-value">{scans.running ?? "—"}</span><span className="rc-name">SCANS</span>
                <span className="rc-sub">INTERACTIVA: {yesNo(interactive.active)}</span>
              </div>
            </div>
            <p className="rc-status" data-testid="resources-status">
              {`STACK: ${stack}\nWORKER: ${worker}\nACTUALIZADO: ${clockTime(data.generated_at)}`}
            </p>
          </div>
          {alert && (
            <div className="rc-alert" role="alert" data-testid="resources-alert-box">
              ALERTA
              <span>{alertText}</span>
            </div>
          )}
          <table className="rc-table">
            <thead>
              <tr><th>CONTENEDOR</th><th>CPU</th><th>RAM</th><th>% LÍMITE</th><th>PROC.</th></tr>
            </thead>
            <tbody>
              {services.map((item) => (
                <tr key={item.service} data-testid="resources-row" data-service={item.service} data-alert={String(item.alert)}>
                  <td>{item.service}</td>
                  {item.status === "ok" ? (
                    <>
                      <td>{percent(item.cpu_percent)}</td>
                      <td>{formatMemory(item.memory_bytes)}{item.memory_limit_bytes ? ` de ${formatMemory(item.memory_limit_bytes)}` : ""}</td>
                      <td>{percent(item.memory_percent)}{item.alert && " ⚠"}</td>
                      <td>{item.pids ?? "—"}</td>
                    </>
                  ) : <td colSpan={4}>no disponible</td>}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="rc-note">
            CPU: 100 % = un núcleo completo. RAM sin caché de archivos inactiva. Cada contenedor informa sus propios contadores (cgroup v2).
            {totals.services_reporting < totals.services_total && ` Informan ${totals.services_reporting} de ${totals.services_total} contenedores.`}
          </p>
        </div>
      )}
      {minimized ? (
        <button type="button" className="rc-restore" ref={measureRef} onClick={restore} data-testid="resources-restore"
          title="Monitor de recursos (minimizado). Clic para mostrarlo.">
          <span aria-hidden="true" className="rc-restore-icon">▣</span>
          {alert && <span className="rc-restore-dot" data-testid="resources-alert" aria-hidden="true" />}
          <span className="sr-only">Mostrar el monitor de recursos{alert ? `. ALERTA: ${alertText}` : ""}</span>
        </button>
      ) : (
        <div className="rc-foot" ref={measureRef}>
          <button type="button" className="rc-collapse" onClick={collapse} data-testid="resources-minimize" title="Minimizar el monitor de recursos a un ícono">
            <span aria-hidden="true">—</span><span className="sr-only">Minimizar el monitor de recursos</span>
          </button>
          <button type="button" className="rc-mini" onClick={() => setOpen(!open)} aria-expanded={open} data-testid="resources-toggle"
            title="Consumo del stack. Clic para ver la consola completa con el detalle por contenedor.">
            {alert && <span className="rc-flag" data-testid="resources-alert">ALERTA<span className="sr-only">: {alertText}</span></span>}
            <span className="rc-box" data-testid="resources-cpu"><b>CPU</b> <span>{percent(totals.cpu_percent)}</span></span>
            <span className="rc-box" data-testid="resources-memory"><b>RAM</b> <span>{formatMemory(totals.memory_bytes)}</span></span>
            <span className="rc-box" data-testid="resources-scans">
              <b>SCANS</b> <span>{scans.running ?? "—"}</span>
              <small data-testid="resources-interactive" data-active={String(interactive.active === true)}>INTERACTIVA: {yesNo(interactive.active)}</small>
            </span>
          </button>
        </div>
      )}
    </aside>
  );
}
