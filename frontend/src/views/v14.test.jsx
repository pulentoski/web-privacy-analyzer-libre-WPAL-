// @vitest-environment jsdom
// v1.4: captura interactiva (marca, línea de tiempo, aviso) e indicador de recursos.
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import ResourceIndicator, { formatMemory, REFRESH_MS } from "../components/ResourceIndicator.jsx";
import { api } from "../lib/api.js";
import { INTERACTIVE_END, InteractiveTimeline } from "./Dashboard.jsx";
import InteractiveCapture, { clock, INTERACTIVE_WARNING } from "./InteractiveCapture.jsx";

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

const HOSTILE = '<img src=x onerror="window.__XSS=1">';
const service = (name, extra = {}) => ({
  service: name, status: "ok", cpu_percent: 1.5, cpu_limit_percent: 100, memory_bytes: 100 * 1024 * 1024, memory_limit_bytes: 512 * 1024 * 1024,
  memory_percent: 19.5, pids: 4, pids_limit: 200, alert: false, ...extra,
});
const resources = (extra = {}) => ({
  totals: { cpu_percent: 7.5, memory_bytes: 1536 * 1024 * 1024, memory_limit_bytes: 6 * 1024 ** 3, memory_percent: 25, services_reporting: 5, services_total: 5 },
  scans: { running: 2, queued: 0, analyzing: 0 }, interactive: { active: false, job_id: null },
  services: ["frontend", "api", "worker", "db", "egress-proxy"].map((name) => service(name)), memory_alert_percent: 85, alerts: [], refresh_s: 5, ...extra,
});
const visibility = (state) => {
  Object.defineProperty(document, "visibilityState", { value: state, configurable: true });
  document.dispatchEvent(new Event("visibilitychange"));
};

describe("formato", () => {
  it("memoria en MB o GB; lo desconocido es «—», nunca 0", () => {
    expect(formatMemory(100 * 1024 * 1024)).toBe("100 MB");
    expect(formatMemory(1536 * 1024 * 1024)).toBe("1,5 GB");
    expect(formatMemory(null)).toBe("—");
    expect(formatMemory(-1)).toBe("—");
  });
  it("reloj mm:ss", () => {
    expect(clock(1793)).toBe("29:53");
    expect(clock(5)).toBe("0:05");
    expect(clock(null)).toBe("—");
  });
});

describe("indicador de recursos", () => {
  it("muestra totales, scans y captura interactiva; el detalle se abre con un clic", async () => {
    vi.spyOn(api, "resources").mockResolvedValue(resources({ interactive: { active: true, job_id: "x" } }));
    render(<ResourceIndicator />);
    expect((await screen.findByTestId("resources-cpu")).textContent).toBe("CPU 7,5 %");
    expect(screen.getByTestId("resources-memory").textContent).toBe("RAM 1,5 GB");
    expect(screen.getByTestId("resources-scans").textContent).toBe("SCANS 2INTERACTIVA: SÍ");
    expect(screen.getByTestId("resources-interactive").getAttribute("data-active")).toBe("true");
    expect(screen.queryByTestId("resources-detail")).toBeNull();
    await act(async () => screen.getByTestId("resources-toggle").click());
    expect(screen.getAllByTestId("resources-row").map((row) => row.getAttribute("data-service"))).toEqual(["frontend", "api", "worker", "db", "egress-proxy"]);
  });
  it("avisa cuando la RAM de un contenedor supera el 85 % de su límite", async () => {
    const data = resources({ alerts: [{ service: "worker", memory_percent: 91 }] });
    data.services[2] = service("worker", { memory_percent: 91, alert: true });
    vi.spyOn(api, "resources").mockResolvedValue(data);
    render(<ResourceIndicator />);
    expect((await screen.findByTestId("resources-alert")).textContent).toBe("ALERTA: RAM sobre 85 % del límite: worker");
    expect(screen.getByTestId("resources").getAttribute("data-alert")).toBe("true");
  });
  it("sin aviso no hay marca; un dato sin medir no se muestra como 0", async () => {
    const data = resources();
    data.totals.cpu_percent = null;
    data.services[0] = { ...service("frontend"), status: "no_disponible" };
    vi.spyOn(api, "resources").mockResolvedValue(data);
    render(<ResourceIndicator />);
    expect((await screen.findByTestId("resources-cpu")).textContent).toBe("CPU —");
    expect(screen.getByTestId("resources").getAttribute("data-alert")).toBe("false");
    expect(screen.queryByTestId("resources-alert")).toBeNull();
    await act(async () => screen.getByTestId("resources-toggle").click());
    expect(screen.getAllByTestId("resources-row")[0].textContent).toBe("frontendno disponible");
  });
  it("consulta cada 5 s y solo con la pestaña visible", async () => {
    vi.useFakeTimers();
    visibility("visible");
    const spy = vi.spyOn(api, "resources").mockResolvedValue(resources());
    render(<ResourceIndicator />);
    expect(REFRESH_MS).toBe(5000);
    expect(spy).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(spy).toHaveBeenCalledTimes(3);
    act(() => visibility("hidden"));
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(spy).toHaveBeenCalledTimes(3);
    act(() => visibility("visible"));
    expect(spy).toHaveBeenCalledTimes(4);
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(spy).toHaveBeenCalledTimes(5);
  });
  it("si la API no responde, no se muestra nada", async () => {
    vi.spyOn(api, "resources").mockRejectedValue({ status: 0 });
    const { container } = render(<ResourceIndicator />);
    await act(async () => {});
    expect(container.textContent).toBe("");
  });
});

describe("captura interactiva", () => {
  it("la línea de tiempo muestra URL y título del sitio solo como texto", () => {
    const info = { end_reason: "idle_timeout", timeline_truncated: true, timeline: [
      { seq: 0, ts: "2026-10-12T10:00:00+00:00", url: "https://sitio.example/", title: "Inicio", tab: 1 },
      { seq: 1, ts: "2026-10-12T10:01:00+00:00", url: `https://sitio.example/?q=${HOSTILE}`, title: HOSTILE, tab: 2 },
      { seq: 2, ts: "2026-10-12T10:02:00+00:00", url: "https://sitio.example/b", title: null, tab: 2 },
    ] };
    const { container } = render(<InteractiveTimeline info={info} />);
    expect(screen.getByTestId("interactive-banner").textContent).toContain("Captura interactiva");
    expect(screen.getByTestId("interactive-end").textContent).toBe(INTERACTIVE_END.idle_timeout);
    expect(screen.getByTestId("interactive-pages").textContent).toBe("3");
    const rows = screen.getAllByTestId("interactive-timeline-row");
    expect(rows).toHaveLength(3);
    expect(rows[1].textContent).toContain("<img src=x onerror=");
    expect(rows[2].textContent).toContain("no disponible");
    expect(container.querySelectorAll("img, script, a[href]").length).toBe(0);
    expect(window.__XSS).toBeUndefined();
  });
  it("advierte sobre contraseñas y cuentas reales antes de iniciar, y exige una URL válida", async () => {
    vi.spyOn(api, "interactiveStatus").mockResolvedValue({ enabled: true, session: null });
    const start = vi.spyOn(api, "interactiveStart");
    render(<InteractiveCapture url="ftp://no" />);
    expect((await screen.findByTestId("interactive-warning")).textContent).toContain(INTERACTIVE_WARNING);
    expect(INTERACTIVE_WARNING).toContain("contraseñas");
    expect(INTERACTIVE_WARNING).toContain("No inicie sesión con cuentas reales si va a compartir el reporte");
    await act(async () => screen.getByTestId("interactive-start").click());
    expect(screen.getByTestId("interactive-problem")).toBeTruthy();
    expect(start).not.toHaveBeenCalled();
  });
  it("en modo demo (deshabilitada) no aparece", async () => {
    vi.spyOn(api, "interactiveStatus").mockResolvedValue({ enabled: false, session: null });
    const { container } = render(<InteractiveCapture url="" />);
    await act(async () => {});
    expect(container.textContent).toBe("");
  });
  it("una sesión iniciada en otra pestaña se puede detener, pero no se ve su pantalla", async () => {
    vi.spyOn(api, "interactiveStatus").mockResolvedValue({ enabled: true, session: {
      job_id: "11111111-1111-4111-8111-111111111111", state: "ready", url: "https://sitio.example/", requests: 12, remaining_s: 1700, idle_remaining_s: 590 } });
    render(<InteractiveCapture url="" />);
    expect((await screen.findByTestId("interactive-elsewhere")).textContent).toContain("otra pestaña");
    expect(screen.getByTestId("interactive-remaining").textContent).toBe("28:20");
    expect(screen.getByTestId("interactive-stop").disabled).toBe(false);
    expect(screen.queryByTestId("vnc-screen")).toBeNull();
    expect(screen.queryByTestId("interactive-start")).toBeNull();
  });
});
