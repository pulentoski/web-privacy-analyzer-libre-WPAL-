// @vitest-environment jsdom
// v1.4.2: hallazgos y rastreadores agrupados, registro de interacción, textos de la captura interactiva,
// consola de recursos y modos de «Analizar un sitio».
import { act, cleanup, render, screen } from "@testing-library/react";
import fs from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ICON_NAMES } from "../components/Icons.jsx";
import ResourceIndicator, { clockTime, MINIMIZED_KEY, readMinimized } from "../components/ResourceIndicator.jsx";
import { Panel } from "../components/ui.jsx";
import { api } from "../lib/api.js";
import { headline } from "./Dashboard.jsx";
import { groupFindings, InteractionPanel } from "./Findings.jsx";
import { groupTrackerRequests, trackerRowCount } from "./Trackers.jsx";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const HOSTILE = '<img src=x onerror="window.__XSS=1">';
const finding = (id, type, level, organizations, requests) => ({ id, kind: "general", type, level, organizations, plain: `frase ${type}`, claim: "detalle", evidence_refs: { requests, calls: [] } });

describe("hallazgos repetidos en una fila", () => {
  it("agrupa por tipo, nivel y organizaciones, y cuenta valores y requests distintos", () => {
    const groups = groupFindings([
      finding(1, "id_sync", "EVIDENCIA", ["Facebook", "on.aws"], [1, 2]), finding(2, "id_sync", "EVIDENCIA", ["Facebook", "on.aws"], [2, 3]),
      finding(3, "id_sync", "EVIDENCIA", ["Google"], [4]), finding(4, "identifier_param", "INFERENCIA", ["Google"], [4]),
      finding(5, "identifier_param", "POSIBLE", ["Google"], [4]), { ...finding(6, "list_match", "EVIDENCIA", undefined, [9]), organizations: undefined },
    ]);
    expect(groups.map((group) => [group.type, group.level, group.organizations.join("+"), group.values, group.requests])).toEqual([
      ["id_sync", "EVIDENCIA", "Facebook+on.aws", 2, 3], ["id_sync", "EVIDENCIA", "Google", 1, 1], ["identifier_param", "INFERENCIA", "Google", 1, 1],
      ["identifier_param", "POSIBLE", "Google", 1, 1], ["list_match", "EVIDENCIA", "", 1, 1],
    ]);
    expect(groups.reduce((total, group) => total + group.items.length, 0)).toBe(6);
  });
});

describe("rastreadores: requests repetidas en una fila", () => {
  const request = (id, signal, url) => ({ request_id: id, url, plain: { signal, text: `frase ${signal}`, level: "EVIDENCIA" } });
  it("agrupa por tipo de señal y cuenta direcciones distintas sin la query", () => {
    const requests = [request(1, "id_sync", "https://a.example/p?x=1"), request(2, "id_sync", "https://a.example/p?x=2"), request(3, "id_sync", "https://a.example/q"),
      request(4, "url_leak", "https://a.example/l"), { request_id: 5, url: "https://a.example/z", plain: null }];
    expect(groupTrackerRequests(requests).map((bundle) => [bundle.signal, bundle.requests.length, bundle.values])).toEqual([["id_sync", 3, 2], ["url_leak", 1, 1], ["sin_senal", 1, 1]]);
    expect(trackerRowCount([{ requests }, { requests: [request(9, "id_sync", "https://b.example/")] }])).toBe(4);
  });
});

describe("textos coherentes con el origen de la captura", () => {
  it("«Durante la sesión» en capturas interactivas y HAR; el scan conserva su frase", () => {
    const capture = { total_requests: 12 };
    const summary = { third_party_domains: 3 };
    expect(headline(capture, summary)).toBe("La página realizó 12 requests y contactó 3 dominios de terceros.");
    expect(headline(capture, summary, "interactive")).toBe("Durante la sesión se realizaron 12 requests y se contactó 3 dominios de terceros.");
    expect(headline({ total_requests: 1 }, { third_party_domains: 1 }, "har_import")).toBe("Durante la sesión se realizaron 1 request y se contactó 1 dominio de tercero.");
  });
});

describe("registro de interacción", () => {
  const interaction = {
    available: true, window_s: 2, total: 3, interactions: { click: 2, key: 1 }, timeline_truncated: false,
    organizations: [{ organization: HOSTILE, interactions: 2, requests: 3, expected: 0, flagged: true }, { organization: "Baliza", interactions: 2, requests: 4, expected: 4, flagged: false }],
    timeline: [{ ts: 1791817200, kind: "click", navigation: false, sends: [{ organization: HOSTILE, requests: 2 }] },
      { ts: 1791817210, kind: "click", navigation: true, sends: [] }, { ts: 1791817220, kind: "key", navigation: false, sends: [] }],
    payloads: [{ domain: "tracker.example", label: "coordenadas del puntero", parameters: ["clientx", HOSTILE], requests: 2 }],
  };
  it("muestra conteos, organizaciones que recibieron envíos y la línea de tiempo, todo como texto", async () => {
    const { container } = render(<InteractionPanel interaction={interaction} />);
    expect(screen.getByTestId("interaction-counts").textContent).toContain("2 clics, 0 desplazamientos, 1 teclas");
    const rows = screen.getAllByTestId("interaction-organization");
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain("<img src=x onerror=");
    await act(async () => screen.getByTestId("interaction-timeline-toggle").click());
    const timeline = screen.getAllByTestId("interaction-row");
    expect(timeline.map((row) => row.getAttribute("data-kind"))).toEqual(["click", "click", "key"]);
    expect(timeline[1].textContent).toContain("abrió otra página");
    expect(timeline[2].textContent).toContain("sin envíos");
    expect(screen.getAllByTestId("interaction-payload")[0].textContent).toContain("coordenadas del puntero");
    expect(container.querySelectorAll("img, script").length).toBe(0);
    expect(window.__XSS).toBeUndefined();
  });
  it("sin registro de interacción lo dice; sin la medición no se muestra nada", () => {
    render(<InteractionPanel interaction={{ available: false, payloads: [], organizations: [] }} />);
    expect(screen.getByTestId("interaction-unavailable").textContent).toContain("no registró la interacción del usuario");
    cleanup();
    const { container } = render(<InteractionPanel interaction={undefined} />);
    expect(container.textContent).toBe("");
  });
});

describe("consola de recursos", () => {
  const data = (extra = {}) => ({
    generated_at: "2026-10-12T15:04:05+00:00", refresh_s: 5, memory_alert_percent: 85, alerts: [],
    totals: { cpu_percent: 7.5, memory_bytes: 512 * 1024 * 1024, memory_limit_bytes: 6 * 1024 ** 3, memory_percent: 8, services_reporting: 5, services_total: 5 },
    status: { database: true, worker: true, stack: "ok" }, scans: { running: 1, queued: 0, analyzing: 0 }, interactive: { active: false, job_id: null },
    services: ["frontend", "api", "worker", "db", "egress-proxy"].map((service) => ({ service, status: "ok", cpu_percent: 1, cpu_limit_percent: 100,
      memory_bytes: 1024 * 1024 * 100, memory_limit_bytes: 1024 * 1024 * 512, memory_percent: 19.5, pids: 3, pids_limit: 100, alert: false })), ...extra,
  });
  it("versión mini con tres cuadros; al abrir, tres placas, bloque de estado y detalle", async () => {
    vi.spyOn(api, "resources").mockResolvedValue(data());
    render(<ResourceIndicator />);
    const mini = await screen.findByTestId("resources-toggle");
    expect([...mini.querySelectorAll(".rc-box b")].map((node) => node.textContent)).toEqual(["CPU", "RAM", "SCANS"]);
    expect(screen.queryByTestId("resources-console")).toBeNull();
    await act(async () => mini.click());
    expect([...screen.getByTestId("resources-console").querySelectorAll(".rc-name")].map((node) => node.textContent)).toEqual(["CPU", "RAM", "SCANS"]);
    expect(screen.getByTestId("plate-cpu").textContent).toBe("7,5 %CPU");
    expect(screen.getByTestId("plate-ram").textContent).toBe("512 MBRAM");
    expect(screen.getByTestId("plate-scans").textContent).toBe("1SCANSINTERACTIVA: NO");
    const expected = clockTime("2026-10-12T15:04:05+00:00");
    expect(expected).toMatch(/^\d\d:\d\d:05$/);
    expect(screen.getByTestId("resources-status").textContent).toBe(`STACK: OK\nWORKER: ACTIVO\nACTUALIZADO: ${expected}`);
    expect(screen.getAllByTestId("resources-row")).toHaveLength(5);
    expect(screen.queryByTestId("resources-alert-box")).toBeNull();
    expect(screen.queryByTestId("resources-alert")).toBeNull();
  });
  it("ALERTA solo con RAM sobre el 85 %; worker sin señal y stack degradado se dicen tal cual", async () => {
    const alerted = data({ alerts: [{ service: "worker", memory_percent: 91 }], status: { database: true, worker: false, stack: "degradado" } });
    vi.spyOn(api, "resources").mockResolvedValue(alerted);
    render(<ResourceIndicator />);
    const toggle = await screen.findByTestId("resources-toggle");
    await act(async () => toggle.click());
    expect(screen.getByTestId("resources-alert-box").textContent).toBe("ALERTARAM sobre 85 % del límite: worker");
    expect(screen.getByTestId("resources-alert-box").getAttribute("role")).toBe("alert");
    expect(screen.getByTestId("resources-status").textContent).toContain("STACK: DEGRADADO\nWORKER: SIN SEÑAL");
  });
  it("sin bloque de estado (api anterior) muestra «—», no inventa OK", async () => {
    vi.spyOn(api, "resources").mockResolvedValue(data({ status: undefined, generated_at: null }));
    render(<ResourceIndicator />);
    const toggle = await screen.findByTestId("resources-toggle");
    await act(async () => toggle.click());
    expect(screen.getByTestId("resources-status").textContent).toBe("STACK: —\nWORKER: —\nACTUALIZADO: —");
  });
  it("se minimiza a un ícono y restaura; la preferencia se recuerda en localStorage", async () => {
    window.localStorage.removeItem(MINIMIZED_KEY);
    vi.spyOn(api, "resources").mockResolvedValue(data());
    render(<ResourceIndicator />);
    await screen.findByTestId("resources-toggle");
    expect(screen.queryByTestId("resources-restore")).toBeNull();
    await act(async () => screen.getByTestId("resources-minimize").click());
    // Minimizada: solo el ícono, sin la consola mini; la preferencia queda guardada.
    expect(screen.queryByTestId("resources-toggle")).toBeNull();
    expect(screen.getByTestId("resources-restore")).toBeTruthy();
    expect(window.localStorage.getItem(MINIMIZED_KEY)).toBe("1");
    await act(async () => screen.getByTestId("resources-restore").click());
    expect(screen.getByTestId("resources-toggle")).toBeTruthy();
    expect(window.localStorage.getItem(MINIMIZED_KEY)).toBe("0");
    cleanup();
    // Arranca minimizada si así quedó la preferencia.
    window.localStorage.setItem(MINIMIZED_KEY, "1");
    render(<ResourceIndicator />);
    expect(await screen.findByTestId("resources-restore")).toBeTruthy();
    expect(screen.queryByTestId("resources-toggle")).toBeNull();
    window.localStorage.removeItem(MINIMIZED_KEY);
  });
  it("lee la preferencia aunque localStorage falle, sin romperse", () => {
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("bloqueado"); });
    expect(readMinimized()).toBe(false);
    getItem.mockRestore();
  });
});

describe("modos de «Analizar un sitio»", () => {
  it("un panel con modo lleva su color por atributo y además título e ícono", () => {
    render(<Panel title="Importar archivo HAR" mode="har" icon="file" testId="p">contenido</Panel>);
    const panel = screen.getByTestId("p");
    expect(panel.getAttribute("data-mode")).toBe("har");
    expect(panel.classList.contains("mode")).toBe(true);
    expect(panel.querySelector("h2.mode-title").textContent.trim()).toBe("Importar archivo HAR");
    expect(panel.querySelector("h2 svg").getAttribute("data-icon")).toBe("file");
    for (const icon of ["pointer", "search", "sliders", "file", "pulse", "user", "repeat", "check"]) expect(ICON_NAMES).toContain(icon);
  });
  it("los colores de acento son tokens CSS definidos en un solo lugar, para ambos temas", () => {
    const css = fs.readFileSync("src/index.css", "utf8");
    const modes = ["scan", "advanced", "consent", "profile", "runs", "interactive", "har", "status"];
    for (const mode of modes) {
      expect(css.match(new RegExp(`--acc-${mode}:`, "g"))).toHaveLength(2);   // :root (Clásico) y Unidad Púrpura
      expect(css).toContain(`.mode[data-mode="${mode}"] { --mode: var(--acc-${mode});`);
    }
    expect(css.match(/--acc-incoherent:/g)).toHaveLength(2);
    // Fuera del bloque de tokens, las reglas de los modos no llevan colores literales.
    const rules = css.split("\n").filter((line) => line.startsWith(".mode") || line.startsWith("html .mode"));
    expect(rules.length).toBeGreaterThan(10);
    for (const line of rules) expect(line).not.toMatch(/#[0-9a-fA-F]{3,6}/);
    expect(css).toContain("@media (prefers-reduced-motion: reduce) { .rc-alert { animation: none; } }");
  });
});
