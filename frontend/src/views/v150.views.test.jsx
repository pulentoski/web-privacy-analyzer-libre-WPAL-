// @vitest-environment jsdom
// v1.5.0 (docs/adr/038): el Panel avisa cuando el ranking mezcla scans con distinto protocolo de visita, y la comparación
// scan ↔ HAR dice qué protocolo siguió el scan. La api se sustituye por respuestas fijas.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const NOTE = "Los scans comparados no siguieron el mismo protocolo de visita (versión sin protocolo, 1): parte de las diferencias puede deberse a cómo se visitó cada sitio, no al sitio.";
const state = { mixed: true };

function panelData() {
  return {
    basis: "Scan analizado más reciente de cada sitio.", level: "EVIDENCIA",
    totals: { sites: 2, scans: 2, requests: 20, organizations: 0, blocked_sites: 0, partial_sites: 0 },
    organizations: [], attributes: { read: [], sent: [] }, blocked_sites: [], partial_sites: [],
    ranking_protocols: state.mixed ? { versions: [null, 1], mixed: true, note: NOTE } : { versions: [1], mixed: false, note: null },
    ranking: [
      { site: "nuevo.example", job_id: "11111111-1111-1111-1111-111111111111", url: "https://nuevo.example/", site_exposure_score: 60, band: "Moderado", created_at: "2026-10-18T12:00:00Z", protocol_version: 1 },
      { site: "viejo.example", job_id: "22222222-2222-2222-2222-222222222222", url: "https://viejo.example/", site_exposure_score: 40, band: "Bajo-moderado", created_at: "2026-10-01T12:00:00Z", protocol_version: state.mixed ? null : 1 },
    ],
  };
}

vi.mock("../lib/api.js", () => ({
  api: {
    panel: () => Promise.resolve(panelData()),
    exposureServer: () => Promise.reject(new Error("sin red")),
    compareCandidates: () => Promise.resolve({ candidates: [{ job_id: "33333333-3333-3333-3333-333333333333", url: "https://nuevo.example/", finished_at: "2026-10-18T12:00:00Z", requests: 5, same_site: true }] }),
    compare: () => Promise.resolve({
      conclusion: { text: "Sin ola de sincronización.", level: "EVIDENCIA" }, note: "Nota.",
      organizations: { only_har: [], only_scan: [], both: [] }, har: { requests: 5 }, scan: { requests: 4, protocol_version: 1 },
      tracking: null, sync_wave: { state: "none", har: { detected: false }, scan: { detected: false } },
      blocked_by_extension: { requests: 0, organizations: [] },
      protocol: { scan: 1, har: null, mixed: true, note: "El scan siguió el protocolo de visita 1 (carga, espera, scroll, espera y cierre); el HAR importado es una navegación libre del usuario, sin protocolo de visita." },
    }),
  },
}));

const { default: PanelView } = await import("./Panel.jsx");
const { default: Compare } = await import("./Compare.jsx");

afterEach(cleanup);

describe("Panel: protocolos mezclados en el ranking", () => {
  it("avisa y marca el protocolo de cada sitio", async () => {
    state.mixed = true;
    render(<PanelView />);
    expect((await screen.findByTestId("panel-protocol-mixed")).textContent).toBe(NOTE);
    expect(screen.getAllByTestId("panel-ranking-item").map((item) => item.dataset.protocol)).toEqual(["1", "ninguno"]);
  });
  it("sin mezcla no avisa", async () => {
    state.mixed = false;
    render(<PanelView />);
    await screen.findAllByTestId("panel-ranking-item");
    expect(screen.queryByTestId("panel-protocol-mixed")).toBeNull();
  });
});

describe("comparación scan ↔ HAR", () => {
  it("dice qué protocolo siguió el scan", async () => {
    render(<Compare jobId="44444444-4444-4444-4444-444444444444" source="har_import" />);
    fireEvent.click(await screen.findByTestId("compare-run"));
    expect((await screen.findByTestId("compare-protocol")).textContent).toContain("protocolo de visita 1");
  });
});
