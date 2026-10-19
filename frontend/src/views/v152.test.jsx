// @vitest-environment jsdom
// v1.5.2: comparación de visitas. La api se sustituye por respuestas fijas: la vista muestra los textos que entrega la
// api tal cual, la advertencia siempre, «no observado en esta captura» para lo ausente y el valor enmascarado por defecto.
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const ID = "a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e";
const MASKED = "a3f9…[32 caracteres]";
const PERSISTENT = "se observó un identificador persistente entre dos visitas con el mismo perfil; el perfil limpio de control mostró un resultado distinto";
const ONLY_V2 = "cambio observado en el perfil persistente que no apareció en los perfiles limpios";
const ALSO = "también observado en el control";
const ABSENT = "no observado en esta captura";
const WARNING = "Tres visitas no prueban causalidad. Una diferencia puede deberse a publicidad dinámica, pruebas A/B, estado del servidor o a la propia captura. Este resultado no indica que el sitio haya reconocido al visitante.";
const calls = [];
const created = [];

function visit(number, overrides = {}) {
  return {
    visit: number, profile: number === 3 ? "B" : "A", label: ["Perfil A limpio", "Perfil A persistente (mismo perfil, tras el intervalo)", "Perfil B limpio de control"][number - 1],
    job_id: `0000000${number}-0000-0000-0000-000000000000`, status: "completed", analysis_status: "completed", error_code: null,
    progress: { stage: "done" }, waiting_until: null, requests: 12, cookies: 3, storage_items: 1, site_exposure_score: 20, band: "Bajo",
    partial_navigation: false, ...overrides,
  };
}

function comparison(reveal, overrides = {}) {
  const value = reveal ? ID : MASKED;
  const empty = (text) => ({ text, total: 0, items: [] });
  return {
    comparison_id: "11111111-1111-1111-1111-111111111111", url: "http://site.example/", status: "valida",
    validity: { status: "valida", valid: true, reasons: [] }, interval: { configured_s: 300, real_s: 302.5 },
    visits: [visit(1), visit(2), visit(3)], condition_differences: [],
    profiles: {
      1: { profile: "A", launched_at: null, closed_at: null, start: { files_before_launch: 0, cookies_at_start: 0 }, end: { persistent_cookies: 1, inventory: { indexeddb_origins: ["x"] } } },
      2: { profile: "A", launched_at: null, closed_at: null, start: { manifest_matches: true, cookies_at_start: 1, persistent_cookies_missing: 0 }, end: { persistent_cookies: 1, inventory: { indexeddb_origins: ["x"] } } },
      3: { profile: "B", launched_at: null, closed_at: null, start: { files_before_launch: 0, cookies_at_start: 0 }, end: { persistent_cookies: 1, inventory: { indexeddb_origins: ["x"] } } },
    },
    warning: WARNING, limits: ["Las tres visitas salen por la misma IP."],
    texts: { absent: ABSENT, different: "valor distinto", observed: "observado" }, revealed: reveal,
    result: {
      classes: {
        persistent: { text: PERSISTENT, total: 1, items: [{ kind: "cookies", kind_label: "Cookies", context: { domain: "site.example", path: "/", name: "uid" }, value, visits: { 1: "observado", 2: "observado", 3: ABSENT } }] },
        only_visit_2: { text: ONLY_V2, total: 1, items: [{ kind: "requests", kind_label: "Requests", context: { method: "GET", host: "site.example", path: "/hola.gif" }, value: null, visits: { 1: ABSENT, 2: "observado", 3: ABSENT } }] },
        also_control: empty(ALSO), profile_a: empty("x"), clean_only: empty("y"),
      },
      discarded: { static: { reason: "igual en las tres visitas (estático)", total: 7 } },
    },
    ...overrides,
  };
}

let response = comparison;

vi.mock("../lib/api.js", () => ({
  api: {
    comparison: (comparisonId, reveal) => {
      calls.push(reveal);
      return Promise.resolve(response(reveal));
    },
    comparisonCreate: (body) => {
      created.push(body);
      return Promise.resolve({ comparison_id: "22222222-2222-2222-2222-222222222222" });
    },
  },
}));

const { default: VisitComparison, VisitComparisonStart, intervalProblem, seconds } = await import("./VisitComparison.jsx");

afterEach(() => {
  cleanup();
  calls.length = 0;
  created.length = 0;
  response = comparison;
});

describe("vista de la comparación", () => {
  it("muestra la advertencia fija, la validez, el intervalo y los textos de cada clase", async () => {
    render(<VisitComparison comparisonId="11111111-1111-1111-1111-111111111111" />);
    expect((await screen.findByTestId("comparison-warning")).textContent).toContain(WARNING);
    expect(screen.getByTestId("comparison-validity").textContent).toContain("Válida");
    expect(screen.getByTestId("comparison-interval-info").textContent).toContain("configurado 5 min · real 5 min 3 s");
    expect(screen.getByTestId("class-text-persistent").textContent).toBe(PERSISTENT);
    expect(screen.getByTestId("class-text-only_visit_2").textContent).toBe(ONLY_V2);
    expect(screen.getByTestId("class-text-also_control").textContent).toBe(ALSO);
    const persistent = screen.getByTestId("item-persistent");
    expect(within(persistent).getByTestId("item-visit-3").textContent).toBe(ABSENT);
    expect(screen.getAllByTestId("comparison-visit").map((row) => row.textContent)).toEqual(
      expect.arrayContaining([expect.stringContaining("Perfil B limpio de control")]));
    expect(document.body.textContent).not.toContain("no existe");
  });

  it("enmascara por defecto y pide los valores completos solo con el interruptor", async () => {
    render(<VisitComparison comparisonId="11111111-1111-1111-1111-111111111111" />);
    const result = await screen.findByTestId("comparison-result");
    await within(result).findByText((text) => text.includes(MASKED));
    expect(result.textContent).not.toContain(ID);
    fireEvent.click(screen.getByTestId("comparison-reveal"));
    await within(result).findByText((text) => text.includes(ID));
    expect(calls).toEqual([false, true]);
  });

  it("una comparación no válida lista sus motivos y no muestra resultado", async () => {
    response = (reveal) => comparison(reveal, {
      status: "no_valida", validity: { status: "no_valida", valid: false, reasons: ["Se perdió el estado del perfil A: su directorio no estaba al empezar la visita 2."] },
      visits: [visit(1), visit(2, { status: "failed", error_code: "COMPARISON_STATE_LOST", progress: { stage: "failed" } }), visit(3, { status: "failed", error_code: "COMPARISON_ABORTED", progress: { stage: "failed" } })],
      result: null,
    });
    render(<VisitComparison comparisonId="11111111-1111-1111-1111-111111111111" />);
    expect((await screen.findByTestId("comparison-validity")).getAttribute("data-valid")).toBe("false");
    expect(screen.getByTestId("comparison-reasons").textContent).toContain("Se perdió el estado del perfil A");
    expect(screen.getAllByTestId("visit-error").map((item) => item.textContent)).toEqual(["COMPARISON_STATE_LOST", "COMPARISON_ABORTED"]);
    expect(screen.queryByTestId("class-persistent")).toBeNull();
    expect(screen.getByTestId("comparison-warning").textContent).toContain(WARNING);
  });

  it("lista las condiciones que no fueron iguales", async () => {
    response = (reveal) => comparison(reveal, { condition_differences: [{ condition: "egress_country", label: "País de la IP de salida", values: { 1: "CL", 2: "CL", 3: null } }] });
    render(<VisitComparison comparisonId="11111111-1111-1111-1111-111111111111" />);
    expect((await screen.findByTestId("condition-difference")).textContent).toBe("País de la IP de salida: visita 1 = CL · visita 2 = CL · visita 3 = no disponible");
  });
});

describe("inicio desde «Analizar un sitio»", () => {
  it("envía la URL y el intervalo; 300 s por defecto", async () => {
    render(<VisitComparisonStart url="https://example.com" />);
    expect(screen.getByTestId("comparison-interval").value).toBe("300");
    fireEvent.click(screen.getByTestId("comparison-submit"));
    await vi.waitFor(() => expect(created).toEqual([{ url: "https://example.com", interval_s: 300, clean_url: true }]));
  });

  it("valida el intervalo antes de enviar", () => {
    render(<VisitComparisonStart url="https://example.com" />);
    fireEvent.change(screen.getByTestId("comparison-interval"), { target: { value: "90000" } });
    fireEvent.click(screen.getByTestId("comparison-submit"));
    expect(screen.getByTestId("comparison-field-error").textContent).toContain("86400");
    expect(created).toEqual([]);
    expect(intervalProblem("5.5")).toContain("entero");
    expect(intervalProblem("0")).toBeNull();
    expect(seconds(45)).toBe("45 s");
    expect(seconds(5400)).toBe("1 h 30 min");
    expect(seconds(null)).toBe("no disponible");
  });
});
