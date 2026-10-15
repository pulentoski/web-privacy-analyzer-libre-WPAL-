// @vitest-environment jsdom
// v1.4.6: cookies por propósito (Resumen) y librería conocida en un CDN público (Servicios de terceros). Lo capturado se pinta como texto.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { CookiePurposes } from "./Dashboard.jsx";
import { ThirdPartyServices } from "./Trackers.jsx";

afterEach(() => { cleanup(); delete window.__XSS; });

const HOSTILE = '<img src=x onerror="window.__XSS=1">';
const LABELS = { funcional: "funcional", analitica: "analítica", publicidad: "publicidad", sin_clasificar: "sin clasificar" };

describe("cookies por propósito", () => {
  it("muestra el conteo por propósito como inferencia y avisa que las funcionales no suman", () => {
    render(<CookiePurposes purposes={{ level: "INFERENCIA", basis: "nombre", labels: LABELS,
      by_purpose: { publicidad: 2, analitica: 3, funcional: 1, sin_clasificar: 4 } }} />);
    expect(screen.getByRole("heading", { name: /Cookies por propósito/ })).toBeTruthy();
    const items = screen.getAllByTestId("cookie-purpose");
    expect(items.map((item) => item.dataset.purpose)).toEqual(["funcional", "analitica", "publicidad", "sin_clasificar"]);
    expect(items.map((item) => item.textContent)).toEqual(["1 funcional", "3 analítica", "2 publicidad", "4 sin clasificar"]);
    expect(screen.getByTestId("cookie-purposes").querySelector("[data-level]").dataset.level).toBe("INFERENCIA");
    expect(screen.getByText(/10 cookies al terminar la visita/)).toBeTruthy();
    expect(screen.getByText(/Las funcionales no suman al índice de exposición/)).toBeTruthy();
  });

  it("v1.4.7: dice cuántas se clasificaron por el nombre y cuántas por la organización", () => {
    render(<CookiePurposes purposes={{ level: "INFERENCIA", labels: LABELS, by_purpose: { publicidad: 4, analitica: 1, funcional: 0, sin_clasificar: 2 },
      by_basis: { nombre: 2, organizacion: 3 } }} />);
    expect(screen.getByTestId("cookie-purpose-basis").textContent).toBe("Por el nombre: 2 · por la organización que la creó: 3.");
  });

  it("un análisis anterior a v1.4.6 no muestra el panel (no se inventa «0»)", () => {
    const { container } = render(<CookiePurposes purposes={undefined} />);
    expect(container.textContent).toBe("");
  });
});

describe("librería en CDN público", () => {
  const services = (items) => ({ level: "EVIDENCIA", service_level: "INFERENCIA", organizations: 1, requests: 2, items, truncated: false });
  const row = (organization, library) => ({ organization, service_type: "library_cdn", service_label: "CDN de librerías", domains: ["jsdelivr.net"],
    hosts: ["cdn.jsdelivr.net"], requests: 1, evidence_refs: [3], in_trackers: false, library });

  it("nombra la librería, no la empresa del CDN, y marca las librerías conocidas", () => {
    render(<ThirdPartyServices jobId="job-1" services={services([
      row("librería chart.js en CDN público (jsDelivr)", { library: "chart.js", cdn: "jsDelivr", benign: true, benign_label: "librería de gráficos" }),
      row("librería bootstrap en CDN público (jsDelivr)", { library: "bootstrap", cdn: "jsDelivr", benign: false, benign_label: null }),
    ])} />);
    const orgs = screen.getAllByTestId("third-party-service-org").map((cell) => cell.textContent);
    expect(orgs[0]).toBe("librería chart.js en CDN público (jsDelivr) (librería conocida: librería de gráficos)");
    expect(orgs[1]).toBe("librería bootstrap en CDN público (jsDelivr)");
    expect(screen.getAllByTestId("third-party-service-benign")).toHaveLength(1);
    expect(orgs.join(" ")).not.toContain("Prospect One");
  });

  it("pinta como texto un nombre hostil", () => {
    render(<ThirdPartyServices services={services([row(HOSTILE, { library: HOSTILE, cdn: "jsDelivr", benign: true, benign_label: HOSTILE })])} />);
    expect(screen.getByTestId("third-party-service-org").textContent).toContain(HOSTILE);
    expect(document.querySelector("img")).toBeNull();
    expect(window.__XSS).toBeUndefined();
  });
});
