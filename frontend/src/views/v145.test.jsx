// @vitest-environment jsdom
// v1.4.5: «Servicios de terceros sin señales de rastreo» (Rastreadores y Resumen). Lo capturado se pinta como texto.
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ThirdPartyServices } from "./Trackers.jsx";

afterEach(() => { cleanup(); delete window.__XSS; });

const HOSTILE = '<img src=x onerror="window.__XSS=1">';
const item = (organization, service_type, service_label, hosts, requests, extra = {}) => ({
  organization, service_type, service_label, domains: hosts, hosts, requests, evidence_refs: [11, 12].slice(0, requests), in_trackers: false, ...extra,
});
const services = (items, extra = {}) => ({
  level: "EVIDENCIA", service_level: "INFERENCIA", organizations: new Set(items.map((entry) => entry.organization)).size,
  requests: items.reduce((total, entry) => total + entry.requests, 0), items, truncated: false, ...extra,
});
const LASERENA = [
  item("Google", "antifraud", "antifraude publicitario/antibot (verifica que el tráfico no sea automatizado)", ["www.google.com", "www.gstatic.com"], 2),
  item("OpenStreetMap Foundation", "maps", "mapas (mapas interactivos, teselas y geocodificación)", ["a.tile.openstreetmap.org"], 2, { in_trackers: true }),
  item("no_disponible", null, null, ["apis.munilaserena.cl"], 1),
];

describe("servicios de terceros sin señales de rastreo", () => {
  it("muestra organización, tipo de servicio, dominios, requests y evidencia", () => {
    render(<ThirdPartyServices jobId="job-1" services={services(LASERENA)} />);
    expect(screen.getByRole("heading", { name: /Servicios de terceros sin señales de rastreo/ })).toBeTruthy();
    expect(screen.getByTestId("third-party-services-counts").textContent).toMatch(/5 requests a 3 organizaciones sin señales de rastreo/);
    const rows = screen.getAllByTestId("third-party-service");
    expect(rows.map((row) => row.dataset.service)).toEqual(["antifraud", "maps", "desconocido"]);
    expect(rows[0].textContent).toContain("Google");
    expect(rows[0].textContent).toContain("www.google.com, www.gstatic.com");
    expect(within(rows[0]).getByTestId("service-type").textContent).toMatch(/^antifraude/);
    expect(rows[1].textContent).toContain("(también en rastreadores)");
    // Sin dueño ni giro conocidos: se dice, no se inventa.
    expect(within(rows[2]).getByTestId("third-party-service-org").textContent).toBe("Organización no disponible");
    expect(within(rows[2]).getByTestId("service-type").textContent).toBe("tipo no identificado");
    expect(within(rows[0]).getAllByTestId("third-party-service-ref").map((link) => link.textContent)).toEqual(["#11", "#12"]);
  });

  it("se muestra también cuando no hay ninguno, y no aparece si el análisis no lo midió", () => {
    const { unmount } = render(<ThirdPartyServices jobId="job-1" services={services([])} />);
    expect(screen.getByTestId("third-party-services").textContent).toContain("En esta visita no hubo requests a terceros sin señales de rastreo.");
    expect(screen.getByTestId("third-party-services-counts").textContent).toMatch(/0 requests a 0 organizaciones/);
    unmount();
    const older = render(<ThirdPartyServices jobId="job-1" services={undefined} />);
    expect(older.container.innerHTML).toBe("");
    older.unmount();
    expect(render(<ThirdPartyServices jobId="job-1" services={{ items: "x" }} />).container.innerHTML).toBe("");
  });

  it("singular con una request a una organización", () => {
    render(<ThirdPartyServices jobId="job-1" services={services([LASERENA[2]])} />);
    expect(screen.getByTestId("third-party-services-counts").textContent).toMatch(/1 request a 1 organización sin señales de rastreo/);
  });

  it("en el Resumen es compacto: hasta 8 filas, sin columna de evidencia y con aviso del resto", () => {
    const many = Array.from({ length: 11 }, (_, index) => item(`Org ${index}`, "cdn", "red de distribución de contenido", [`h${index}.example`], 1));
    render(<ThirdPartyServices services={services(many)} compact />);
    expect(screen.getAllByTestId("third-party-service")).toHaveLength(8);
    expect(screen.queryByTestId("third-party-service-ref")).toBeNull();
    expect(screen.getByTestId("third-party-services").textContent).toContain("Se muestran 8 de 11; la lista completa está en Rastreadores.");
  });

  it("pinta como texto lo que viene de la captura", () => {
    render(<ThirdPartyServices jobId="job-1" services={services([item(HOSTILE, HOSTILE, HOSTILE, [HOSTILE], 1)])} />);
    const panel = screen.getByTestId("third-party-services");
    expect(panel.querySelector("img")).toBeNull();
    expect(panel.textContent).toContain(HOSTILE);
    expect(window.__XSS).toBeUndefined();
  });
});
