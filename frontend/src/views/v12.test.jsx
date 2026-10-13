// @vitest-environment jsdom
// v1.2: modo compacto, scan simple frente a opciones avanzadas y nombres de atributos compartidos.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { Info, LimitsNotice, Panel } from "../components/ui.jsx";
import { CATALOG } from "../exposure/catalog.js";
import { catalogEntry, groupByLabel, scanAttributeLabel } from "../exposure/scanAttributes.js";
import { isSimpleScan } from "./Analyze.jsx";
import { mergeByLabel } from "./Panel.jsx";

afterEach(cleanup);

describe("scan simple frente a opciones avanzadas", () => {
  it("la selección por defecto es un scan simple", () => {
    expect(isSimpleScan(["sin_interaccion"], ["real"], 1)).toBe(true);
  });
  it.each([
    [["sin_interaccion"], ["real"], 2],
    [["rechazar"], ["real"], 1],
    [["sin_interaccion", "rechazar"], ["real"], 1],
    [["sin_interaccion"], ["windows-chrome-es-cl"], 1],
    [["sin_interaccion"], ["real", "windows-chrome-es-cl"], 1],
    [[], ["real"], 1],
  ])("cualquier otra selección es un grupo: %j %j %i", (scenarios, profiles, runs) => {
    expect(isSimpleScan(scenarios, profiles, runs)).toBe(false);
  });
});

describe("nombres de atributos: los mismos de «Mi exposición»", () => {
  it("cada atributo de scan del catálogo tiene su etiqueta", () => {
    CATALOG.forEach((item) => item.scan.forEach((name) => expect(catalogEntry(name)).not.toBeNull()));
    expect(scanAttributeLabel("canvas")).toBe("Huella de canvas");
    expect(scanAttributeLabel("webgl_vendor")).toBe("Tarjeta gráfica (WebGL)");
    expect(scanAttributeLabel("webgl_renderer")).toBe("Tarjeta gráfica (WebGL)");
  });
  it("un atributo que el catálogo no tiene se muestra con su identificador, sin inventar un nombre", () => {
    expect(scanAttributeLabel("battery")).toBe("Batería"); // solo lo miden los scans
    expect(scanAttributeLabel("atributo_nuevo")).toBe("atributo_nuevo");
    expect(scanAttributeLabel("constructor")).toBe("constructor");
    expect(scanAttributeLabel("<img src=x>")).toBe("<img src=x>");
  });
  it("agrupa por etiqueta y no repite scripts ni destinos", () => {
    const reader = { script_url: "https://t.example/fp.js", organization: "Tracker", is_entity: true };
    const sent = { organization: "Tracker", domain: "t.example", request_ref: 7, level: "EVIDENCIA" };
    const rows = groupByLabel([
      { attribute: "webgl_vendor", read_by: [reader], sent_to: [sent] },
      { attribute: "webgl_renderer", read_by: [reader, { ...reader, script_url: "https://t.example/b.js" }], sent_to: [sent] },
      { attribute: "canvas", read_by: [reader], sent_to: [] },
    ]);
    expect(rows.map((row) => row.label)).toEqual(["Tarjeta gráfica (WebGL)", "Huella de canvas"]);
    expect(rows[0].read_by).toHaveLength(2);
    expect(rows[0].sent_to).toHaveLength(1);
    expect(groupByLabel(null)).toEqual([]);
  });
});

describe("modo compacto", () => {
  it("el panel lleva título, subtítulo de una línea y la explicación en un ⓘ", () => {
    render(<Panel title="Rastreadores" subtitle="Requests en banda Moderado o superior." info={<span>La organización viene de un mapa.</span>} testId="p">contenido</Panel>);
    expect(screen.getByRole("heading", { level: 2 }).textContent).toContain("Rastreadores");
    expect(screen.getByTestId("panel-subtitle").textContent).toBe("Requests en banda Moderado o superior.");
    const info = screen.getByTestId("info");
    expect(info.getAttribute("aria-label")).toBe("Información: Rastreadores");
    expect(info.querySelector("[role=tooltip]").textContent).toBe("La organización viene de un mapa.");
  });
  it("un ⓘ pinta su contenido como texto", () => {
    render(<Info label="x">{"<img src=x onerror=alert(1)>"}</Info>);
    expect(screen.getByRole("tooltip").textContent).toBe("<img src=x onerror=alert(1)>");
    expect(document.querySelector("img")).toBeNull();
  });
  it("los límites de la medición quedan plegados", () => {
    render(<LimitsNotice limitations={["una"]} />);
    const notice = screen.getByTestId("limits-notice");
    expect(notice.tagName).toBe("DETAILS");
    expect(notice.open).toBe(false);
    expect(notice.querySelector("summary").textContent).toBe("Límites de la medición");
  });
});

describe("Panel: atributos más leídos y más enviados", () => {
  it("no repite una etiqueta cuando dos atributos de scan comparten nombre", () => {
    const rows = mergeByLabel([
      { attribute: "user_agent", sites: 3, of: 5, organizations: ["A"] },
      { attribute: "webgl_vendor", sites: 1, of: 5, organizations: ["M"] },
      { attribute: "webgl_renderer", sites: 2, of: 5, organizations: ["M", "N"] },
    ]);
    expect(rows.map((row) => [row.label, row.sites, row.organizations])).toEqual([
      ["User agent", 3, ["A"]], ["Tarjeta gráfica (WebGL)", 2, ["M", "N"]],
    ]);
    expect(mergeByLabel(null)).toEqual([]);
  });
});
