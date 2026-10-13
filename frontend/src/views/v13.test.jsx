// @vitest-environment jsdom
// v1.3: importar HAR, comparación scan vs HAR, etiquetas de terceros por organización y título del Panel.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { partyLabel, requestOutcome } from "../lib/format.js";
import { waveText } from "./Compare.jsx";
import HarImport, { HAR_MAX_BYTES, harFileProblem, loadTime } from "./HarImport.jsx";
import PanelView from "./Panel.jsx";

afterEach(cleanup);

describe("importar HAR", () => {
  it("acepta hasta 50 MB y rechaza vacío o más grande", () => {
    expect(HAR_MAX_BYTES).toBe(50 * 1024 * 1024);
    expect(harFileProblem(null)).toBe("Elija un archivo HAR.");
    expect(harFileProblem({ size: 0 })).toBe("El archivo está vacío.");
    expect(harFileProblem({ size: HAR_MAX_BYTES + 1 })).toBe("El archivo supera el máximo de 50 MB.");
    expect(harFileProblem({ size: HAR_MAX_BYTES })).toBeNull();
  });
  it("muestra la hora de la carga en UTC, y no interpreta texto que no sea una fecha", () => {
    expect(loadTime("2026-10-10T15:27:09.554000+00:00")).toBe("2026-10-10 15:27:09 UTC");
    expect(loadTime("<img src=x onerror=alert(1)>")).toBe("hora no disponible");
    expect(loadTime(null)).toBe("hora no disponible");
  });
  it("declara el origen de la captura y que no hay fingerprinting instrumentado", () => {
    render(<HarImport />);
    const note = screen.getByTestId("har-source-note").textContent;
    expect(note).toContain("Captura importada: navegador real del usuario.");
    expect(note).toContain("sin fingerprinting instrumentado");
    expect(screen.getByTestId("har-file").getAttribute("type")).toBe("file");
  });
});

describe("terceros por organización en la tabla de requests", () => {
  it("usa party del análisis: la misma organización no es tercero", () => {
    expect(partyLabel({ party: "same_org", third_party: true }, { short: true })).toBe("Misma org.");
    expect(partyLabel({ party: "same_org", third_party: true })).toBe("misma organización (no es tercero)");
    expect(partyLabel({ party: "third_party", third_party: true }, { short: true })).toBe("Tercero");
    expect(partyLabel({ party: "first_party", third_party: false })).toBe("propio del sitio");
  });
  it("sin análisis cae al criterio por dominio y no inventa", () => {
    expect(partyLabel({ party: null, third_party: true }, { short: true })).toBe("Tercero");
    expect(partyLabel({ party: null, third_party: null })).toBe("origen no determinado");
  });
  it("nombra aparte las requests bloqueadas por una extensión", () => {
    expect(requestOutcome({ failure_text: "net::ERR_BLOCKED_BY_CLIENT" })).toBe("bloqueada por una extensión del navegador");
    expect(requestOutcome({ blocked_by_proxy: true, failure_text: "x" })).toBe("bloqueada");
    expect(requestOutcome({ failure_text: "net::ERR_ABORTED" })).toBe("falló");
    expect(requestOutcome({ response_status: 204 })).toBe(204);
  });
});

describe("comparación scan vs HAR", () => {
  it("describe la ola o dice que no hay medición", () => {
    expect(waveText({ available: true, detected: true, requests: 17, organizations: 13, initiator: "gum.criteo.com" }))
      .toBe("17 requests a 13 organizaciones, iniciada por gum.criteo.com");
    expect(waveText({ available: true, detected: false })).toBe("no se observó");
    expect(waveText(null)).toBe("medición no disponible (reanalice la captura)");
    expect(waveText({ available: false, detected: false })).toBe("medición no disponible (reanalice la captura)");
  });
});

describe("título del Panel", () => {
  it("tiene el título y el subtítulo nuevos", () => {
    render(<PanelView />);
    expect(screen.getByTestId("panel-heading").textContent).toBe("Panel de recolección de datos");
    expect(screen.getByTestId("panel-heading-subtitle").textContent).toBe("Métodos, destinos y organizaciones observados en los sitios analizados");
    expect(document.body.textContent).not.toContain("Cómo recopilan información");
  });
});
