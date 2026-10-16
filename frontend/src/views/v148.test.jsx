// @vitest-environment jsdom
// v1.4.8 (docs/adr/035): scan fallido = «Sin medición» con su código net::ERR_*; scan parcial; nota Posible.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { bandClass, bands, setBands } from "../lib/format.js";
import { BlockingBanner, NO_MEASUREMENT, NO_NET_ERROR, NoMeasurement, PartialScanNotice } from "../components/ui.jsx";

afterEach(cleanup);

describe("scan fallido", () => {
  it("dice «Sin medición» y el código net::ERR_* real, sin índice", () => {
    render(<NoMeasurement failure={{ error_code: "NAVIGATION_FAILED", net_error: "net::ERR_CERT_AUTHORITY_INVALID" }} message="La navegación falló." />);
    const box = screen.getByTestId("scan-failed");
    expect(NO_MEASUREMENT).toBe("Sin medición");
    expect(screen.getByTestId("no-measurement").textContent).toBe("Sin medición.");
    expect(screen.getByTestId("net-error").textContent).toBe("net::ERR_CERT_AUTHORITY_INVALID");
    expect(box.textContent).toContain("NAVIGATION_FAILED");
    expect(box.textContent).not.toContain("Nada observado");
  });
  it("sin código del navegador lo dice, sin inventarlo", () => {
    render(<NoMeasurement failure={{ error_code: "NAVIGATION_TIMEOUT", net_error: null }} message="Tiempo agotado." />);
    expect(screen.getByTestId("net-error").textContent).toBe(`(${NO_NET_ERROR})`);
  });
});

describe("scan parcial", () => {
  it("muestra el aviso con el mensaje como texto", () => {
    render(<PartialScanNotice partial={{ message: "<b>x</b> 3 con respuesta", net_error: null }} />);
    const notice = screen.getByTestId("partial-scan-notice");
    expect(notice.textContent).toContain("Scan parcial:");
    expect(notice.querySelector("b")).toBeNull();
  });
  it("sin parcial no muestra nada", () => {
    const { container } = render(<PartialScanNotice partial={null} />);
    expect(container.textContent).toBe("");
  });
});

describe("nota Posible (pocas requests o rastreo anómalo sin señal dura)", () => {
  const variant = { level: "POSIBLE", text: "La página podría haber mostrado una versión distinta al navegador automatizado; compare con un HAR propio.",
    signals: [{ signal: "few_requests", detail: "Se capturaron 2 request(s)." }] };
  it("no es el aviso de navegador automatizado y no excluye del ranking", () => {
    render(<BlockingBanner blocking={{ blocked: false, partial: false, signals: [], possible_variant: variant }} />);
    const note = screen.getByTestId("possible-variant-note");
    expect(note.textContent).toContain(variant.text);
    expect(note.textContent).toContain("sigue en el ranking del Panel");
    expect(note.textContent).toContain("Posible");
    expect(screen.queryByTestId("blocking-banner")).toBeNull();
  });
});

describe("bandas (única fuente: data/scoring.yaml, vía /api/bands)", () => {
  it("el frontend no tiene una lista propia de bandas", () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const format = fs.readFileSync(path.resolve(here, "..", "lib", "format.js"), "utf8");
    ["Bajo-moderado", "Muy alto", "Moderado"].forEach((name) => expect(format).not.toContain(`"${name}"`));
  });
  it("usa los nombres que entrega la api, sin «Posible», y lo desconocido queda neutro", () => {
    setBands([{ name: "Bajo", max: 20 }, { name: "Bajo-moderado", max: 40 }, { name: "Moderado", max: 60 }, { name: "Alto", max: 80 }, { name: "Muy alto", max: 100 }]);
    expect(bands()).toEqual(["Bajo", "Bajo-moderado", "Moderado", "Alto", "Muy alto"]);
    bands().forEach((band) => expect(bandClass(band)).not.toContain("bg-white"));
    expect(bandClass("Posible")).toContain("bg-white");
    setBands([{ name: "<b>x</b>".repeat(20) }, null, 7]);
    expect(bands()).toEqual([]);
  });
});
