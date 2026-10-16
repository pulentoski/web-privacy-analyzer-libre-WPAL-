// @vitest-environment jsdom
// v1.4.8 (docs/adr/035): scan fallido = «Sin medición» con su código net::ERR_*; scan parcial; nota Posible.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { BANDS, bandClass } from "../lib/format.js";
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

describe("bandas (única fuente: data/scoring.yaml)", () => {
  it("el frontend usa los mismos nombres y orden, sin «Posible»", () => {
    expect(BANDS).toEqual(["Bajo", "Bajo-moderado", "Moderado", "Alto", "Muy alto"]);
    expect(BANDS).not.toContain("Posible");
    BANDS.forEach((band) => expect(bandClass(band)).not.toContain("bg-white"));
    const file = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "data", "scoring.yaml");
    if (!fs.existsSync(file)) {
      // Igual que wording.test.js: el contenedor del frontend sin data/ montado no puede comparar.
      expect(process.env.WPA_DATA_REQUIRED).not.toBe("1");
      return;
    }
    const text = fs.readFileSync(file, "utf8");
    const block = text.slice(text.indexOf("bands:"), text.indexOf("tracker_min_band:"));
    expect([...block.matchAll(/name:\s*([^,}]+?)\s*,/g)].map((match) => match[1])).toEqual(BANDS);
  });
});
