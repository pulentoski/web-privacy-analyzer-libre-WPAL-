// @vitest-environment jsdom
// v1.3.1: índice parcial del HAR y botón visible para elegir el archivo .har.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { BandBadge, BlockingBanner, PARTIAL_BLOCK_BANNER, PARTIAL_INDEX } from "../components/ui.jsx";
import HarImport from "./HarImport.jsx";
import { FirstPartyTelemetry } from "./Trackers.jsx";

afterEach(cleanup);

describe("índice parcial del HAR", () => {
  it("lo rotula como parcial, sin cookies ni fingerprinting", () => {
    expect(PARTIAL_INDEX).toBe("índice parcial (sin cookies ni fingerprinting)");
    render(<BandBadge band="Alto" score={49} partial />);
    expect(screen.getByTestId("partial-index").textContent).toBe(`49 · Alto ${PARTIAL_INDEX}`);
  });
  it("un scan no lleva el rótulo", () => {
    render(<BandBadge band="Alto" score={91} />);
    expect(screen.queryByTestId("partial-index")).toBeNull();
  });
});

describe("selector de archivo HAR", () => {
  it("muestra un botón propio, el nombre del archivo y «Importar y analizar» deshabilitado desde el inicio", () => {
    render(<HarImport />);
    const choose = screen.getByTestId("har-choose");
    expect(choose.tagName).toBe("BUTTON");
    expect(choose.textContent).toBe("Seleccionar archivo .har");
    expect(choose.getAttribute("aria-describedby")).toBe("har-file-name");
    expect(screen.getByTestId("har-file-name").textContent).toBe("Ningún archivo seleccionado");
    expect(screen.getByTestId("har-file").getAttribute("accept")).toBe(".har,application/json");
    const submit = screen.getByTestId("har-submit");
    expect(submit.textContent).toBe("Importar y analizar");
    expect(submit.disabled).toBe(true);
  });
});

describe("bloqueo parcial (v1.3.2)", () => {
  const signals = [{ signal: "challenge_component", detail: "<img src=x onerror=alert(1)> firma punish" }];
  it("es un aviso informativo distinto del de visita posiblemente bloqueada", () => {
    render(<BlockingBanner blocking={{ blocked: false, partial: true, signals }} />);
    const banner = screen.getByTestId("partial-blocking-banner");
    expect(PARTIAL_BLOCK_BANNER).toBe("Bloqueo parcial: un componente mostró verificación antibot.");
    expect(banner.textContent).toContain(PARTIAL_BLOCK_BANNER);
    expect(banner.textContent).toContain("sigue en el ranking del Panel");
    expect(banner.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(banner.querySelector("img")).toBeNull();
    expect(screen.queryByTestId("blocking-banner")).toBeNull();
  });
  it("con otra señal manda el aviso de visita posiblemente bloqueada", () => {
    render(<BlockingBanner blocking={{ blocked: true, partial: false, signals }} />);
    expect(screen.getByTestId("blocking-banner").textContent).toContain("posiblemente");
    expect(screen.queryByTestId("partial-blocking-banner")).toBeNull();
  });
});

describe("ilustración giratoria y tono de los títulos (v1.3.3)", () => {
  it("la ilustración aparece solo mientras el proceso está en curso", async () => {
    const { default: StageProgress } = await import("../components/StageProgress.jsx");
    const { rerender } = render(<StageProgress progress={{ stage: "capturing", requests: 3 }} />);
    const image = screen.getByTestId("scan-spinner").querySelector("img");
    expect(image.getAttribute("alt")).toContain("Scan en curso");
    expect(image.getAttribute("src")).toBe("/scanning-320.jpg");
    rerender(<StageProgress progress={{ stage: "done", requests: 3 }} />);
    expect(screen.queryByTestId("scan-spinner")).toBeNull();
    rerender(<StageProgress progress={{ stage: "failed", failed_at: "capturing" }} />);
    expect(screen.queryByTestId("scan-spinner")).toBeNull();
    expect(document.querySelector(".panel-head").dataset.tone).toBe("danger");
  });
});

describe("telemetría propia (v1.3.4)", () => {
  const telemetry = { requests: 54, endpoints: 9, scripts: 7,
    endpoint_list: [{ host: "api.tienda.example", path: "/tracks/<img src=x onerror=alert(1)>", kind: "known", name: "Melidata (Mercado Libre)", requests: 12 }],
    script_list: [{ host: "cdn.tienda.example", path: "/melidata.min.js", kind: "script", name: "Melidata (Mercado Libre)", requests: 1 }] };
  it("se lista aparte, con su conteo y como texto", () => {
    render(<FirstPartyTelemetry telemetry={telemetry} />);
    expect(screen.getByTestId("telemetry-counts").textContent).toContain("54 requests de eventos hacia 9 endpoints; 7 scripts de analítica propia.");
    const rows = screen.getAllByTestId("telemetry-row");
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain("<img src=x onerror=alert(1)>");
    expect(rows[0].querySelector("img")).toBeNull();
    expect(screen.getByTestId("first-party-telemetry").textContent).toContain("no son terceros");
  });
  it("sin la medición no muestra nada (no inventa cero)", () => {
    const { container } = render(<FirstPartyTelemetry telemetry={undefined} />);
    expect(container.textContent).toBe("");
  });
  it("rastreo de terceros bajo con telemetría propia es una nota, no un bloqueo", () => {
    render(<BlockingBanner blocking={{ blocked: false, partial: false, signals: [], note: { signal: "low_third_party_tracking", detail: "Rastreo de terceros bajo; telemetría propia detectada (54 requests)." } }} />);
    expect(screen.getByTestId("low-tracking-note").textContent).toContain("Rastreo de terceros bajo; telemetría propia detectada.");
    expect(screen.queryByTestId("blocking-banner")).toBeNull();
  });
});
