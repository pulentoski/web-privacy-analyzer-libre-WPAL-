// @vitest-environment jsdom
// v1.5.0 (docs/adr/038): condiciones de la medición, protocolo de visita con sus etapas, cobertura por contexto dentro de
// «Límites de la medición» y avisos de protocolos mezclados en el Panel y en la comparación.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { countryText, CoverageTable, MeasurementPanel } from "../components/Measurement.jsx";
import { LimitsNotice } from "../components/ui.jsx";

afterEach(cleanup);

const STAGES = ["carga", "espera", "scroll", "espera", "cierre"].map((name, index) => ({
  name, order: index + 1, planned: [{}, { duration_s: 3 }, { max_s: 8, step_interval_ms: 400 }, { duration_s: 3 }, { observe_s: 3 }][index],
  completed: index < 2, started_at: index < 3 ? `2026-10-18T12:00:0${index}.000+00:00` : null, ended_at: null,
  reason: index < 2 ? "duration_elapsed" : index === 2 ? "scan_timeout" : "previous_stage_incomplete",
  reason_text: index < 2 ? "se cumplió el tiempo de la etapa" : index === 2 ? "se agotó el tiempo máximo del scan (SCAN_TIMEOUT_S)" : "no se ejecutó: la etapa anterior no se completó",
  requests: index === 0 ? 4 : 0, request_seqs: [], includes: [],
}));
const COVERAGE = {
  audited_with: "worker/tests/v150/test_coverage_audit.py", probe_apis: ["canvas.toDataURL", "navigator.userAgent"],
  contexts: [
    { id: "main_frame", label: "Frame principal", instrumentation: true, apis_observed: ["canvas.toDataURL", "navigator.userAgent"], traffic_captured: true, limitation: null },
    { id: "dedicated_worker", label: "Dedicated worker", instrumentation: false, apis_observed: [], traffic_captured: true, limitation: "Dedicated workers: …" },
    { id: "service_worker", label: "Service worker", instrumentation: false, apis_observed: [], traffic_captured: false, limitation: "Service workers: …" },
  ],
  closing_events: [{ event: "beforeunload", captured: true }],
};
const MEASUREMENT = {
  protocol_version: 1,
  conditions: {
    browser: { name: "Chromium", version: "153.0.8010.12" }, browser_mode: "headful", measured_at: "2026-10-18T12:00:00.000+00:00",
    analyzer_version: "1.17.0", lists_version: "abc", lists: [{ id: "easylist", version: "202610062156" }],
    egress_country: { status: "ok", country_code: "CL", country: "Chile", source: "DB-IP Lite 2026-10", reason: null },
  },
  visit_protocol: { applies: true, protocol_version: 1, stages: STAGES, note: null, closing_sends: [],
    closing_notice: "La captura sigue activa durante el cierre de la pestaña. El cierre no garantiza capturar todos los beacons de salida." },
  coverage: COVERAGE,
};

describe("condiciones de la medición", () => {
  it("muestra navegador, modo, país y cada etapa con su estado", () => {
    render(<MeasurementPanel measurement={MEASUREMENT} />);
    expect(screen.getByTestId("measurement-browser").textContent).toBe("Chromium 153.0.8010.12");
    expect(screen.getByTestId("measurement-mode").textContent).toBe("con ventana (headful)");
    expect(screen.getByTestId("measurement-country").textContent).toBe("Chile (CL) · DB-IP Lite 2026-10");
    expect(screen.getByTestId("visit-protocol").dataset.protocol).toBe("1");
    const stages = screen.getAllByTestId("visit-stage");
    expect(stages.map((row) => row.dataset.stage)).toEqual(["carga", "espera", "scroll", "espera", "cierre"]);
    expect(stages.map((row) => row.dataset.completed)).toEqual(["true", "true", "false", "false", "false"]);
    expect(stages[2].textContent).toContain("se agotó el tiempo máximo del scan");
    expect(screen.getByTestId("closing-sends").textContent).toContain("ninguno");
    expect(screen.getByTestId("closing-notice").textContent).toContain("no garantiza capturar todos los beacons de salida");
  });
  it("sin protocolo muestra la nota y no inventa etapas", () => {
    render(<MeasurementPanel measurement={{ ...MEASUREMENT, protocol_version: null,
      visit_protocol: { applies: false, protocol_version: null, stages: [], note: "Scan anterior a v1.5.0: se hizo sin el protocolo de visita fijo.", closing_sends: [], closing_notice: "x" } }} />);
    expect(screen.getByTestId("visit-protocol-note").textContent).toContain("Scan anterior a v1.5.0");
    expect(screen.queryAllByTestId("visit-stage")).toHaveLength(0);
    expect(screen.getByTestId("visit-protocol").dataset.protocol).toBe("ninguno");
  });
  it("país desconocido con su motivo; nunca deducido", () => {
    expect(countryText({ status: "desconocido", reason: "EGRESS_IP_SERVICE_URL está vacío: no se consultó la IP de salida." }))
      .toBe("desconocido (EGRESS_IP_SERVICE_URL está vacío: no se consultó la IP de salida.)");
    expect(countryText(undefined)).toBe("desconocido");
  });
  it("un reporte anterior sin sección no muestra el panel", () => {
    const { container } = render(<MeasurementPanel measurement={undefined} />);
    expect(container.textContent).toBe("");
  });
});

describe("cobertura en «Límites de la medición»", () => {
  it("tres columnas separadas por contexto", () => {
    render(<LimitsNotice limitations={["Dedicated workers: …"]}><CoverageTable coverage={COVERAGE} /></LimitsNotice>);
    const rows = screen.getAllByTestId("coverage-row");
    expect(rows.map((row) => row.dataset.context)).toEqual(["main_frame", "dedicated_worker", "service_worker"]);
    expect(rows[1].textContent).toBe("Dedicated workernoningunasí");
    expect(rows[2].textContent).toBe("Service workernoningunano");
    expect(screen.getByTestId("limits-content").textContent).toContain("auditoría reproducible worker/tests/v150/test_coverage_audit.py");
  });
});
