// @vitest-environment jsdom
// v1.6.0 (docs/adr/042): Resumen en bento. Orden de las secciones, alertas solo cuando existen, «vs scan anterior» solo
// con un scan anterior del mismo protocolo, ranking «Quién recibió más datos» y los colores de ambos temas por variables.
import fs from "node:fs";
import path from "node:path";

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { alerts, figures, figuresSentence, previousDelta, validity } from "../components/Summary.jsx";

let overviewResponse;
let reportResponse;

vi.mock("../lib/api.js", () => ({
  api: {
    report: () => Promise.resolve(reportResponse),
    domains: () => Promise.resolve({ domains: [
      { domain: "site.example", requests: 3, category: "first-party", entity: "Sitio", third_party: false, tracker: false, fingerprinting: false },
      { domain: "tracker.example", requests: 5, category: "advertising", entity: "Ads Co", third_party: true, tracker: true, fingerprinting: false },
    ] }),
    overview: () => Promise.resolve(overviewResponse),
    reportUrl: (jobId) => `/api/scans/${jobId}/report`,
    glossary: () => Promise.resolve({ terms: [], panels: {} }),
  },
}));

const { default: Dashboard } = await import("./Dashboard.jsx");

function report(overrides = {}) {
  const base = {
    scan: { job_id: "j1", url: "https://www.site.example/", final_url: "https://www.site.example/home", source: "scan", started_at: "2026-10-19T12:00:00+00:00" },
    capture: { total_requests: 40 },
    site: {
      exposure_score: 62, band: "Alto",
      breakdown: [
        { component: "tracker_domains", count: 6, points: 20.5, cap: 26, inference_points: 0 },
        { component: "url_leak_recipients", count: 3, points: 9, cap: 12, inference_points: 0 },
        { component: "fp_scripts", count: 1, points: 4, cap: 10, inference_points: 4 },
      ],
      data_categories: [{ category: "IDENTIFIERS", status: "observado", item: "Identificador enviado a Ads Co", evidence_refs: [7] }],
      summary: {
        trackers: 18, third_party_domains: 9, categories: { advertising: 18, "first-party": 10 },
        score_by_level: { EVIDENCIA: 52, INFERENCIA: 10 },
        blocking: { blocked: false, partial: false, possible_variant: null, min_requests: 20 },
        parties: { same_org_domains: ["cdn.site.example"] },
        first_party_telemetry: { requests: 4, scripts: 1 },
        cookie_purposes: { by_purpose: { publicidad: 3, funcional: 1 }, labels: { publicidad: "publicidad", funcional: "funcional" } },
        third_party_services: { items: [] },
      },
    },
    trackers: [{ entity: "Ads Co", domains: ["tracker.example"], request_count: 18 }],
    findings: [
      { type: "id_sync", level: "EVIDENCIA", details: { owners: "4" }, evidence_refs: [7] },
      { type: "url_leak", level: "EVIDENCIA", details: { recipient: "Ads Co" }, evidence_refs: [7] },
      { type: "server_side_meta", level: "INFERENCIA", details: {}, evidence_refs: [8] },
    ],
    fingerprinting: { instrumented: true, scripts: [{ fingerprinting_inferred: true }], exfiltrations: [] },
    consent: { tcf: { present: false }, banner_interaction: false, consent_mode: { requests: 9, states: { "G1--": 9 } },
      conclusions: [{ text: "Se enviaron datos a Google sin declarar estado de consentimiento (gcs=G1--).", level: "EVIDENCIA" }] },
    measurement: {
      conditions: { browser: { name: "Chromium", version: "153" }, browser_mode: "headful", measured_at: "2026-10-19T12:00:00+00:00",
        analyzer_version: "1.18.0", lists_version: "abc", lists: [], egress_country: { status: "ok", country: "Chile", country_code: "CL" } },
      visit_protocol: { applies: true, protocol_version: 1, stages: [{ name: "carga", order: 1, completed: true, planned: {}, requests: 3 }], closing_sends: [], closing_notice: "x" },
      coverage: null,
    },
    limitations: [],
  };
  return { ...base, ...overrides };
}

const OVERVIEW = {
  recipients: [
    { rank: 1, organization: "Ads Co", label: "Ads Co", domains: ["tracker.example"], data_types: ["identificador", "url"],
      data_type_labels: ["Identificador", "URL de la página"], tracking_requests: 18, longest_cookie_days: 395, longest_cookie: "uid" },
    { rank: 2, organization: "no_disponible", label: null, domains: ["cdn.example"], data_types: ["url"], data_type_labels: ["URL de la página"],
      tracking_requests: 0, longest_cookie_days: null, longest_cookie: null },
  ],
  previous_scan: { job_id: "j0", created_at: "2026-10-01T10:00:00+00:00", score: 55, band: "Moderado", protocol_version: 1 },
  previous_reason: null,
};

beforeEach(() => {
  reportResponse = report();
  overviewResponse = OVERVIEW;
});
afterEach(cleanup);

describe("Resumen en bento", () => {
  it("las secciones van en el orden del rediseño, sin perder ninguna", async () => {
    render(<Dashboard jobId="j1" />);
    await screen.findByTestId("recipients");
    await waitFor(() => expect(screen.getAllByTestId("recipient-row")).toHaveLength(2));
    const order = ["summary-header", "summary-bento", "summary-stats", "relations", "chart-category", "chart-org", "recipients", "data-categories",
      "fold-cookies", "fold-services", "fold-levels", "fold-more", "limits-notice"];
    const nodes = order.map((id) => screen.getByTestId(id));
    for (let index = 1; index < nodes.length; index += 1) {
      expect(nodes[index - 1].compareDocumentPosition(nodes[index]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
    // Dentro del bento: índice, lo más relevante, y la columna de condiciones + consentimiento.
    const bento = screen.getByTestId("summary-bento");
    expect([...bento.children].map((node) => node.dataset.testid || [...node.children].map((child) => child.dataset.testid).join("+")))
      .toEqual(["card-exposure", "highlights", "measurement+consent-conclusions"]);
    // Las 8 cifras, cada una con su línea de color por tipo.
    const stats = within(screen.getByTestId("summary-stats")).getAllByText((_, node) => node.classList && node.classList.contains("vignette"));
    expect(stats.map((node) => [node.dataset.testid, node.dataset.kind])).toEqual([
      ["card-trackers", "tracking"], ["card-orgs", "tracking"], ["card-leaks", "tracking"], ["card-exfil", "exfil"],
      ["card-fp", "fp"], ["card-third", "third"], ["card-telemetry", "own"], ["card-same-org", "own"],
    ]);
    // Lo que había sigue: desglose (plegado), cookies, servicios, niveles y dominios de la misma organización.
    expect(screen.getByTestId("card-exposure").textContent).toContain("Dominios de terceros con tracking");
    expect(screen.getAllByTestId("cookie-purpose")).toHaveLength(2);
    expect(screen.getByTestId("same-org").textContent).toContain("cdn.site.example");
    expect(screen.getByTestId("summary-plain").textContent).toContain("La página realizó 40 requests");
    expect(screen.getByTestId("summary-validity").textContent).toBe("Medición válida");
    expect(screen.getByTestId("summary-final-url").textContent).toContain("https://www.site.example/home");
  });

  it("encabezado: validez según la regla antibot", () => {
    expect(validity({ blocked: false, partial: false, possible_variant: { level: "POSIBLE" } }).label).toBe("Posible variante");
    expect(validity({ blocked: false, partial: true }).label).toBe("Bloqueo parcial");
    expect(validity({ blocked: false }).label).toBe("Medición válida");
    expect(validity({ not_applicable: "interactive" }).id).toBe("no_aplica");
  });

  it("«Lo más relevante»: 3 cifras y solo las alertas que existen, con su nivel", async () => {
    const data = report();
    expect(figures(data)).toEqual({ trackerDomains: 6, urlRecipients: 3, sameIdCompanies: 4 });
    expect(figuresSentence(figures(data))).toBe("6 dominios de terceros con rastreo; 3 terceros recibieron la URL de la página; 4 empresas recibieron el mismo identificador.");
    // Hasta 3, en orden: consentimiento sin interacción, sincronización, lado del servidor (el fingerprinting queda fuera).
    expect(alerts(data, 1).map((item) => [item.id, item.level])).toEqual([["consent", "EVIDENCIA"], ["sync", "EVIDENCIA"], ["server_side", "INFERENCIA"]]);
    // Con interacción con el aviso, sin sincronización ni servidor: solo fingerprinting.
    const quiet = report({ findings: [], consent: { ...data.consent, banner_interaction: true } });
    expect(alerts(quiet, 1).map((item) => item.id)).toEqual(["fingerprinting"]);
    expect(alerts(quiet, 0)).toEqual([]);
    reportResponse = quiet;
    overviewResponse = { ...OVERVIEW, recipients: [] };
    render(<Dashboard jobId="j1" />);
    await screen.findByTestId("highlights");
    expect(screen.getAllByTestId("summary-alert").map((node) => node.dataset.alert)).toEqual(["fingerprinting"]);
  });

  it("«vs scan anterior» solo con un scan anterior del mismo protocolo", async () => {
    expect(previousDelta(62, OVERVIEW)).toEqual({ delta: 7, previous: OVERVIEW.previous_scan });
    expect(previousDelta(62, { previous_scan: null, previous_reason: "otro_protocolo" })).toBeNull();
    render(<Dashboard jobId="j1" />);
    const indicator = await screen.findByTestId("exposure-previous");
    expect(indicator.textContent).toBe("↑ 7 vs scan anterior");
    cleanup();
    overviewResponse = { ...OVERVIEW, previous_scan: null, previous_reason: "otro_protocolo" };
    render(<Dashboard jobId="j1" />);
    await screen.findByTestId("recipients");
    await waitFor(() => expect(screen.getAllByTestId("recipient-row")).toHaveLength(2));
    expect(screen.queryByTestId("exposure-previous")).toBeNull();
  });

  it("«Quién recibió más datos»: posición, organización, tipos y cookie más larga", async () => {
    render(<Dashboard jobId="j1" />);
    await waitFor(() => expect(screen.getAllByTestId("recipient-row")).toHaveLength(2));
    const [first, second] = screen.getAllByTestId("recipient-row");
    expect(first.dataset.rank).toBe("1");
    expect(within(first).getByTestId("recipient-org").textContent).toBe("Ads Co");
    expect(within(first).getByTestId("recipient-types").textContent).toBe("IdentificadorURL de la página");
    expect(within(first).getByTestId("recipient-cookie").textContent).toContain("Cookie más larga: 395 días (uid)");
    expect(within(second).getByTestId("recipient-org").textContent).toBe("(sin organización) cdn.example");
    expect(within(second).getByTestId("recipient-cookie").textContent).toContain("no observada en esta captura");
  });

  it("el consentimiento se muestra siempre", async () => {
    reportResponse = report({ consent: {} });
    render(<Dashboard jobId="j1" />);
    const card = await screen.findByTestId("consent-conclusions");
    expect(card.textContent).toContain("Interacción con el aviso de consentimiento: no");
    expect(screen.getByTestId("consent-tcf").textContent).toBe("TCF: no observado en esta captura");
  });
});

describe("temas: variables CSS y contraste", () => {
  const css = fs.readFileSync(path.resolve(__dirname, "../index.css"), "utf8");
  const block = (selector) => {
    const blocks = [...css.matchAll(new RegExp(`${selector.replace(/[[\]"()]/g, "\\$&")}\\s*\\{([^}]*)\\}`, "g"))].map((match) => match[1]).join("\n");
    return Object.fromEntries([...blocks.matchAll(/--([\w-]+):\s*([^;]+);/g)].map((match) => [match[1], match[2].trim()]));
  };
  const luminance = (hex) => {
    const [r, g, b] = [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16) / 255)
      .map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const ratio = (a, b) => {
    const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (high + 0.05) / (low + 0.05);
  };
  const TOKENS = ["c-tracking", "c-fp", "c-own", "c-third", "c-exfil", "c-valid", "c-warn", "card-radius"];
  const classic = { ...block(":root") };
  const purple = { ...block('html[data-theme="purple"]') };

  it("cada color con significado está definido en los dos temas", () => {
    for (const token of TOKENS) {
      expect(classic[token], `Clásico --${token}`).toBeDefined();
      expect(purple[token], `Unidad Púrpura --${token}`).toBeDefined();
    }
    expect(classic["card-radius"]).toBe("16px");
    expect(purple["card-radius"]).toBe("16px");
  });

  it("texto con significado sobre la tarjeta: ≥ 4,5:1 en ambos temas (también en modo presentación)", () => {
    for (const [name, theme, surface] of [["Clásico", classic, classic.surface], ["Unidad Púrpura", purple, purple.surface]]) {
      for (const token of ["c-tracking", "c-fp", "c-own", "c-third", "c-exfil", "c-valid", "c-warn", "ink", "muted"]) {
        expect(ratio(theme[token], surface), `${name} --${token} sobre ${surface}`).toBeGreaterThanOrEqual(4.5);
      }
    }
    const presentation = block('html.presentation[data-theme="classic"]');
    expect(ratio(presentation["c-third"], "#ffffff")).toBeGreaterThanOrEqual(4.5);
  });
});
