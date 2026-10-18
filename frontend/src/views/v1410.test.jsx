// @vitest-environment jsdom
// v1.4.10 (docs/adr/037): linker de Google (_gl) con presencia, campos y conclusión por separado, y la interacción con el
// aviso de consentimiento (banner_interaction; los reportes anteriores traen user_interaction).
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ConsentPanel, SiteLinker } from "./Dashboard.jsx";

afterEach(cleanup);

const BASE = {
  source: "navigation", source_label: "navegación", request_id: 3, seq: 2, redirect_chain: null, duplicate_of: null, evidence_refs: [3],
  origin: { url: "https://es.aliexpress.com/", host: "es.aliexpress.com", domain: "aliexpress.com", via: "pagina_anterior" },
  destination: { url: "https://www.aliexpress.com/ssr/x", host: "www.aliexpress.com", domain: "aliexpress.com" },
};
const DECODED = { present: true, format: "linker_v1", fields: [{ name: "_ga", value: "5899…[20 caracteres]", length: 20 }], undecoded_fields: 0 };

describe("linker de Google (_gl)", () => {
  it("separa presencia, campos decodificados y destino; un propio no suma", () => {
    render(<SiteLinker info={{ items: [{ ...BASE, gl: DECODED, counts_in_index: false,
      classification: { status: "first_party", label: "Propio", organization: "Alibaba", basis: "dominio_registrable", basis_label: "dominio registrable" } }] }} />);
    expect(screen.getByTestId("linker-presence").textContent).toContain("es.aliexpress.com");
    expect(screen.getByTestId("linker-fields").textContent).toContain("_ga = 5899…[20 caracteres]");
    expect(screen.getByTestId("linker-destination").textContent).toContain("Propio");
    expect(screen.getByTestId("linker-destination").textContent).toContain("según dominio registrable");
    expect(screen.getByTestId("linker-destination").textContent).toContain("No suma al índice");
    expect(screen.getByTestId("linker-conclusion").textContent).toContain("No muestra que el destino haya reconocido al visitante");
  });
  it("un valor sin formato reconocido muestra solo la presencia, sin campos", () => {
    render(<SiteLinker info={{ items: [{ ...BASE, gl: { present: true, format: "no_reconocido", fields: [], undecoded_fields: 0 }, counts_in_index: true,
      classification: { status: "third_party", label: "Tercero", organization: "Reservas SpA", basis: "mapa_entidades", basis_label: "mapa de entidades" } }] }} />);
    expect(screen.getByTestId("linker-fields").textContent).toContain("formato no reconocido; solo se registra la presencia");
    expect(screen.getByTestId("linker-fields").textContent).not.toContain("_ga");
    expect(screen.getByTestId("linker-destination").textContent).toContain("Suma al puntaje de la request");
  });
  it("una transferencia ya informada no se repite", () => {
    render(<SiteLinker info={{ items: [{ ...BASE, gl: DECODED, counts_in_index: false, duplicate_of: "redirect_sync",
      classification: { status: "third_party", label: "Tercero", organization: "Ads Two", basis: "alias", basis_label: "alias de organización (org_aliases)" } }] }} />);
    expect(screen.getByTestId("linker-destination").textContent).toContain("Ya informado como «Sincronización por redirección»");
  });
  it("sin _gl no muestra nada", () => {
    const { container } = render(<SiteLinker info={{ items: [], total: 0 }} />);
    expect(container.textContent).toBe("");
  });
});

describe("interacción con el aviso de consentimiento", () => {
  it("usa banner_interaction", () => {
    render(<ConsentPanel consent={{ tcf: { present: true }, consent_mode: null, banner_interaction: true, conclusions: [] }} />);
    expect(screen.getByTestId("banner-interaction").textContent).toContain("Interacción con el aviso de consentimiento: sí");
  });
  it("lee un reporte anterior con user_interaction", () => {
    render(<ConsentPanel consent={{ tcf: { present: true }, consent_mode: null, user_interaction: false, conclusions: [] }} />);
    expect(screen.getByTestId("banner-interaction").textContent).toContain("Interacción con el aviso de consentimiento: no");
  });
});
