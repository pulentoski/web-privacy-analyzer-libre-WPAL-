// @vitest-environment jsdom
// v1.5.1: «Mostrar identificadores completos» en el detalle de request (desactivado: la api enmascara) y la marca de la
// organización junto a su dueño («LinkedIn (Microsoft)»). La api se sustituye por respuestas fijas.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { entityLabel } from "../lib/format.js";

const ID = "5f0c3e9a7b1d4c2e8f6a0b9c3d7e1f42";
const MASKED = "5f0c…[32 caracteres]";
const calls = [];

function detail(reveal) {
  const value = reveal ? ID : MASKED;
  return {
    request_id: 7, seq: 1, url: `https://px.ads.linkedin.com/collect?uid=${value}`, host: "px.ads.linkedin.com", method: "GET",
    entity: "Microsoft", brand: "LinkedIn", party: "third_party", third_party: true, registrable_domain: "linkedin.com",
    category: "advertising", band: "Alto", score: 70, masked: !reveal, plain: null, reasons: [], findings: [],
    parameters: [{ source: "query", name: "uid", value, shapes: [], identifier_like: true },
                 { source: "cookie", name: "li_sugr", value, shapes: [] }],
    request_headers: [{ name: "cookie", value: `li_sugr=${value}` }], response_headers: [{ name: "location", value: `https://www.linkedin.com/sync/${value}` }],
    redirect_chain: [
      { hop: 0, request_seq: 1, request_id: 7, status: 302, host: "px.ads.linkedin.com", entity: "Microsoft", brand: "LinkedIn", location: `https://www.linkedin.com/sync/${value}`, next_request_seq: 2, next_request_id: 8 },
      { hop: 1, request_seq: 2, request_id: 8, status: 200, host: "www.linkedin.com", entity: "Microsoft", brand: "LinkedIn", location: null, next_request_seq: null, next_request_id: null },
    ],
    decoded_values: [], initiator: null, frame_url: "http://site.example/",
  };
}

vi.mock("../lib/api.js", () => ({
  api: {
    requestDetail: (jobId, requestId, reveal) => {
      calls.push(reveal);
      return Promise.resolve(detail(reveal));
    },
  },
}));

const { default: RequestDetail } = await import("./RequestDetail.jsx");

afterEach(() => {
  cleanup();
  calls.length = 0;
});

async function openTechDetail() {
  const toggle = await screen.findByTestId("request-tech-toggle");
  if (toggle.getAttribute("aria-expanded") !== "true") fireEvent.click(toggle);
  return screen.findByTestId("request-tech-content");
}

describe("detalle de request: identificadores", () => {
  it("por defecto pide el detalle enmascarado y no muestra ningún valor completo", async () => {
    render(<RequestDetail jobId="11111111-1111-1111-1111-111111111111" requestId={7} />);
    const content = await openTechDetail();
    expect(calls).toEqual([false]);
    expect(screen.getByTestId("request-reveal").checked).toBe(false);
    expect(screen.getByTestId("request-masking-note").textContent).toContain("enmascarados");
    expect(content.textContent).not.toContain(ID);
    expect(content.textContent).toContain(MASKED);
  });

  it("«Mostrar identificadores completos» vuelve a pedirlo sin enmascarar", async () => {
    render(<RequestDetail jobId="11111111-1111-1111-1111-111111111111" requestId={7} />);
    await openTechDetail();
    fireEvent.click(screen.getByTestId("request-reveal"));
    const content = await openTechDetail();
    await screen.findByText((text) => text.includes("valores completos"));
    expect(calls).toEqual([false, true]);
    expect(content.textContent).toContain(ID);
  });

  it("al pasar a otra request vuelve a enmascarado", async () => {
    const { rerender } = render(<RequestDetail jobId="11111111-1111-1111-1111-111111111111" requestId={7} />);
    await openTechDetail();
    fireEvent.click(screen.getByTestId("request-reveal"));
    await screen.findByText((text) => text.includes("valores completos"));
    rerender(<RequestDetail jobId="11111111-1111-1111-1111-111111111111" requestId={8} />);
    await openTechDetail();
    expect(screen.getByTestId("request-reveal").checked).toBe(false);
    expect(calls).toEqual([false, true, false]);
  });
});

describe("marca y dueño", () => {
  it("«Marca (Dueño)» solo cuando difieren", () => {
    expect(entityLabel("Microsoft", "LinkedIn")).toBe("LinkedIn (Microsoft)");
    expect(entityLabel("Microsoft", null)).toBe("Microsoft");
    expect(entityLabel("Microsoft", "Microsoft")).toBe("Microsoft");
    expect(entityLabel("no_disponible", "LinkedIn")).toBe("Organización no disponible");
  });

  it("el detalle de request y la cadena de redirección muestran la marca", async () => {
    render(<RequestDetail jobId="11111111-1111-1111-1111-111111111111" requestId={7} />);
    expect((await screen.findByTestId("request-entity")).textContent).toBe("LinkedIn (Microsoft)");
    await openTechDetail();
    expect(screen.getAllByTestId("redirect-hop").every((hop) => hop.textContent.includes("LinkedIn (Microsoft)"))).toBe(true);
  });
});
