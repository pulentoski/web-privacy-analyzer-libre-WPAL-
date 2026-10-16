// @vitest-environment jsdom
// v1.4.9 (docs/adr/036): cadena de redirección, Client Hints (solicitud ≠ envío) y «Evidencia X + Inferencia Y».
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ClientHints, RedirectChain, ScoreLevels } from "./RequestDetail.jsx";

afterEach(cleanup);

const CHAIN = [
  { hop: 0, request_seq: 243, request_id: 11, status: 307, host: "anylist.c.appier.net", entity: "Appier",
    location: "https://s.c.appier.net/aprcm?a_i=x", next_request_seq: 295, next_request_id: 12 },
  { hop: 1, request_seq: 295, request_id: 12, status: 302, host: "s.c.appier.net", entity: "Appier",
    location: "https://anylist.c.appier.net/r2?x", next_request_seq: 345, next_request_id: 13 },
  { hop: 2, request_seq: 345, request_id: 13, status: 200, host: "anylist.c.appier.net", entity: "Appier", location: null },
];

describe("cadena de redirección", () => {
  it("muestra cada salto con su Location y la request siguiente", () => {
    render(<RedirectChain jobId="j" chain={CHAIN} current={243} />);
    const hops = screen.getAllByTestId("redirect-hop");
    expect(hops).toHaveLength(3);
    expect(hops[0].textContent).toContain("#244");
    expect(hops[0].textContent).toContain("Location:");
    expect(screen.getAllByTestId("redirect-next").map((link) => link.textContent)).toEqual(["request #296", "request #346"]);
  });
  it("sin redirección no muestra nada", () => {
    const { container } = render(<RedirectChain jobId="j" chain={[CHAIN[2]]} current={345} />);
    expect(container.textContent).toBe("");
  });
});

describe("Client Hints", () => {
  const requested = { organization: "Appier", hints: ["Sec-CH-UA-Full-Version-List", "Sec-CH-UA-Model"], sent: "no_observado", sent_hints: [],
    text: "El servidor pidió datos del navegador potencialmente útiles para identificarlo; esta solicitud no demuestra que los haya recibido." };
  it("una solicitud sin envío nunca se presenta como recepción", () => {
    render(<ClientHints info={{ requested, sent: null, delegation: { label: "No determinado", evidence: [] }, notes: [] }} />);
    expect(screen.getByTestId("ch-requested").textContent).toContain("no demuestra que los haya recibido");
    expect(screen.getByTestId("ch-sent-state").textContent).toContain("no observado");
    expect(screen.queryByTestId("ch-sent")).toBeNull();
    expect(screen.getByTestId("ch-delegation").textContent).toContain("No determinado");
  });
  it("el envío se muestra solo con las cabeceras observadas", () => {
    render(<ClientHints info={{ requested: null, sent: { organization: "Appier", hints: ["Sec-CH-UA-Model"], after_request: true },
      delegation: { label: "Delegación detectada", evidence: ["Permissions-Policy: ch-ua-model=*"] }, notes: [] }} />);
    expect(screen.getByTestId("ch-sent").textContent).toContain("Sec-CH-UA-Model");
  });
});

describe("puntaje por nivel", () => {
  it("muestra Evidencia + Inferencia y avisa si se acota", () => {
    render(<ScoreLevels levels={{ EVIDENCIA: 85, INFERENCIA: 15, POSIBLE: 0, clamped: false }} />);
    expect(screen.getByTestId("score-levels").textContent).toBe("Evidencia 85 + Inferencia 15");
    cleanup();
    render(<ScoreLevels levels={{ EVIDENCIA: 90, INFERENCIA: 30, POSIBLE: 0, clamped: true }} />);
    expect(screen.getByTestId("score-levels").textContent).toContain("se acota");
  });
});
