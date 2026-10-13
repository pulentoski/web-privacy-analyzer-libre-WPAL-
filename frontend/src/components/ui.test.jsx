import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { filterFindings } from "../views/Findings.jsx";
import { buildGraph, domainKind, MAX_GRAPH_DOMAINS } from "./Graph.jsx";
import { BandBadge, Captured, EvidenceBadge, EvidenceLegend, EvidenceRefs, ExternalUrl, LimitsNotice, TextViewer } from "./ui.jsx";

afterEach(cleanup);

const XSS = '<img src=x onerror="window.__XSS=1"><script>window.__XSS=1</script>';

describe("EvidenceBadge", () => {
  it.each([["EVIDENCIA", "Evidencia"], ["INFERENCIA", "Inferencia"], ["POSIBLE", "Posible"], ["DESCONOCIDO", "Desconocido"]])(
    "%s muestra su etiqueta y explica el nivel en el tooltip", (level, label) => {
      render(<EvidenceBadge level={level} />);
      const badge = screen.getByText(label);
      expect(badge.getAttribute("title").length).toBeGreaterThan(30);
      expect(badge.getAttribute("aria-label")).toContain(label);
      expect(badge.dataset.level).toBe(level);
    });
  it("es el mismo componente en toda la app: misma clase base y una clase de color por nivel", () => {
    const { container } = render(<><EvidenceBadge level="EVIDENCIA" /><EvidenceBadge level="INFERENCIA" /></>);
    const [a, b] = container.querySelectorAll(".badge");
    expect(a.className).not.toBe(b.className);
    expect(a.className).toContain("badge");
  });
  it("la leyenda lista los cuatro niveles", () => {
    render(<EvidenceLegend />);
    expect(screen.getAllByRole("listitem")).toHaveLength(4);
  });
});

describe("BandBadge", () => {
  it("muestra puntaje y banda", () => {
    render(<BandBadge band="Alto" score={75} />);
    expect(screen.getByText("75 · Alto")).toBeTruthy();
  });
  it("sin análisis no muestra 0", () => {
    render(<BandBadge band={null} score={null} />);
    expect(screen.getByText("sin análisis")).toBeTruthy();
  });
});

describe("Captured", () => {
  it("pinta HTML capturado como texto, sin crear elementos", () => {
    const { container } = render(<Captured value={XSS} limit={500} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=");
    expect(window.__XSS).toBeUndefined();
  });
  it("trunca y expande con «ver más»", () => {
    render(<Captured value={"a".repeat(300)} limit={100} />);
    expect(screen.getByText(/ver más \(200 caracteres\)/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByText("ver menos")).toBeTruthy();
    expect(document.body.textContent).toContain("a".repeat(300));
  });
  it("dentro de un enlace no ofrece «ver más» (no anida controles)", () => {
    const { container } = render(<Captured value={"a".repeat(300)} limit={100} expandable={false} />);
    expect(container.querySelector("button")).toBeNull();
    expect(container.textContent).toBe("a".repeat(100) + "…");
  });
  it("un valor ausente se dice", () => {
    render(<Captured value={null} />);
    expect(screen.getByText("no disponible")).toBeTruthy();
  });
});

describe("ExternalUrl", () => {
  it("por defecto una URL capturada no es un enlace", () => {
    const { container } = render(<ExternalUrl value="https://example.com/x" />);
    expect(container.querySelector("a")).toBeNull();
  });
  it("habilitada, solo enlaza http(s) y con rel seguro", () => {
    const { container } = render(<ExternalUrl value="https://example.com/x" clickable />);
    const link = container.querySelector("a");
    expect(link.getAttribute("href")).toBe("https://example.com/x");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    expect(link.getAttribute("target")).toBe("_blank");
  });
  it.each(["javascript:alert(1)", "data:text/html,<script>alert(1)</script>", " javascript:alert(1)", "vbscript:x"])(
    "nunca enlaza %s aunque esté habilitada", (value) => {
      const { container } = render(<ExternalUrl value={value} clickable />);
      expect(container.querySelector("a")).toBeNull();
      expect(container.textContent).toContain(value.trim().slice(0, 10));
    });
});

describe("TextViewer", () => {
  it("formatea JSON y lo muestra como texto", () => {
    const { container } = render(<TextViewer value={'{"a":"<b>x</b>"}'} />);
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("pre").textContent).toContain('"a": "<b>x</b>"');
  });
  it("lo que no es JSON se muestra tal cual", () => {
    const { container } = render(<TextViewer value={XSS} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("pre").textContent).toBe(XSS);
  });
});

describe("EvidenceRefs", () => {
  it("enlaza cada referencia a su request o llamada", () => {
    const { container } = render(<EvidenceRefs jobId="j1" requests={[7, 9]} calls={[3]} />);
    const hrefs = [...container.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["#/scan/j1/request/7", "#/scan/j1/request/9", "#/scan/j1/fingerprinting?call=3"]);
  });
  it("limita cuántas muestra y lo dice", () => {
    render(<EvidenceRefs jobId="j1" requests={Array.from({ length: 30 }, (_, i) => i)} max={5} />);
    expect(screen.getByText(/y 25 más/)).toBeTruthy();
  });
  it("sin referencias lo indica", () => {
    render(<EvidenceRefs jobId="j1" />);
    expect(screen.getByText("sin referencias")).toBeTruthy();
  });
});

describe("LimitsNotice", () => {
  it("advierte que 0 exfiltraciones no significa que no salgan datos", () => {
    render(<LimitsNotice limitations={["una", "dos"]} />);
    expect(screen.getByText(/«0 exfiltraciones» no significa que no salgan datos/)).toBeTruthy();
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
  });
});

describe("filtro de hallazgos", () => {
  const items = [{ level: "EVIDENCIA" }, { level: "INFERENCIA" }, { level: "EVIDENCIA" }];
  it("filtra por nivel conocido", () => {
    expect(filterFindings(items, "EVIDENCIA")).toHaveLength(2);
    expect(filterFindings(items, "POSIBLE")).toHaveLength(0);
  });
  it("un nivel desconocido no filtra nada", () => {
    expect(filterFindings(items, "")).toHaveLength(3);
    expect(filterFindings(items, "SEGURO")).toHaveLength(3);
  });
});

describe("grafo", () => {
  const domain = (name, extra = {}) => ({ domain: name, third_party: true, requests: 1, category: "analytics", entity: "no_disponible", tracker: false, fingerprinting: false, ...extra });
  it("clasifica cada dominio en un solo color", () => {
    expect(domainKind(domain("a", { third_party: false }))).toBe("firstParty");
    expect(domainKind(domain("a"))).toBe("thirdParty");
    expect(domainKind(domain("a", { tracker: true }))).toBe("tracker");
    expect(domainKind(domain("a", { tracker: true, fingerprinting: true }))).toBe("fingerprinting");
  });
  it("no agrupa dominios sin organización conocida", () => {
    const graph = buildGraph([domain("a.example"), domain("b.example"), domain("g1.example", { entity: "Google" }), domain("g2.example", { entity: "Google" })], "sitio");
    expect(graph.entities).toEqual(["Google", "no_disponible:a.example", "no_disponible:b.example"]);
    expect(graph.categories).toEqual(["analytics"]);
    expect(graph.edges).toContain("e|Google|d|g1.example");
    expect(graph.edges).toContain("e|Google|d|g2.example");
  });
  it("limita la cantidad de dominios e informa cuántos quedan fuera", () => {
    const many = Array.from({ length: MAX_GRAPH_DOMAINS + 15 }, (_, i) => domain(`d${i}.example`, { requests: i }));
    const graph = buildGraph(many, "sitio");
    expect(graph.domains).toHaveLength(MAX_GRAPH_DOMAINS);
    expect(graph.hidden).toBe(15);
    expect(graph.domains.map((d) => d.domain)).not.toContain("d0.example");
  });
});
