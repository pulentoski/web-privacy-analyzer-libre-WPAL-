import { describe, expect, it } from "vitest";

import {
  bandClass, bands, buildQuery, setBands, errorMessage, formatBytes, isFinished, levelInfo, LEVELS, orUnavailable, PROGRESS_STAGES, safeHttpUrl,
  sanitizeRequestFilters, scanStage, stageIndex, stageLabel, truncate, validateScanUrl,
} from "./format.js";
import { buildHash, parseHash } from "./router.js";

describe("truncate", () => {
  it("deja intactos los textos cortos", () => {
    expect(truncate("hola", 10)).toEqual({ text: "hola", truncated: false, hidden: 0 });
  });
  it("corta e informa cuánto oculta", () => {
    expect(truncate("x".repeat(150), 100)).toEqual({ text: "x".repeat(100), truncated: true, hidden: 50 });
  });
  it("tolera null, undefined y no-cadenas", () => {
    expect(truncate(null).text).toBe("");
    expect(truncate(undefined).text).toBe("");
    expect(truncate(12345, 3)).toEqual({ text: "123", truncated: true, hidden: 2 });
    expect(truncate({ a: 1 }, 50).text).toBe("[object Object]");
  });
});

describe("safeHttpUrl", () => {
  it("acepta solo http y https", () => {
    expect(safeHttpUrl("https://example.com/a?b=1")).toBe("https://example.com/a?b=1");
    expect(safeHttpUrl("HTTP://example.com")).toBe("http://example.com/");
  });
  it.each([
    "javascript:alert(1)", "JaVaScRiPt:alert(1)", " javascript:alert(1)", "\tjavascript:alert(1)", "java\nscript:alert(1)",
    "data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)", "file:///etc/passwd", "blob:https://example.com/x",
    "//example.com", "/ruta/relativa", "example.com", "", "https://", "http://[mal", null, undefined, 42, {},
    "https://example.com/" + "a".repeat(9000),
  ])("rechaza %s", (value) => {
    expect(safeHttpUrl(value)).toBeNull();
  });
});

describe("validateScanUrl", () => {
  it("acepta URLs públicas http(s)", () => {
    expect(validateScanUrl("https://www.biobiochile.cl")).toBeNull();
    expect(validateScanUrl("  http://example.com/ruta?x=1  ")).toBeNull();
    expect(validateScanUrl("https://example.com:443/")).toBeNull();
  });
  it.each([
    ["", "Escriba una URL."], ["example.com", "http://"], ["ftp://example.com", "http://"], ["javascript:alert(1)", "http://"],
    ["https://user:pass@example.com", "credenciales"], ["https://example.com:8443", "puertos"], ["http://localhost", "dominio público"],
    ["https://" + "a".repeat(2100) + ".com", "demasiado larga"],
  ])("rechaza %s", (value, fragment) => {
    expect(validateScanUrl(value)).toContain(fragment);
  });
});

describe("niveles de evidencia y bandas", () => {
  it("define los cuatro niveles con etiqueta, explicación y estilo distintos", () => {
    expect(Object.keys(LEVELS)).toEqual(["EVIDENCIA", "INFERENCIA", "POSIBLE", "DESCONOCIDO"]);
    const classes = new Set(Object.values(LEVELS).map((level) => level.className));
    expect(classes.size).toBe(4);
    Object.values(LEVELS).forEach((level) => {
      expect(level.label.length).toBeGreaterThan(3);
      expect(level.description.length).toBeGreaterThan(30);
    });
  });
  it("un nivel desconocido no se disfraza de otro", () => {
    expect(levelInfo("SEGURO").label).toBe("SEGURO");
    expect(levelInfo(undefined).label).toBe("sin nivel");
    expect(levelInfo("<img src=x onerror=alert(1)>").label).toBe("<img src=x onerror=alert(1)>");
  });
  it("cada banda tiene su clase y lo desconocido una neutra", () => {
    // v1.4.9: las bandas las entrega la api (data/scoring.yaml); el color va por posición.
    setBands([{ name: "Bajo" }, { name: "Bajo-moderado" }, { name: "Moderado" }, { name: "Alto" }, { name: "Muy alto" }]);
    expect(new Set(bands().map(bandClass)).size).toBe(5);
    expect(bandClass("Otra")).toContain("bg-white");
  });
});

describe("scanStage", () => {
  it.each([
    [{ progress: { stage: "queued" } }, "queued"],
    [{ progress: { stage: "opening" } }, "opening"],
    [{ progress: { stage: "capturing" } }, "capturing"],
    [{ progress: { stage: "analyzing" } }, "analyzing"],
    [{ progress: { stage: "building" } }, "building"],
    [{ progress: { stage: "done" } }, "done"],
    [{ progress: { stage: "failed" } }, "failed"],
    [{ stage: "capturing" }, "capturing"],
    [{ progress: { stage: "<img src=x>" } }, "desconocido"],
    [{}, "desconocido"],
    [null, "desconocido"],
  ])("%o → %s", (scan, stage) => {
    expect(scanStage(scan)).toBe(stage);
  });
  it("solo done y failed son finales", () => {
    expect(isFinished({ progress: { stage: "done" } })).toBe(true);
    expect(isFinished({ progress: { stage: "failed" } })).toBe(true);
    expect(isFinished({ progress: { stage: "building" } })).toBe(false);
    expect(isFinished({ progress: { stage: "capturing" } })).toBe(false);
  });
  it("las etapas son las seis del progreso real, en orden", () => {
    expect(PROGRESS_STAGES.map((stage) => stage.id)).toEqual(["queued", "opening", "capturing", "analyzing", "building", "done"]);
    expect(PROGRESS_STAGES.map((stage) => stage.label)).toEqual(["En cola", "Abriendo el sitio", "Capturando", "Analizando", "Generando resultado", "Finalizado"]);
    expect(stageLabel("failed")).toBe("Falló");
    expect(stageLabel("otra")).toBe("Desconocido");
    expect(stageIndex("building")).toBe(4);
  });
});

describe("errorMessage", () => {
  it("traduce los error_code conocidos", () => {
    expect(errorMessage({ error_code: "IP_FORBIDDEN" })).toContain("rango prohibido");
    expect(errorMessage({ error_code: "RATE_LIMITED" })).toContain("Demasiados scans");
    expect(errorMessage({ error_code: "EGRESS_BLOCKED" })).toContain("bloqueado");
  });
  it("usa el mensaje del servidor o uno genérico", () => {
    expect(errorMessage({ error_code: "OTRO", message: "detalle" })).toBe("detalle");
    expect(errorMessage({})).toBe("Ocurrió un error inesperado.");
    expect(errorMessage(null)).toBe("Ocurrió un error inesperado.");
  });
});

describe("formateo", () => {
  it("formatBytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes("12")).toBe("—");
  });
  it("lo que falta se dice, no se inventa", () => {
    expect(orUnavailable(null)).toBe("no disponible");
    expect(orUnavailable("")).toBe("no disponible");
    expect(orUnavailable(0)).toBe(0);
    expect(orUnavailable(false)).toBe(false);
  });
});

describe("filtros de la tabla", () => {
  it("buildQuery omite vacíos y ordena las claves", () => {
    expect(buildQuery({ page: 2, band: "Alto", domain: "", blocked: null, category: undefined })).toBe("?band=Alto&page=2");
    expect(buildQuery({})).toBe("");
    expect(buildQuery({ domain: "a&b=c" })).toBe("?domain=a%26b%3Dc");
  });
  it("sanitizeRequestFilters descarta claves y valores no válidos", () => {
    setBands([{ name: "Bajo" }, { name: "Alto" }]);
    expect(sanitizeRequestFilters({
      band: "Alto", category: "analytics", mechanism: "pixel", third_party: "true", blocked: "false", domain: "google",
      sort: "-score", page: "3", page_size: "100",
    })).toEqual({ band: "Alto", category: "analytics", mechanism: "pixel", third_party: "true", blocked: "false", domain: "google", sort: "-score", page: 3, page_size: 100 });
    expect(sanitizeRequestFilters({
      band: "Altísimo", third_party: "quizas", sort: "drop table", page: "-4", page_size: "5000", otra: "x", domain: "d".repeat(300),
    })).toEqual({});
    expect(sanitizeRequestFilters(undefined)).toEqual({});
    expect(sanitizeRequestFilters({ page: "abc", page_size: "25" })).toEqual({ page_size: 25 });
  });
});

describe("rutas por hash", () => {
  it("parsea segmentos y query", () => {
    expect(parseHash("#/scan/abc/requests?band=Alto&page=2")).toEqual({ segments: ["scan", "abc", "requests"], query: { band: "Alto", page: "2" } });
    expect(parseHash("")).toEqual({ segments: [], query: {} });
    expect(parseHash("#/scan/%E0%A4%A")).toEqual({ segments: ["scan", "%E0%A4%A"], query: {} });
  });
  it("buildHash escapa cada segmento y es inverso de parseHash", () => {
    const hash = buildHash(["scan", "a/b", "request", 7], { f: "general-3", vacio: "" });
    expect(hash).toBe("#/scan/a%2Fb/request/7?f=general-3");
    expect(parseHash(hash)).toEqual({ segments: ["scan", "a/b", "request", "7"], query: { f: "general-3" } });
  });
});
