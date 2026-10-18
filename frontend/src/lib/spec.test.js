// v1.4.10: la tabla del índice de exposición de docs/SPEC.md debe coincidir con data/scoring.yaml §site_exposure
// (componentes, tope y k). scoring.yaml es la fuente; el SPEC lo documenta.
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const ROOT = path.resolve(__dirname, "..", "..", "..");
const SPEC = path.join(ROOT, "docs", "SPEC.md");
const SCORING = path.join(ROOT, "data", "scoring.yaml");

// Bloque `site_exposure:` de scoring.yaml. Cada línea no vacía y sin comentario debe tener la forma
// «  nombre: {cap: N, k: N}»: una línea con otra forma hace fallar el test en vez de ignorarse.
export function scoringComponents(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => /^site_exposure:\s*(#.*)?$/.test(line));
  if (start < 0) throw new Error("scoring.yaml: falta site_exposure");
  const components = {};
  for (const line of lines.slice(start + 1)) {
    const content = line.replace(/\s+#.*$/, "");
    if (!content.trim() || content.trim().startsWith("#")) continue;
    if (!/^\s/.test(content)) break; // siguiente clave de primer nivel
    const match = content.match(/^ {2}([a-z_]+):\s*\{\s*cap:\s*(\d+(?:\.\d+)?),\s*k:\s*(\d+(?:\.\d+)?)\s*\}\s*$/);
    if (!match) throw new Error(`scoring.yaml §site_exposure: línea no reconocida: ${line.trim()}`);
    components[match[1]] = { cap: Number(match[2]), k: Number(match[3]) };
  }
  return components;
}

// Tabla «| Componente | n | cap | k |» de la sección «site_exposure_score» del SPEC.
export function specComponents(text) {
  const section = text.split(/^### site_exposure_score/m)[1];
  if (!section) throw new Error("SPEC.md: falta la sección site_exposure_score");
  const body = section.split(/^#{2,3} /m)[0];
  const components = {};
  let header = false;
  for (const line of body.split("\n")) {
    if (/^\|\s*Componente\s*\|\s*n\s*\|\s*cap\s*\|\s*k\s*\|/.test(line)) { header = true; continue; }
    if (!header || /^\|[-\s|]+\|$/.test(line)) continue;
    if (!line.startsWith("|")) { if (Object.keys(components).length) break; continue; }
    const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
    if (cells.length !== 4) throw new Error(`SPEC.md: fila de la tabla del índice con ${cells.length} columnas: ${line}`);
    components[cells[0]] = { cap: Number(cells[2]), k: Number(cells[3]) };
  }
  return components;
}

describe("docs/SPEC.md y data/scoring.yaml (índice de exposición)", () => {
  it("los archivos están disponibles", () => {
    // El contenedor de tests del frontend monta docs/ y data/ (scripts/test.sh); en CI y en el repo están en el checkout.
    expect([fs.existsSync(SPEC), fs.existsSync(SCORING)]).toEqual([true, true]);
  });
  it("la tabla del SPEC tiene los mismos componentes, topes y k que scoring.yaml", () => {
    const scoring = scoringComponents(fs.readFileSync(SCORING, "utf8"));
    const spec = specComponents(fs.readFileSync(SPEC, "utf8"));
    expect(Object.keys(scoring).length).toBeGreaterThanOrEqual(9);
    expect(spec).toEqual(scoring);
  });
  it("los topes suman 100 en los dos", () => {
    const sum = (components) => Object.values(components).reduce((total, item) => total + item.cap, 0);
    expect(sum(scoringComponents(fs.readFileSync(SCORING, "utf8")))).toBe(100);
    expect(sum(specComponents(fs.readFileSync(SPEC, "utf8")))).toBe(100);
  });
  it("detecta una diferencia y una línea mal formada", () => {
    const yaml = "site_exposure:\n  a: {cap: 60, k: 2}   # x\n  b: {cap: 40, k: 3}\nblocking:\n  x: 1\n";
    const spec = "### site_exposure_score\n\n| Componente | n | cap | k |\n|---|---|---|---|\n| a | n | 60 | 2 |\n| b | n | 41 | 3 |\n\nTexto.\n";
    expect(specComponents(spec)).not.toEqual(scoringComponents(yaml));
    expect(() => scoringComponents("site_exposure:\n  a: 60\n")).toThrow(/no reconocida/);
  });
});
