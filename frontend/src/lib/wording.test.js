// La interfaz nunca promete anonimato ni que el visitante quede "oculto": solo dice qué
// cambió y qué sigue siendo observable. Este test recorre TODOS los textos del frontend.
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { formatStats, testSize } from "./format.js";

const ROOT = path.resolve(__dirname, "..");
const FORBIDDEN = [/\ban[oó]nim[oa]s?\b/i, /ocult[oa]s?\b/i, /ocultar|ocultan|oculte/i, /invisible/i, /indetectable/i, /irrastreable/i, /no \w+ pueden (rastrear|identificar)/i];

function sources(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return sources(full);
    return /\.(jsx?|css|html)$/.test(entry.name) && !/\.test\.jsx?$/.test(entry.name) ? [full] : [];
  });
}

describe("textos de la interfaz", () => {
  const files = [...sources(ROOT), path.resolve(ROOT, "..", "index.html")];
  it("revisa una cantidad razonable de archivos", () => {
    expect(files.length).toBeGreaterThan(15);
    expect(files.some((file) => file.endsWith("PrivacyTest.jsx"))).toBe(true);
  });
  it.each(files.map((file) => [path.relative(ROOT, file), file]))("%s no promete anonimato", (_, file) => {
    const text = fs.readFileSync(file, "utf8");
    FORBIDDEN.forEach((pattern) => {
      const match = text.match(pattern);
      expect(match ? `${match[0]} en ${file}` : null).toBeNull();
    });
  });
  it.each(files.map((file) => [path.relative(ROOT, file), file]))("%s no lleva onomatopeyas ni exclamaciones de apertura", (_, file) => {
    const match = fs.readFileSync(file, "utf8").match(/¡|onomatop/i);
    expect(match ? `${match[0]} en ${file}` : null).toBeNull();
  });
  it("el único uso de «anonimato» es para negarlo", () => {
    files.forEach((file) => {
      const text = fs.readFileSync(file, "utf8");
      (text.match(/[^.\n]*anonimato[^.\n]*/gi) || []).forEach((sentence) => expect(sentence).toMatch(/no es anonimato/i));
    });
  });
});

// Las frases técnicas y el glosario viven en data/*.yaml (los sirve la API): también son textos
// de la interfaz. Aquí se revisan como texto plano; su estructura la valida la API al cargarlos.
describe("textos de data/ que muestra la interfaz", () => {
  const DATA = path.resolve(ROOT, "..", "..", "data");
  const names = ["explanations.yaml", "glossary.yaml", "identifiability.yaml"];
  it.each(names)("%s no promete anonimato y trata de usted", (name) => {
    const file = path.join(DATA, name);
    if (!fs.existsSync(file)) {
      // El contenedor de tests del frontend solo monta frontend/: la misma comprobación corre en la suite de la api.
      expect(process.env.WPA_DATA_REQUIRED).not.toBe("1");
      return;
    }
    const text = fs.readFileSync(file, "utf8").split("\n").filter((line) => !line.trim().startsWith("#")).join("\n");
    // Registro técnico: sin exclamaciones ni analogías coloquiales.
    const COLLOQUIAL = [/[¡!]/, /\banalogy\b/, /\bguardia\b/i, /\bcarta\b/i, /\bfirma\b/i, /\bcomo una?\b/i];
    [...FORBIDDEN, ...COLLOQUIAL, /\banonimato\b/i, /\btu\b/i, /\btus\b/i, /\bpuedes\b/i, /\btienes\b/i].forEach((pattern) => {
      const match = text.match(pattern);
      expect(match ? `${match[0]} en ${name}` : null).toBeNull();
    });
  });
});

describe("formato del Privacy Test", () => {
  it("formatStats muestra mediana y rango", () => {
    expect(formatStats({ median: 414, min: 409, max: 765 })).toBe("414 (409–765)");
    expect(formatStats({ median: 21, min: 21, max: 21 })).toBe("21");
    expect(formatStats(null)).toBe("—");
  });
  it("testSize multiplica escenarios, perfiles y corridas", () => {
    expect(testSize(["a", "b", "c"], ["real"], 2)).toBe(6);
    expect(testSize([], ["real"], 2)).toBe(0);
    expect(testSize(["a"], ["x", "y", "z"], 1)).toBe(3);
  });
});
