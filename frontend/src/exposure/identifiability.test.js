// data/identifiability.yaml debe cubrir todo el catálogo: un atributo sin nivel se mostraría con "—".
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { CATALOG, GROUPS } from "./catalog.js";

const FILE = path.resolve(__dirname, "..", "..", "..", "data", "identifiability.yaml");

/** Lee `seccion: { id: { level } }` del YAML sin dependencias (estructura fija, validada por la API). */
function levelsOf(text, section) {
  const out = {};
  let inside = false;
  let current = null;
  text.split("\n").forEach((line) => {
    if (/^\S/.test(line)) inside = line.startsWith(`${section}:`);
    else if (inside && /^ {2}\S/.test(line)) current = line.trim().replace(/:$/, "");
    else if (inside && current && /^ {4}level:/.test(line)) out[current] = line.split(":")[1].trim();
  });
  return out;
}

describe("niveles de identificabilidad", () => {
  it("cada atributo del catálogo tiene nivel alto, medio o bajo", () => {
    if (!fs.existsSync(FILE)) {
      // Sin data/ montado la misma estructura la valida la suite de la api.
      expect(process.env.WPA_DATA_REQUIRED).not.toBe("1");
      return;
    }
    const text = fs.readFileSync(FILE, "utf8");
    const levels = levelsOf(text, "attributes");
    expect(Object.keys(levels).sort()).toEqual(CATALOG.map((item) => item.id).sort());
    Object.values(levels).forEach((level) => expect(["alto", "medio", "bajo"]).toContain(level));
    expect(levels.canvas).toBe("alto");
    expect(levels.color_depth).toBe("bajo");
    // Estimación cualitativa: el archivo no publica cifras de entropía.
    expect(text).toMatch(/ESTIMACIÓN CUALITATIVA/);
    expect(text.split("\n").filter((line) => !line.trim().startsWith("#")).join("\n")).not.toMatch(/\d+\s*bits de entrop/i);
  });
  it("las subsecciones son las del panel", () => {
    expect(GROUPS.map(([, label]) => label)).toEqual(["Navegador y sistema", "Pantalla", "Hardware", "Huellas derivadas", "Permisos"]);
  });
});
