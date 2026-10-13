// F10: frase técnica antes del detalle, glosario con tooltips, menú nuevo, barra de progreso
// real, tema y borrado del historial. Todo lo capturado se sigue pintando como texto.
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { buildGlossary, GlossaryContext } from "../lib/glossary.js";
import { DEFAULT_THEME, normalizeTheme, ThemeContext, THEMES } from "../lib/theme.js";
import { headline } from "../views/Dashboard.jsx";
import { Step } from "../views/Findings.jsx";
import { TABS, TabMenu } from "../views/Scan.jsx";
import { DeleteAllHistory, deletedSummary, DeletedNotice } from "./HistoryControls.jsx";
import { ICON_NAMES, Icon } from "./Icons.jsx";
import StageProgress from "./StageProgress.jsx";
import { GlossaryPage, Term, WhatIsThis } from "./Term.jsx";
import { EvidenceBadge, Plain, TechDetail } from "./ui.jsx";

afterEach(cleanup);

const PAYLOAD = '<img src=x onerror="window.__XSS=1">';
const GLOSSARY = buildGlossary({
  terms: [
    { id: "tracker", term: "Tracker", plain: "rastreador", definition: "Una request con señales de seguimiento." },
    { id: "inferencia", term: "Inferencia", plain: "conclusión razonable", definition: "Se concluye de un patrón; no se observó directamente." },
    { id: "roto" },
  ],
  panels: { trackers: { title: "¿Qué es esto?", definition: "Las requests con señales de seguimiento, por organización.", method: "La atribución procede de un mapa público.", terms: ["tracker", "no_existe"] } },
});

function withGlossary(node, theme = "classic") {
  return render(<ThemeContext.Provider value={theme}><GlossaryContext.Provider value={GLOSSARY}>{node}</GlossaryContext.Provider></ThemeContext.Provider>);
}

describe("frase técnica y detalle técnico", () => {
  it("muestra la frase con su nivel, como texto", () => {
    const { container } = render(<Plain text={`Le contó a ${PAYLOAD} qué página estaba viendo.`} level="EVIDENCIA" />);
    const bubble = screen.getByTestId("plain");
    expect(bubble.textContent).toContain(PAYLOAD);
    expect(bubble.getAttribute("data-level")).toBe("EVIDENCIA");
    expect(within(bubble).getByText("Evidencia")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });
  it("sin frase no pinta nada", () => {
    const { container } = render(<Plain text={null} level="EVIDENCIA" />);
    expect(container.innerHTML).toBe("");
  });
  it("el detalle técnico está cerrado hasta que se pide, y la frase queda antes", () => {
    render(<div><Plain text="Frase técnica." level="INFERENCIA" /><TechDetail><p>URL, parámetros y cabeceras</p></TechDetail></div>);
    expect(screen.queryByText("URL, parámetros y cabeceras")).toBeNull();
    const toggle = screen.getByTestId("tech-detail-toggle");
    expect(toggle.textContent).toBe("Ver detalle técnico");
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    const detail = screen.getByText("URL, parámetros y cabeceras");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(toggle.textContent).toBe("Cerrar detalle técnico");
    // Orden en el documento: primero la frase, después el detalle.
    expect(screen.getByTestId("plain").compareDocumentPosition(detail) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe("glosario", () => {
  it("un término muestra su definición en un tooltip accesible", () => {
    withGlossary(<p>Estos son <Term id="tracker">rastreadores</Term>.</p>);
    const term = screen.getByTestId("term");
    expect(term.textContent).toContain("rastreadores");
    const tip = within(term).getByRole("tooltip");
    expect(tip.textContent).toContain("Una request con señales de seguimiento.");
    expect(tip.textContent).toBe("Tracker: Una request con señales de seguimiento.");
    expect(term.getAttribute("aria-describedby")).toBe(tip.id);
    expect(term.getAttribute("tabindex")).toBe("0");
  });
  it("sin glosario, o con un término desconocido, el texto se muestra igual", () => {
    render(<p><Term id="tracker">rastreadores</Term></p>);
    expect(screen.getByText("rastreadores")).toBeTruthy();
    expect(screen.queryByRole("tooltip")).toBeNull();
    withGlossary(<p><Term id="no_existe">algo</Term></p>);
    expect(screen.getByText("algo")).toBeTruthy();
  });
  it("descarta entradas mal formadas", () => {
    expect(GLOSSARY.terms.map((term) => term.id)).toEqual(["tracker", "inferencia"]);
    expect(buildGlossary(null)).toEqual({ terms: [], panels: {}, byId: {} });
    expect(buildGlossary({ terms: "x", panels: 3 }).terms).toEqual([]);
  });
  it("el panel «¿Qué es esto?» describe el contenido y el método", () => {
    withGlossary(<WhatIsThis panel="trackers" />);
    const panel = screen.getByTestId("what-is-this");
    expect(panel.textContent).toContain("¿Qué es esto?");
    expect(screen.getByTestId("what-definition").textContent).toContain("Las requests con señales de seguimiento");
    expect(screen.getByTestId("what-method").textContent).toBe("Método. La atribución procede de un mapa público.");
    expect(screen.queryByTestId("what-analogy")).toBeNull();
    expect(within(panel).getAllByTestId("term")).toHaveLength(1);
    expect(screen.getByTestId("glossary-link").getAttribute("href")).toBe("#/glossary");
  });
  it("un panel que no existe no pinta nada", () => {
    const { container } = withGlossary(<WhatIsThis panel="otro" />);
    expect(container.querySelector("[data-testid=what-is-this]")).toBeNull();
  });
  it("la página de glosario lista cada término", () => {
    withGlossary(<GlossaryPage />);
    expect(screen.getAllByTestId("glossary-term")).toHaveLength(2);
    expect(screen.getByTestId("glossary").textContent).toContain("rastreador");
  });
  it("el badge de nivel usa la definición del glosario", () => {
    withGlossary(<EvidenceBadge level="INFERENCIA" />);
    expect(screen.getByText("Inferencia").getAttribute("title")).toBe("Se concluye de un patrón; no se observó directamente.");
  });
});

describe("menú del scan", () => {
  it("tiene las cinco secciones con nombre técnico y subtítulo técnico", () => {
    expect(TABS.map((tab) => [tab.title, tab.technical, tab.subtitle])).toEqual([
      ["Resumen", null, "Índice de exposición, terceros contactados y categorías de datos"],
      ["Hallazgos", null, "Ocho grupos técnicos, con nivel de evidencia y requests de respaldo"],
      ["Rastreadores", null, "Requests con señales de seguimiento, agrupadas por organización"],
      ["Fingerprinting", null, "Lectura de atributos del dispositivo mediante APIs del navegador"],
      ["Tráfico", "requests", "Todas las requests capturadas durante la visita"],
    ]);
    TABS.forEach((tab) => expect(ICON_NAMES).toContain(tab.icon));
    expect(new Set(TABS.map((tab) => tab.icon)).size).toBe(5);
  });
  it("cada pestaña lleva ícono, título, subtítulo y marca la actual", () => {
    render(<TabMenu jobId="0b3512cb-837b-4729-8c2d-d96cf8a1fc02" active="trackers" />);
    const menu = screen.getByTestId("tab-menu");
    expect(menu.textContent).not.toContain("Orden de lectura sugerido"); // v1.2: sin párrafos explicativos
    const links = within(menu).getAllByRole("link");
    expect(links).toHaveLength(5);
    links.forEach((link) => {
      expect(link.querySelector("svg[data-icon]")).toBeTruthy();
      expect(within(link).getByTestId("tab-title").textContent.length).toBeGreaterThan(5);
      expect(within(link).getByTestId("tab-subtitle").textContent.length).toBeGreaterThan(10);
    });
    expect(screen.getByTestId("tab-trackers").getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("tab-summary").getAttribute("aria-current")).toBeNull();
    expect(screen.getByTestId("tab-findings").textContent).toContain("Hallazgos");
    expect(screen.getByTestId("tab-requests").textContent).toContain("Tráfico (requests)");
    expect(screen.getByTestId("tab-requests").getAttribute("href")).toBe("#/scan/0b3512cb-837b-4729-8c2d-d96cf8a1fc02/requests");
    expect(screen.getByTestId("tab-summary").getAttribute("href")).toBe("#/scan/0b3512cb-837b-4729-8c2d-d96cf8a1fc02");
  });
  it("un ícono desconocido cae en el de ayuda en vez de romper", () => {
    const { container } = render(<Icon name={PAYLOAD} />);
    expect(container.querySelector("svg").getAttribute("data-icon")).toBe("help");
  });
});

describe("barra de progreso", () => {
  const states = () => Object.fromEntries(screen.getAllByRole("listitem").map((item) => [item.getAttribute("data-testid"), item.getAttribute("data-state")]));
  it("marca la etapa actual y muestra el contador real", () => {
    withGlossary(<StageProgress progress={{ stage: "capturing", requests: 37, capture_elapsed_s: 12.3, capture_max_s: 60 }} />);
    expect(states()).toEqual({ "stage-queued": "done", "stage-opening": "done", "stage-capturing": "current", "stage-analyzing": "pending", "stage-building": "pending", "stage-done": "pending" });
    expect(screen.getByTestId("progress-requests").textContent).toBe("37");
    expect(screen.getByTestId("progress").textContent).toContain("requests capturadas hasta ahora");
    expect(screen.getByTestId("progress-max").textContent).toBe("60");
    const meter = screen.getByRole("meter");
    expect(meter.getAttribute("aria-valuemax")).toBe("60");
    expect(meter.getAttribute("aria-valuenow")).toBe("12");
    expect(screen.getByTestId("progress").textContent).not.toContain("%");
  });
  it("no inventa números que el worker no publicó", () => {
    withGlossary(<StageProgress progress={{ stage: "opening", requests: null, capture_elapsed_s: null, capture_max_s: 60 }} />);
    expect(screen.queryByTestId("progress-requests")).toBeNull();
    expect(screen.queryByTestId("progress-time")).toBeNull();
    expect(screen.queryByRole("meter")).toBeNull();
    expect(screen.getByTestId("progress-description").textContent).toContain("se inicia y solicita la página");
  });
  it("en cola muestra el puesto real", () => {
    withGlossary(<StageProgress progress={{ stage: "queued", requests: null, queue_position: 3 }} />);
    expect(screen.getByTestId("queue-position").textContent).toBe("puesto 3 en la cola");
    expect(states()["stage-queued"]).toBe("current");
  });
  it("un scan fallido marca dónde se quedó", () => {
    withGlossary(<StageProgress progress={{ stage: "failed", failed_at: "opening", requests: null }}><p>detalle del error</p></StageProgress>);
    expect(states()).toMatchObject({ "stage-queued": "done", "stage-opening": "failed", "stage-capturing": "pending", "stage-failed": "failed" });
    expect(screen.getByText("detalle del error")).toBeTruthy();
  });
  it("al terminar todo queda hecho, sin onomatopeyas en ningún tema", () => {
    withGlossary(<StageProgress progress={{ stage: "done", requests: 41, capture_elapsed_s: 15.4, capture_max_s: 60 }} />);
    expect(new Set(Object.values(states()))).toEqual(new Set(["done"]));
    expect(screen.getByTestId("progress-elapsed").textContent).toBe("15.4");
    expect(screen.getByTestId("progress").textContent).not.toMatch(/[¡!]/);
    cleanup();
    withGlossary(<StageProgress progress={{ stage: "done", requests: 41 }} />, "purple");
    expect(screen.getByTestId("progress").textContent).not.toMatch(/[¡!]/);
  });
  it("en un grupo de Privacy Test muestra la corrida k de N", () => {
    withGlossary(<StageProgress testId="group-progress" title="Progreso de la corrida en curso" run={{ index: 2, of: 6 }} progress={{ stage: "analyzing", requests: 21 }} />);
    expect(screen.getByTestId("progress-run").textContent).toBe("Corrida 2 de 6");
    expect(screen.getByTestId("group-progress").getAttribute("data-stage")).toBe("analyzing");
  });
});

describe("paso de «Hallazgos por grupo»", () => {
  const step = {
    id: "equipo", number: 2, title: "Fingerprinting", technical: "fingerprinting", icon: "device", fixed: false, observed: true, count: 2, total_items: 2,
    levels: { EVIDENCIA: 1, INFERENCIA: 1 },
    sentences: [{ text: "Programas de 1 organización leyeron características de su equipo.", level: "EVIDENCIA" }, { text: "En 1 caso, es compatible con fingerprinting.", level: "INFERENCIA" }],
    items: [
      { key: null, type: "fp_read", level: "EVIDENCIA", plain: `Un programa de ${PAYLOAD} leyó de su equipo: el tamaño de su pantalla.`, claim: `El script ${PAYLOAD} llamó a screen.width`, evidence_refs: { requests: [], calls: [7] } },
      { key: "fingerprinting-3", type: "canvas_fingerprinting", level: "INFERENCIA", plain: "Es compatible con tomar la huella de su tarjeta gráfica.", claim: "detalle técnico", evidence_refs: { requests: [4], calls: [8] } },
    ],
  };
  it("muestra título, conteo y una frase por nivel antes del detalle", () => {
    const { container } = withGlossary(<ol><Step jobId="job" step={step} /></ol>);
    expect(screen.getByTestId("story-title").textContent).toBe("2. Fingerprinting");
    expect(screen.getByTestId("story-count").textContent).toBe("2");
    const sentences = screen.getAllByTestId("story-sentence");
    expect(sentences.map((node) => node.getAttribute("data-level"))).toEqual(["EVIDENCIA", "INFERENCIA"]);
    expect(screen.queryByTestId("story-item")).toBeNull();
    fireEvent.click(screen.getByTestId("story-detail-toggle"));
    const items = screen.getAllByTestId("story-item");
    expect(items).toHaveLength(2);
    expect(items[0].textContent).toContain(PAYLOAD);
    expect(within(items[1]).getByTestId("ref-request").getAttribute("href")).toBe("#/scan/job/request/4");
    expect(container.querySelector("img")).toBeNull();
  });
  it("un paso sin hallazgos lo dice; el último es fijo", () => {
    withGlossary(<ol><Step jobId="job" step={{ ...step, observed: false, count: 0, total_items: 0, levels: {}, items: [], sentences: [{ text: "No se observó en esta visita.", level: null }] }} /></ol>);
    expect(screen.getByTestId("story-none").textContent).toBe("No se observó en esta visita.");
    expect(screen.getByTestId("story-step").getAttribute("data-observed")).toBe("false");
    expect(screen.queryByTestId("story-detail-toggle")).toBeNull();
    cleanup();
    withGlossary(<ol><Step jobId="job" step={{ ...step, id: "no_visible", number: 7, title: "Fuera del alcance observable", fixed: true, count: null, items: [], total_items: 0, sentences: [{ text: "Lo que pasa en sus servidores no es observable.", level: "DESCONOCIDO" }] }} /></ol>);
    expect(screen.queryByTestId("story-count")).toBeNull();
    expect(screen.getByTestId("story-sentence").getAttribute("data-level")).toBe("DESCONOCIDO");
  });
});

describe("resumen", () => {
  it("la frase del resumen usa los números del análisis", () => {
    expect(headline({ total_requests: 427 }, { third_party_domains: 33 })).toBe("La página realizó 427 requests y contactó 33 dominios de terceros.");
    expect(headline({ total_requests: 1 }, { third_party_domains: 1 })).toBe("La página realizó 1 request y contactó 1 dominio de tercero.");
  });
});

describe("tema", () => {
  it("clásico es el tema por defecto y solo se aceptan los dos temas", () => {
    expect(DEFAULT_THEME).toBe("classic");
    expect(THEMES.map((theme) => [theme.id, theme.label])).toEqual([["classic", "Clásico"], ["purple", "Unidad Púrpura"]]);
    expect(normalizeTheme("purple")).toBe("purple");
    // El tema Cómic se eliminó: la preferencia guardada migra a Unidad Púrpura.
    expect(normalizeTheme("comic")).toBe("purple");
    expect(normalizeTheme("cómic")).toBe("purple");
    expect(normalizeTheme(PAYLOAD)).toBe("classic");
    expect(normalizeTheme(null)).toBe("classic");
  });
  it("las tipografías son locales: ninguna hoja de estilo ni HTML apunta a otro origen", () => {
    const root = path.resolve(__dirname, "..");
    const css = fs.readFileSync(path.join(root, "index.css"), "utf8");
    expect(css).toContain('@import "@fontsource/barlow-condensed/latin-700.css"');
    expect(css).toContain('@import "@fontsource/jetbrains-mono/latin-400.css"');
    expect(css).not.toMatch(/bangers|comic-neue|data-theme="comic"/i);
    const html = fs.readFileSync(path.resolve(root, "..", "index.html"), "utf8");
    [css, html].forEach((text) => {
      expect(text).not.toMatch(/https?:\/\//);
      expect(text).not.toMatch(/url\(\s*["']?data:/);
    });
    const packages = JSON.parse(fs.readFileSync(path.resolve(root, "..", "package.json"), "utf8")).dependencies;
    expect(packages["@fontsource/barlow-condensed"]).toMatch(/^\d+\.\d+\.\d+$/);
    expect(packages["@fontsource/jetbrains-mono"]).toMatch(/^\d+\.\d+\.\d+$/);
    expect(packages["@fontsource/bangers"]).toBeUndefined();
    expect(packages["@fontsource/comic-neue"]).toBeUndefined();
    ["barlow-condensed", "jetbrains-mono"].forEach((font) => {
      const license = path.resolve(root, "..", "node_modules", "@fontsource", font, "LICENSE");
      expect(fs.readFileSync(license, "utf8")).toContain("SIL Open Font License, Version 1.1");
    });
  });
});

describe("borrado del historial", () => {
  it("resume cuántos scans y cuánto espacio se liberó", () => {
    expect(deletedSummary({ scans: 3, groups: 1, reports: 2, bytes_freed: 1258291 })).toBe("Se borraron 3 scans, 1 grupo de Opciones avanzadas y 2 reportes exportados. Se liberaron 1.2 MB de datos.");
    expect(deletedSummary({ scans: 1, groups: 0, reports: 0, bytes_freed: 2048 })).toBe("Se borró 1 scan y 0 reportes exportados. Se liberaron 2.0 KB de datos.");
    render(<DeletedNotice result={{ deleted: { scans: 2, groups: 0, reports: 6, bytes_freed: 4096 }, note: "Los respaldos de backups/ no se tocan." }} />);
    expect(screen.getByTestId("deleted-summary").textContent).toContain("Se borraron 2 scans y 6 reportes exportados. Se liberaron 4.0 KB de datos.");
    expect(screen.getByTestId("deleted-notice").textContent).toContain("backups/");
  });
  it("borrar todo exige escribir BORRAR exactamente", () => {
    render(<DeleteAllHistory stats={{ scans: 12, groups: 2, reports: 5, delete_enabled: true, confirmation: "BORRAR" }} onDeleted={() => {}} />);
    expect(screen.queryByTestId("delete-all-form")).toBeNull();
    fireEvent.click(screen.getByTestId("delete-all-open"));
    expect(screen.getByTestId("delete-all-count").textContent).toBe("12");
    expect(screen.getByTestId("delete-all-form").textContent).toContain("backups/");
    const input = screen.getByTestId("delete-all-input");
    const confirm = screen.getByTestId("delete-all-confirm");
    expect(confirm.disabled).toBe(true);
    ["borrar", "BORRA", "BORRAR ", " BORRAR"].forEach((value) => {
      fireEvent.change(input, { target: { value } });
      expect(confirm.disabled).toBe(true);
    });
    fireEvent.change(input, { target: { value: "BORRAR" } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(screen.getByTestId("delete-all-cancel"));
    expect(screen.queryByTestId("delete-all-form")).toBeNull();
  });
  it("en modo demo no se ofrece borrar", () => {
    render(<DeleteAllHistory stats={{ scans: 12, groups: 0, reports: 0, delete_enabled: false, confirmation: "BORRAR" }} onDeleted={() => {}} />);
    expect(screen.queryByTestId("delete-all-open")).toBeNull();
    expect(screen.getByTestId("delete-disabled").textContent).toContain("modo demo");
  });
  it("sin scans no hay nada que borrar", () => {
    render(<DeleteAllHistory stats={{ scans: 0, groups: 0, reports: 0, delete_enabled: true, confirmation: "BORRAR" }} onDeleted={() => {}} />);
    expect(screen.getByTestId("delete-all-open").disabled).toBe(true);
  });
});
