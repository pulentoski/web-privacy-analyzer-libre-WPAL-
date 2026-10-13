// Glosario (data/glossary.yaml, servido por GET /api/glossary). Se carga una vez y se
// comparte por contexto: los tooltips de <Term> y los paneles «¿Qué es esto?» lo leen de aquí.
import { createContext, useContext } from "react";

export const EMPTY_GLOSSARY = { terms: [], panels: {}, byId: {} };

/** Normaliza la respuesta de la API. Lo que no tenga la forma esperada se descarta. */
export function buildGlossary(data) {
  const terms = (data && Array.isArray(data.terms) ? data.terms : []).filter(
    (term) => term && typeof term.id === "string" && typeof term.term === "string" && typeof term.definition === "string",
  );
  const byId = {};
  terms.forEach((term) => {
    byId[term.id] = term;
  });
  const panels = data && data.panels && typeof data.panels === "object" ? data.panels : {};
  return { terms, panels, byId };
}

export const GlossaryContext = createContext(EMPTY_GLOSSARY);

export function useGlossary() {
  return useContext(GlossaryContext);
}

// Nivel de evidencia -> término del glosario.
export const LEVEL_TERMS = { EVIDENCIA: "evidencia", INFERENCIA: "inferencia", POSIBLE: "posible", DESCONOCIDO: "desconocido" };
