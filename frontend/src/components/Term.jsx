// Glosario en la interfaz: <Term> pone un tooltip sobre un término técnico, <WhatIsThis> es
// el panel «¿Qué es esto?» de cada pestaña y <GlossaryPage> lista todos los términos.
// Los textos vienen de data/glossary.yaml (texto fijo del proyecto, pintado como texto).
import { useId } from "react";

import { useGlossary } from "../lib/glossary.js";
import { Icon } from "./Icons.jsx";
import { Link, Panel } from "./ui.jsx";

/** Término con su definición al pasar el cursor o al enfocarlo con el teclado. */
export function Term({ id, children }) {
  const { byId } = useGlossary();
  const tipId = useId();
  const term = byId[id];
  // Sin glosario (aún cargando o no disponible) el texto se muestra igual, sin tooltip.
  if (!term) return <>{children}</>;
  return (
    <span className="term" tabIndex={0} aria-describedby={tipId} data-term={id} data-testid="term">
      {children || term.term}
      <span className="term-tip" role="tooltip" id={tipId}>
        <strong>{term.term}</strong>: {term.definition}
      </span>
    </span>
  );
}

/** Panel «¿Qué es esto?»: qué muestra la vista + cómo se obtiene + términos relacionados. */
export function WhatIsThis({ panel }) {
  const { panels, byId } = useGlossary();
  const info = panels[panel];
  if (!info) return null;
  return (
    <details className="panel p-3" data-testid="what-is-this" data-panel={panel}>
      <summary className="cursor-pointer font-bold flex items-center gap-2">
        <Icon name="help" /> {info.title || "¿Qué es esto?"}
      </summary>
      <div className="mt-2 space-y-2 text-sm">
        <p data-testid="what-definition"><strong>Contenido.</strong> {info.definition}</p>
        {info.method && <p data-testid="what-method"><strong>Método.</strong> {info.method}</p>}
        {(info.terms || []).length > 0 && (
          <p>
            <strong>Términos de esta vista:</strong>{" "}
            {info.terms.filter((id) => byId[id]).map((id, index) => (
              <span key={id}>{index > 0 && " · "}<Term id={id}>{byId[id].term}</Term></span>
            ))}
            {" · "}<Link to={["glossary"]} testId="glossary-link">ver el glosario completo</Link>
          </p>
        )}
      </div>
    </details>
  );
}

export function GlossaryPage() {
  const { terms } = useGlossary();
  return (
    <Panel title="Glosario" subtitle="Definición técnica de cada término; en la interfaz aparecen subrayados con puntos." testId="glossary">
      {terms.length === 0 ? <p className="muted italic">El glosario no está disponible en este momento.</p> : (
        <dl className="space-y-3">
          {terms.map((term) => (
            <div key={term.id} className="panel p-3" data-testid="glossary-term" id={`term-${term.id}`}>
              <dt className="font-bold">{term.term} <span className="muted font-normal">— {term.plain}</span></dt>
              <dd className="text-sm mt-1">{term.definition}</dd>
            </div>
          ))}
        </dl>
      )}
    </Panel>
  );
}
