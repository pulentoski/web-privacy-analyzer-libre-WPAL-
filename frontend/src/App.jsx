import { lazy, Suspense, useEffect, useState } from "react";

import { GlossaryPage } from "./components/Term.jsx";
import { api } from "./lib/api.js";
import { buildGlossary, EMPTY_GLOSSARY, GlossaryContext } from "./lib/glossary.js";
import { buildHash, useRoute } from "./lib/router.js";
import { applyTheme, readTheme, ThemeContext, THEMES } from "./lib/theme.js";
import ResourceIndicator from "./components/ResourceIndicator.jsx";
import { Logo } from "./components/ui.jsx";
import Analyze from "./views/Analyze.jsx";
import Exposure from "./views/Exposure.jsx";
import History from "./views/History.jsx";
import PanelView from "./views/Panel.jsx";
import PrivacyTest from "./views/PrivacyTest.jsx";
import Scan from "./views/Scan.jsx";
import VisitComparison from "./views/VisitComparison.jsx";

// Control negativo de XSS: SOLO en el build de test. Con cualquier otro valor esta rama es
// código muerto y el empaquetador elimina la vista vulnerable del bundle.
const XssControl = import.meta.env.VITE_XSS_CONTROL === "1" ? lazy(() => import("./views/XssControl.jsx")) : null;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function readPresentation() {
  try {
    return window.localStorage.getItem("presentation") === "1";
  } catch {
    return false;
  }
}

export default function App() {
  const route = useRoute();
  const [presentation, setPresentation] = useState(readPresentation);
  const [theme, setTheme] = useState(readTheme);
  const [glossary, setGlossary] = useState(EMPTY_GLOSSARY);
  // "exposure" = modo demo que solo publica Mi exposición (lo decide nginx, no el cliente:
  // en ese modo la API de scans responde 403 pase lo que pase aquí).
  const [mode, setMode] = useState(null);
  useEffect(() => {
    api.mode().then((data) => setMode(data && data.mode === "exposure" ? "exposure" : "full"), () => setMode("full"));
  }, []);

  // El glosario es texto fijo: se pide una vez. Si falla, la interfaz funciona igual, sin tooltips.
  useEffect(() => {
    if (mode !== "full") return;
    api.glossary().then((data) => setGlossary(buildGlossary(data)), () => setGlossary(EMPTY_GLOSSARY));
  }, [mode]);

  useEffect(() => {
    document.documentElement.classList.toggle("presentation", presentation);
    try {
      window.localStorage.setItem("presentation", presentation ? "1" : "0");
    } catch {
      /* sin almacenamiento: el modo dura lo que dure la pestaña */
    }
  }, [presentation]);

  useEffect(() => applyTheme(theme), [theme]);

  const [section, jobId, tab, requestId] = route.segments;
  // «Privacy Test» pasó a ser las Opciones avanzadas de «Analizar un sitio»: #/privacy redirige.
  // (#/privacy/<id> sigue siendo el resultado de un grupo.)
  const legacyPrivacy = section === "privacy" && !UUID.test(jobId || "");
  useEffect(() => {
    if (legacyPrivacy) window.location.replace(buildHash(["analyze"], { advanced: 1 }));
  }, [legacyPrivacy]);

  // Panel (inicio). `fixtures=1` solo tiene efecto en el stack de pruebas (lo decide la API).
  let view = <PanelView includeTests={route.query.fixtures === "1"} />;
  if (section === "analyze" || legacyPrivacy) view = <Analyze advanced={legacyPrivacy || route.query.advanced === "1"} />;
  if (section === "history") view = <History />;
  if (section === "scan" && UUID.test(jobId || "")) {
    const isRequest = tab === "request" && /^[0-9]{1,18}$/.test(requestId || "");
    view = <Scan jobId={jobId} tab={isRequest ? "requests" : tab} requestId={isRequest ? requestId : null} query={route.query} />;
  }

  if (section === "privacy" && !legacyPrivacy) view = <PrivacyTest groupId={jobId} />;
  if (section === "comparison" && UUID.test(jobId || "")) view = <VisitComparison comparisonId={jobId} />;
  if (section === "glossary") view = <GlossaryPage />;
  if (section === "exposure" || mode === "exposure") view = <Exposure mode={mode || "full"} />;
  if (mode === null) view = null;
  if (XssControl && mode === "full" && section === "__xss-control" && UUID.test(jobId || "")) {
    view = <Suspense fallback={null}><XssControl jobId={jobId} /></Suspense>;
  }

  return (
    <ThemeContext.Provider value={theme}>
      <GlossaryContext.Provider value={glossary}>
        <div className="app-root">
          <header className="app-header">
            <div className="max-w-6xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
              <a href="#/" className="brand-link text-lg font-bold display" data-testid="home-link">
                <Logo size="header" testId="header-logo" />
                <span>Web Privacy &amp; Tracker Analyzer</span>
              </a>
              {mode === "full" && (
                <nav className="flex flex-wrap gap-4 text-sm font-bold" aria-label="Principal" data-testid="main-nav">
                  <a href="#/" data-testid="nav-panel" aria-current={!section ? "page" : undefined}>Panel</a>
                  <a href="#/analyze" data-testid="nav-scans" aria-current={section === "analyze" ? "page" : undefined}>Analizar un sitio</a>
                  <a href="#/history" data-testid="nav-history" aria-current={section === "history" ? "page" : undefined}>Historial</a>
                  <a href="#/glossary" data-testid="nav-glossary" aria-current={section === "glossary" ? "page" : undefined}>Glosario</a>
                </nav>
              )}
              <div className="flex flex-wrap items-center gap-2">
                <div role="group" aria-label="Tema visual" className="inline-flex gap-1" data-testid="theme-selector">
                  {THEMES.map((item) => (
                    <button key={item.id} type="button" className={`btn text-sm ${theme === item.id ? "btn-primary" : ""}`} aria-pressed={theme === item.id}
                      onClick={() => setTheme(item.id)} data-testid={`theme-${item.id}`}>
                      {item.label}
                    </button>
                  ))}
                </div>
                <button type="button" className="btn text-sm" aria-pressed={presentation} onClick={() => setPresentation(!presentation)} data-testid="presentation-toggle">
                  {presentation ? "Salir del modo presentación" : "Modo presentación"}
                </button>
              </div>
            </div>
            {/* Cromo de la aplicación, no contenido: vive en el encabezado y se pinta fijo en la esquina inferior. */}
            {mode === "full" && <ResourceIndicator />}
          </header>
          <main className="max-w-6xl mx-auto px-4 py-4 app-main">{view}</main>
        </div>
      </GlossaryContext.Provider>
    </ThemeContext.Provider>
  );
}
