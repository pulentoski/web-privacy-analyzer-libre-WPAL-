// Grafo de relaciones: sitio → categorías → organizaciones → dominios.
// Es una jerarquía fija de 4 niveles, así que se dibuja en columnas con SVG propio
// (sin librería de grafos). Todo texto va en <text>: React lo escapa.
import { categoryLabel, entityLabel, truncate, UNKNOWN_ENTITY } from "../lib/format.js";

const COLORS = {
  site: "#1e3a8a",
  category: "#334155",
  entity: "#475569",
  firstParty: "#2563eb",
  thirdParty: "#94a3b8",
  tracker: "#dc2626",
  fingerprinting: "#7c3aed",
};
export const MAX_GRAPH_DOMAINS = 40;
const ROW = 24;
const COLUMN_X = [10, 200, 420, 700];
const WIDTH = 980;

export function domainKind(domain) {
  if (domain.fingerprinting) return "fingerprinting";
  if (domain.tracker) return "tracker";
  return domain.third_party ? "thirdParty" : "firstParty";
}

/** Nodos y aristas a partir de la lista de dominios. Función pura (se testea aparte). */
export function buildGraph(domains, siteLabel) {
  const shown = [...domains]
    .sort((a, b) => b.requests - a.requests)
    .slice(0, MAX_GRAPH_DOMAINS)
    .sort((a, b) => (a.category || "").localeCompare(b.category || "") || (a.entity || "").localeCompare(b.entity || "") || a.domain.localeCompare(b.domain));
  const categories = [];
  const entities = [];
  const edges = new Set();
  shown.forEach((domain) => {
    const category = domain.category || "sin análisis";
    // Sin organización conocida, cada dominio queda en su propio nodo: no se agrupan por suposición.
    const entity = domain.entity === UNKNOWN_ENTITY || !domain.entity ? `${UNKNOWN_ENTITY}:${domain.domain}` : domain.entity;
    if (!categories.includes(category)) categories.push(category);
    if (!entities.includes(entity)) entities.push(entity);
    edges.add(`s|site|c|${category}`);
    edges.add(`c|${category}|e|${entity}`);
    edges.add(`e|${entity}|d|${domain.domain}`);
  });
  return { site: siteLabel, categories, entities, domains: shown, edges: [...edges], hidden: Math.max(0, domains.length - shown.length) };
}

export default function Graph({ domains, siteLabel }) {
  const graph = buildGraph(domains, siteLabel);
  const rows = Math.max(1, graph.categories.length, graph.entities.length, graph.domains.length);
  const height = rows * ROW + 20;
  const position = (count, index) => 20 + ((index + 0.5) * (rows * ROW)) / count;
  const y = { "s|site": position(1, 0) };
  graph.categories.forEach((category, index) => (y[`c|${category}`] = position(graph.categories.length, index)));
  graph.entities.forEach((entity, index) => (y[`e|${entity}`] = position(graph.entities.length, index)));
  graph.domains.forEach((domain, index) => (y[`d|${domain.domain}`] = position(graph.domains.length, index)));
  const column = { s: 0, c: 1, e: 2, d: 3 };

  return (
    <div data-testid="graph">
      <ul className="flex flex-wrap gap-4 text-sm mb-2" aria-label="Leyenda del grafo">
        {[["firstParty", "Propio del sitio"], ["thirdParty", "Tercero"], ["tracker", "Con requests de tracking"], ["fingerprinting", "Con patrón de fingerprinting"]].map(([kind, label]) => (
          <li key={kind} className="flex items-center gap-1">
            <svg width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="6" fill={COLORS[kind]} className={`graph-${kind}`} /></svg>
            {label}
          </li>
        ))}
      </ul>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${WIDTH} ${height}`} width="100%" role="img" aria-label="Grafo: sitio, categorías, organizaciones y dominios" style={{ minWidth: "720px" }}>
          {graph.edges.map((edge) => {
            const [fromType, fromId, toType, toId] = edge.split("|");
            const x1 = COLUMN_X[column[fromType]] + 8, x2 = COLUMN_X[column[toType]] - 2;
            const y1 = y[`${fromType}|${fromId}`], y2 = y[`${toType}|${toId}`];
            const middle = (x1 + x2) / 2;
            return <path key={edge} d={`M${x1},${y1} C${middle},${y1} ${middle},${y2} ${x2},${y2}`} fill="none" className="graph-edge" strokeWidth="1.2" />;
          })}
          <g>
            <circle cx={COLUMN_X[0]} cy={y["s|site"]} r="7" fill={COLORS.site} className="graph-site" />
            <text x={COLUMN_X[0] + 12} y={y["s|site"] + 4} fontSize="12" fontWeight="700">{truncate(graph.site, 24).text}</text>
          </g>
          {graph.categories.map((category) => (
            <g key={category}>
              <rect x={COLUMN_X[1] - 6} y={y[`c|${category}`] - 6} width="12" height="12" fill={COLORS.category} className="graph-category" />
              <text x={COLUMN_X[1] + 12} y={y[`c|${category}`] + 4} fontSize="12">{categoryLabel(category)}</text>
            </g>
          ))}
          {graph.entities.map((entity) => {
            const unknown = entity.startsWith(`${UNKNOWN_ENTITY}:`);
            return (
              <g key={entity}>
                <rect x={COLUMN_X[2] - 6} y={y[`e|${entity}`] - 6} width="12" height="12" rx="3" fill={unknown ? undefined : COLORS.entity} className={unknown ? "graph-unknown" : "graph-entity"} stroke={COLORS.entity} strokeDasharray={unknown ? "2 2" : undefined} />
                <text x={COLUMN_X[2] + 12} y={y[`e|${entity}`] + 4} fontSize="12" fontStyle={unknown ? "italic" : "normal"}>
                  {unknown ? "organización no disponible" : truncate(entityLabel(entity), 34).text}
                </text>
              </g>
            );
          })}
          {graph.domains.map((domain) => (
            <g key={domain.domain} data-kind={domainKind(domain)}>
              <circle cx={COLUMN_X[3]} cy={y[`d|${domain.domain}`]} r="6" fill={COLORS[domainKind(domain)]} className={`graph-${domainKind(domain)}`} />
              <text x={COLUMN_X[3] + 12} y={y[`d|${domain.domain}`] + 4} fontSize="12">
                {truncate(domain.domain, 30).text} ({domain.requests})
              </text>
            </g>
          ))}
        </svg>
      </div>
      {graph.hidden > 0 && <p className="muted text-sm">Se muestran los {MAX_GRAPH_DOMAINS} dominios con más requests; hay {graph.hidden} más en la tabla de requests.</p>}
    </div>
  );
}
