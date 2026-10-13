# ADR 010 — Librerías del frontend

Estado: aceptado · Fase: F5

## Contexto
La interfaz necesita gráficos, un grafo de relaciones, una tabla con muchos datos
y rutas. Cada dependencia npm es superficie de ataque (cadena de suministro) en
una aplicación que muestra datos de sitios no confiables. Los candidatos se
evaluaron con los metadatos del registro npm (2026-10-06) **antes de instalar**.

## Evidencia

| Paquete | Versión | Licencia | Última publicación | Creado | Tamaño | Deps | Descargas/sem. | Repositorio |
|---|---|---|---|---|---|---|---|---|
| `recharts` | 3.10.1 | MIT | 2026-07-25 | 2015 | 7,3 MB | 11 | 71 M | recharts/recharts |
| `@xyflow/react` | 12.12.0 | MIT | 2026-09-24 | 2024 | 1,2 MB | 3 | 15 M | xyflow/xyflow |
| `cytoscape` | 3.34.3 | MIT | 2026-09-07 | 2012 | 5,6 MB | 0 | 20 M | cytoscape/cytoscape.js |
| `vis-network` | 10.1.2 | Apache-2.0 o MIT | 2026-08-19 | 2019 | 82 MB | 0 | — | visjs/vis-network |
| `d3-force` | 3.0.0 | ISC | 2021-06-05 | 2016 | 87 KB | 3 | — | d3/d3-force |
| `@tanstack/react-table` | 9.2.6 | MIT | 2026-10-04 | 2022 | 119 KB | 2 | 27 M | TanStack/table |
| `react-router-dom` | 7.18.4 | MIT | 2026-09-15 | 2016 | 5 KB (+router) | 1 | 55 M | remix-run/react-router |

## Decisión
- **Gráficos: `recharts` 3.10.1** (lo pedía la fase). MIT, mantenido, sin
  `<style>` ni scripts inline: funciona con la CSP estricta (comprobado en E2E,
  0 violaciones). Las animaciones se desactivan.
- **Grafo: sin librería.** El grafo es una jerarquía fija de 4 niveles (sitio →
  categorías → organizaciones → dominios). No necesita layout por fuerzas, zoom ni
  edición, que es lo que aportan `@xyflow/react`, `cytoscape` o `vis-network` a
  cambio de 1–82 MB. Se dibuja en columnas con SVG propio
  (`components/Graph.jsx`, ~130 líneas); el texto va en `<text>`, escapado por
  React. Limitado a 40 dominios, con aviso de cuántos quedan fuera.
- **Tabla: sin librería.** La paginación, los filtros y el orden los hace el
  servidor; el navegador nunca recibe más de 200 filas. `@tanstack/react-table`
  resolvería un problema (estado de tabla en el cliente) que aquí no existe.
- **Rutas: sin librería.** Un enrutador por hash de ~45 líneas
  (`lib/router.js`). Los parámetros de la URL se validan antes de usarse.
- **Tests**: `vitest` 5.0.3, `@testing-library/react` 16.3.3 (+ `dom` 10.4.2) y
  `jsdom` 30.1.2, solo como dependencias de desarrollo. Las pruebas E2E usan el
  Playwright de Python que ya tenía el proyecto (servicio `e2e`): cero paquetes
  npm nuevos para eso.

Instalación con `npm install --ignore-scripts --save-exact` (versiones exactas,
sin ejecutar scripts de instalación). `npm audit`: 0 vulnerabilidades.

## Consecuencias
- Una sola dependencia de ejecución nueva (`recharts`), que trae 11 transitivas.
  El bundle pesa 632 KB (188 KB gzip), casi todo por los gráficos.
- El grafo propio no escala a cientos de nodos ni permite reordenar: si hiciera
  falta, `@xyflow/react` es la alternativa evaluada.
- Revisar `npm audit` al actualizar dependencias.
