# Cambios

Formato: una sección por versión, la más reciente arriba. Las decisiones de diseño de cada versión están en
[docs/adr/](docs/adr/README.md); las versiones anteriores a 1.4.6, en la sección «Fases» de [docs/SPEC.md](docs/SPEC.md).

## 1.4.6 — 2026-10-14

Analizador 1.13.0 · [ADR 033](docs/adr/033-atribucion-cdn-sincronizacion-alias-y-cookies.md). Los scans guardados se
actualizan sin volver a navegar con `./scripts/reanalyze.sh`.

### Cambiado
- **Librerías en CDN público:** los recursos de jsDelivr, cdnjs y unpkg se atribuyen a la librería leída de la ruta
  («librería bootstrap en CDN público (jsDelivr)»), no a la empresa del CDN (p. ej. Prospect One). Si la ruta no lo
  permite: «librería en CDN público (<cdn>)». Las que figuran en `data/benign_libraries.yaml` se marcan como librería
  conocida.
- **Sincronización de identificadores** (grupo 5) solo cuando el mismo identificador llega a 2 o más organizaciones
  distintas del sitio; el propio sitio ya no cuenta como segunda organización. Con una sola organización, el hallazgo
  pasa al grupo 1: «Identificador persistente enviado a <org>».
- **Índice de exposición:** las cookies funcionales no suman (`stored_items` = cookies no funcionales + storage).

### Agregado
- `data/org_aliases.yaml`: alias de organización (dominios del mismo dueño). Primero: Municipalidad de La Serena
  (laserena.cl, munilaserena.cl).
- `data/cookie_purposes.yaml`: propósito de cada cookie por su nombre conocido (funcional, analítica, publicidad), también
  las del propio dominio, como Inferencia. Panel «Cookies por propósito» en Resumen y hallazgos en Hallazgos.
- UserWay en el catálogo de organizaciones, con el tipo de servicio «widget de accesibilidad».
- Glosario: «Librería en CDN público», «Propósito de una cookie», «Alias de organización».
