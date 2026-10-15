# Cambios

Formato: una sección por versión, la más reciente arriba. Las decisiones de diseño de cada versión están en
[docs/adr/](docs/adr/README.md); las versiones anteriores a 1.4.6, en la sección «Fases» de [docs/SPEC.md](docs/SPEC.md).

## 1.4.7 — 2026-10-15

Analizador 1.14.0 · [ADR 034](docs/adr/034-fugas-a-cdn-y-cookies-por-organizacion.md). Actualizar los scans guardados con
`./scripts/reanalyze.sh --all`.

### Corregido
- Fugas hacia un CDN público: se verificó que la fuga por Referer de laserena.cl hacia cdnjs seguía informada y
  contando en el índice, pero su frase nombraba a la librería como receptora. Ahora las fugas (URL y Referer) nombran
  al CDN que recibió la request («CDN público cdnjs (Cloudflare)»), nunca a la librería.

### Cambiado
- Propósito de cookies en dos pasos: por el nombre conocido y, si no está, por el tipo de servicio de la organización
  que la creó (adtech/publicidad → publicidad; analítica → analítica; CDN/antibot → funcional). Siempre Inferencia, con
  su base; el Resumen indica cuántas se clasificaron de cada forma.

### Agregado
- Nombres de cookies de Alibaba/AliExpress (aep_usuc_f, intl_locale, xman_us_f, _m_h5_tk, isg, tfstk, l, cna,
  ali_apache_id) y de adtech común (cto_bundle, MUID, _uetsid, _uetvid, tuuid, A3).
- `docker-compose.release.yml` y `scripts/release-images.sh` en la versión 1.4.7 (sin publicar imágenes); ahora también
  en el repo privado, para que la sincronización privado → libre no los desactualice.

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
