# Reportes de ejemplo

Scans del 2026-10-07 (analizador 1.2.0), exportados de nuevo en F9 con el schema
`report-1.3.0`, perfil de licencias no comercial y **enmascarados** (opción por defecto,
que desde F9 cubre también los segmentos de ruta con forma de identificador). Cada sitio trae el PDF, el HTML autocontenido y el JSON del que salen
ambos. El sha256 impreso en cada documento es el de su JSON:

```sh
sha256sum docs/samples/*.json
```

| Sitio | sha256 del JSON |
|---|---|
| `biobiochile` — https://www.biobiochile.cl | `6a58192b84bed17ffe594cc1bba44248248aab76833479f25e42179d5dedb967` |
| `aliexpress` — https://es.aliexpress.com | `22793b736aff86c8865967739662cc38580201daaf0721f885a01ee5439a89e1` |

Son una sola visita automatizada de cada sitio, desde la red del analizador y sin
interacción. No son una evaluación de esos sitios.

**Captura parcial de biobiochile.** Durante ese scan el DNS upstream del proxy
falló unos segundos: 108 de las 223 requests no llegaron a salir (sobre todo
imágenes y librerías de subdominios del propio sitio). El reporte las cuenta como
bloqueadas y deja 5 dominios sin IP, con su motivo. Sirve como ejemplo del formato,
no como medición completa del sitio.
