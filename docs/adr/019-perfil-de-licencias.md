# ADR 019 — Perfil de licencias: modo comercial y no comercial

Estado: aceptado · Fase: F9 · Complementa: ADR 005

## Contexto
Dos fuentes de datos impiden usar el proyecto con fines comerciales tal como estaba:

| Fuente | Para qué | Licencia | Problema |
|---|---|---|---|
| DuckDuckGo Tracker Radar (`data/lists/entity_map.json`) | dominio → organización | CC BY-NC-SA 4.0 | No comercial |
| Lista de CMP de IAB Europe (`data/iab/cmp-list.json`) | `cmpId` → nombre | Sin licencia explícita | No hay permiso que citar |

El resto sí admite uso comercial con atribución: EasyList y EasyPrivacy (GPL-3.0+ o
CC BY-SA 3.0) y DB-IP Lite (CC BY 4.0).

## Decisión
`LICENSE_PROFILE` en `.env`, leído por el worker al arrancar:

- **`no_comercial`** (por defecto): el comportamiento de F3–F8, sin cambios.
- **`comercial`**:
  - toda fuente marcada `noncommercial: true` en `data/lists/MANIFEST.json` **no se abre**
    (queda en `excluded` y en el log `analyzer_resources_loaded`);
  - el mapa de organizaciones sale de **AdGuard companiesdb**
    (`data/lists/companiesdb/`, `scripts/update-companiesdb.sh`), CC BY-SA 4.0,
    verificada en su archivo `LICENSE` el 2026-10-07. Es una base derivada de
    whotracks.me con correcciones de AdGuard;
  - la lista de CMP de IAB **no se abre**: el reporte muestra `CMP 28` en vez del
    nombre, y `versions.cmp_list` dice `excluida (perfil comercial)`.

El perfil queda **guardado con cada análisis** (`summary.license_profile`) y el reporte
lo imprime (campo `license_profile`, schema `report-1.3.0`, encabezado y tabla de
versiones del HTML/PDF). Las atribuciones del reporte son las de las fuentes realmente
usadas. Un valor desconocido de `LICENSE_PROFILE` impide arrancar el worker.

Cambiar de perfil no reescribe scans existentes: hay que re-analizarlos
(`POST /api/scans/{id}/reanalyze`). Un análisis hecho en modo no comercial sigue
marcado así y sus datos derivados heredan la condición NC.

## Pérdida de cobertura medida
`scripts/license-coverage.sh` (2026-10-07), sobre los dominios de terceros de las
muestras y del sitio de fixtures:

| Conjunto | Dominios de terceros | Con organización: no comercial | Con organización: comercial | Pierden | Ganan |
|---|---|---|---|---|---|
| muestra aliexpress | 50 | 44 (88 %) | 39 (78 %) | 5 | 0 |
| muestra biobiochile | 15 | 11 (73 %) | 9 (60 %) | 3 | 1 |
| fixtures | 2 | 0 (0 %) | 0 (0 %) | 0 | 0 |

Pierden organización: `alibaba-inc.com`, `aliexpress-media.com`, `appier.net`,
`clmbtech.com`, `opera.com`, `clarity.ms`, `mrf.io`, `rudo.video`. En modo comercial
esos dominios aparecen como `no_disponible` y **no se agrupan** con otros de la misma
empresa, así que el conteo de organizaciones del resumen puede subir o bajar. Los
dominios del sitio de fixtures no están en ningún mapa: ahí no hay pérdida que medir.

Lo que **no** cambia entre perfiles: qué requests se consideran de seguimiento (listas
de filtros y heurísticas), los scores y los hallazgos. Solo cambia el nombre de la
organización y el de la CMP.

## Consecuencias y límites
- La medición es de dos sitios: orienta, no generaliza.
- CC BY-SA 4.0 exige atribución y compartir igual los datos derivados: el mapa
  generado se distribuye con su `MANIFEST.json` y la atribución va en cada reporte.
- El nombre que da companiesdb puede diferir del de Tracker Radar para la misma empresa.
- Este ADR no es asesoría legal: antes de un uso comercial, revisar las licencias.

## Verificación
`worker/tests/f9/test_license_profile.py` (en modo comercial no se lee ni
`entity_map.json` ni nada de `data/iab/`, comprobado sobre las lecturas de archivo) y
`api/tests/test_hardening_api.py` (perfil y atribuciones en el reporte).
