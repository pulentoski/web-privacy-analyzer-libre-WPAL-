# Licencias de los datos en data/lists/

Los archivos descargados los genera `scripts/update-lists.sh`; su fecha, URL de
origen y sha256 están en `MANIFEST.json`. No se editan a mano.

| Archivo | Fuente | Licencia | ¿Uso comercial? |
|---|---|---|---|
| `easylist.txt` | EasyList — https://easylist.to/ | Doble licencia: GPL-3.0-or-later **o** CC BY-SA 3.0 (https://easylist.to/pages/licence.html) | Sí, respetando atribución y share-alike de la licencia elegida |
| `easyprivacy.txt` | EasyPrivacy — https://easylist.to/ | Doble licencia: GPL-3.0-or-later **o** CC BY-SA 3.0 | Sí, en los mismos términos |
| `entity_map.json` | DuckDuckGo Tracker Radar — https://github.com/duckduckgo/tracker-radar (`build-data/generated/entity_map.json`) | **CC BY-NC-SA 4.0** — Copyright 2020 Duck Duck Go, Inc. | **NO. ⚠ NO COMERCIAL (NC).** |
| `test-fixtures.txt` | Propio de este proyecto | La del proyecto | Sí |

## ⚠ Fuente no comercial: `entity_map.json`

Tracker Radar se distribuye bajo **Creative Commons
Attribution-NonCommercial-ShareAlike 4.0**. Mientras ese archivo esté en uso:

- este proyecto **no puede usarse con fines comerciales**, salvo que se obtenga una
  licencia comercial de DuckDuckGo o se reemplace la fuente;
- los datos derivados de él (el campo `entity` de cada request y la agrupación de
  `/trackers`) heredan la condición share-alike;
- hay que mantener la atribución: *"Entity data from DuckDuckGo Tracker Radar,
  CC BY-NC-SA 4.0"*.

La fuente es reemplazable sin tocar código: ver
[docs/adr/005-licencias-de-listas.md](../../docs/adr/005-licencias-de-listas.md).
Si se elimina el archivo, el analizador sigue funcionando y la entidad de cada
dominio queda como `no_disponible`.

## Atribución

- EasyList y EasyPrivacy: © The EasyList authors (https://easylist.to/).
- Tracker Radar: © Duck Duck Go, Inc., CC BY-NC-SA 4.0.

## Otros datos del proyecto (no son de terceros)

`data/param_names.yaml`, `data/scoring.yaml` y `data/domain_categories.yaml` son
propios de este proyecto, escritos a mano.

Las bases de IP (DB-IP Lite) tienen su propio archivo: `data/ipdb/LICENSES.md`.

## Perfil comercial: `companiesdb/entity_map.json`

Con `LICENSE_PROFILE=comercial` (docs/adr/019) **no se abre** `entity_map.json` de
Tracker Radar. El mapa dominio → organización sale de:

| Archivo | Fuente | Licencia | ¿Uso comercial? |
|---|---|---|---|
| `companiesdb/entity_map.json` | AdGuard companiesdb — https://github.com/AdguardTeam/companiesdb (`dist/trackers.json` y `dist/companies.json`), basada en whotracks.me | **CC BY-SA 4.0** (archivo `LICENSE` del repositorio, verificado el 2026-10-07) | Sí, con atribución y compartiendo igual los datos derivados |

Lo genera `scripts/update-companiesdb.sh`; fecha, versión y sha256 (del mapa y de los
dos archivos de origen) en `companiesdb/MANIFEST.json`.

Atribución: *"Company data from AdGuard companiesdb (based on whotracks.me), CC BY-SA 4.0"*.
