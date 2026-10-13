# ADR 005 — Licencias de las listas y fuente NO COMERCIAL

Estado: aceptado · Fase: F3

## Contexto
El analizador usa datos de terceros, descargados por `scripts/update-lists.sh` y
versionados en `data/lists/` (fecha, URL y sha256 en `MANIFEST.json`; licencias en
`LICENSES.md`). El proyecto podría llegar a usarse comercialmente.

| Dato | Fuente | Licencia | Comercial |
|---|---|---|---|
| Reglas de publicidad | EasyList | GPL-3.0-or-later o CC BY-SA 3.0 | Sí (atribución + share-alike) |
| Reglas de tracking | EasyPrivacy | GPL-3.0-or-later o CC BY-SA 3.0 | Sí (ídem) |
| Dominio → organización | DuckDuckGo Tracker Radar (`entity_map.json`) | **CC BY-NC-SA 4.0** | **No** |

Las alternativas para el mapa de entidades están en la sección
"Licencias verificadas" más abajo.

> **Corrección (F4).** La primera versión de este ADR decía que WhoTracks.me era
> CC BY-NC-SA 4.0 y que no existía una fuente con licencia apta para uso comercial.
> Eso se escribió sin verificar y **era incorrecto**: ver la tabla.

## Decisión
1. Usar Tracker Radar (lo pide la SPEC) y **marcarlo como NO COMERCIAL** en
   `LICENSES.md`, en `MANIFEST.json` (`"noncommercial": true`) y en cada reporte
   (`analysis.lists[].noncommercial`), para que quien use un resultado sepa de qué
   datos depende.
2. Que la fuente sea **reemplazable sin tocar código**:
   - el mapa solo se usa para el campo `entity` y para agrupar `/trackers`; no
     influye en el `tracking_score` de ninguna request. Sí influye en un punto: la
     sincronización de identificadores exige dos organizaciones distintas, y sin
     mapa cada dominio cuenta como una organización propia;
   - `FilterLists` acepta dos formatos, declarados en `MANIFEST.json`:
     `ddg-entity-map` y `simple-entity-map` (`{"dominio": "Organización"}`). Para
     reemplazar la fuente basta con dejar un JSON en el formato simple, cambiar la
     entrada del manifest y reiniciar el worker;
   - si el archivo falta, el analizador funciona y la entidad queda como
     `"no_disponible"` (nunca se inventa).
3. `data/domain_categories.yaml`, `data/param_names.yaml` y `data/scoring.yaml`
   son propios del proyecto, sin restricciones.

## Consecuencias
- **Mientras `entity_map.json` esté en uso, el proyecto no puede explotarse
  comercialmente** sin licencia de DuckDuckGo. Antes de un uso comercial: obtener
  la licencia, o reemplazar el archivo por un mapa propio, o eliminarlo.
- El archivo está versionado en el repositorio: redistribuirlo obliga a mantener
  la atribución y la condición share-alike.
- EasyList/EasyPrivacy no se modifican; solo se leen.

## Licencias verificadas (F4, 2026-10-06)

Verificadas leyendo el archivo de licencia y el README de cada repositorio oficial
(y la página del proyecto cuando dice algo). No se cambió ninguna fuente.

| Fuente dominio→organización | Licencia verificada | Evidencia | ¿Uso comercial? |
|---|---|---|---|
| **DuckDuckGo Tracker Radar** (la que usa el proyecto) | CC BY-NC-SA 4.0 | [LICENSE](https://github.com/duckduckgo/tracker-radar/blob/main/LICENSE): "Licensed under the CC BY-NC-SA 4.0 license". [README](https://github.com/duckduckgo/tracker-radar#licensing): "If you'd like to license the list for commercial use, please reach out". | **No**, salvo licencia comercial de DuckDuckGo |
| **Disconnect Tracking Protection** | CC BY-NC-SA 4.0 | [LICENSE](https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE): "Licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0". [README](https://github.com/disconnectme/disconnect-tracking-protection): "Please email support@disconnect.me if you'd like to license the lists for commercial use". La página https://disconnect.me/trackerprotection no menciona la licencia. | **No**, salvo licencia de Disconnect |
| **Ghostery TrackerDB** | CC BY-NC-SA 4.0 | [LICENSE](https://github.com/ghostery/trackerdb/blob/main/LICENSE): "Licensed under the CC-BY-NC-SA-4.0 license". [README](https://github.com/ghostery/trackerdb#licensing): "free to use for non-commercial purposes. If you want to use it in your business, please contact sales@ghostery.com". | **No**, salvo licencia de Ghostery |
| **WhoTracks.me** (Ghostery) | Contenido: **CC BY 4.0**. Código: MIT | [README](https://github.com/whotracksme/whotracks.me#license): "The content of this project itself is licensed under the Creative Commons Attribution 4.0 license, and the underlying source code [...] under the MIT license". [LICENSE.md](https://github.com/whotracksme/whotracks.me/blob/master/LICENSE.md): MIT. La página https://www.ghostery.com/whotracksme no menciona la licencia. | **Sí, con atribución** — con la salvedad de abajo |
| **AdGuard companiesdb** | **CC BY-SA 4.0** | [LICENSE](https://github.com/AdguardTeam/companiesdb/blob/main/LICENSE): "Attribution-ShareAlike 4.0 International" (GitHub lo detecta como CC-BY-SA-4.0). [README](https://github.com/AdguardTeam/companiesdb): "It is basically the Whotracks.me database converted to a simple JSON format". Publica `dist/companies.json` y `dist/trackers.json`. | **Sí, con atribución y share-alike** sobre la base de datos derivada |
| Mozilla `shavar-prod-lists` | La de Disconnect | [README](https://github.com/mozilla-services/shavar-prod-lists): las listas son "maintained by Disconnect". No se verificó un archivo de licencia propio. | **No** (hereda la de Disconnect) |

No verificadas (no se encontró el repositorio o no se revisó): webXray, EFF
Privacy Badger (no publica un mapa dominio→organización reutilizable).

### Salvedad sobre WhoTracks.me y companiesdb
El README de WhoTracks.me licencia "el contenido de este proyecto" como CC BY 4.0,
pero Ghostery publica su base de trackers actual (TrackerDB) como CC BY-NC-SA 4.0.
No se verificó qué archivos de datos de WhoTracks.me provienen de TrackerDB ni si
eso limita la licencia declarada. Lo mismo aplica a companiesdb, que deriva de
WhoTracks.me. **Esto es una lectura de los textos de licencia, no asesoría legal.**

### Recomendación para uso comercial
1. Mientras el proyecto no sea comercial: seguir con Tracker Radar (cobertura
   mayor: ~19 000 entidades) y mantener el aviso de NO COMERCIAL.
2. Para un uso comercial, en orden de preferencia:
   a. **AdGuard companiesdb** (CC BY-SA 4.0): licencia clara en su propio archivo
      LICENSE, formato JSON simple, mantenido activamente. Obliga a atribuir y a
      publicar bajo la misma licencia la base derivada (no el código). Requiere un
      conversor a `simple-entity-map` (`{"dominio": "Organización"}`).
   b. Negociar una licencia comercial con DuckDuckGo, Ghostery o Disconnect.
   c. Mantener un mapa propio (solo las organizaciones que interesen).
3. Antes de cualquiera de las anteriores, **confirmar con asesoría legal** la
   salvedad sobre el origen de los datos de WhoTracks.me/companiesdb.
4. El cambio no requiere tocar código: dejar el JSON en `data/lists/`, declararlo
   en `MANIFEST.json` con `"format": "simple-entity-map"` y reiniciar el worker.
