# ADR 004 — Motor de reglas Adblock

Estado: aceptado · Fase: F3

## Contexto
El analizador necesita saber si una request coincide con EasyList/EasyPrivacy,
respetando las opciones de la sintaxis Adblock (`$third-party`, `$domain=`,
`$ping`, `$image`) y las excepciones (`@@`). Son ~137 000 reglas y un scan puede
tener 1500 requests. Se evaluaron los paquetes de PyPI **antes de instalar nada**
en el proyecto (metadatos de la API JSON de PyPI y prueba funcional en un
contenedor desechable `python:3.12-slim`, 2026-10-06).

## Evidencia

| Paquete | Mantenedor / repo | Última versión | Python 3.12 | Resultado |
|---|---|---|---|---|
| `adblock` 0.6.0 | Árni Dagur — github.com/ArniDagur/python-adblock (bindings de `adblock-rust`, el motor de Brave). MIT/Apache-2.0. 19 releases desde 2020-03 | 2022-07-17 | Sí: wheel `cp37-abi3-manylinux` | **Elegido** |
| `braveblock` 0.5.1 | Gal Ben David (Intsights) — mismos bindings | 2024-02-14 | **No**: wheels solo cp37–cp311, sin sdist (`No matching distribution found`) | Descartado |
| `adblockparser` 0.7 | Mikhail Korobov (Scrapinghub) | 2016-10-17 | Sí (Python puro) | Descartado: sin mantenimiento desde 2016, regex en Python (lento con 137k reglas y expuesto a backtracking con URLs hostiles) |
| `python-abp` 0.2.0 | eyeo GmbH | 2020-05-20 | Solo sdist | Descartado: solo parsea listas, no evalúa requests; GPLv3 |
| `abp-blocklist-parser` 0.3 | Steven Englehardt | 2020-01-23 | Sí | Descartado: GPLv3, regex en Python, sin mantenimiento |

Prueba funcional de `adblock` 0.6.0 (11 casos, 11 correctos): `$third-party`
desde otro sitio y desde el mismo; `$domain=` que coincide y que no; `$ping` e
`$image` con el tipo correcto y con otro tipo; regla simple; excepción `@@`;
patrón de ruta. Con las listas reales: carga en 0,24 s y 20 000 consultas en
0,05 s. Devuelve el texto de la regla que coincidió (`debug=True`).

## Decisión
Usar `adblock==0.6.0`, fijado en `worker/requirements.txt`. Un motor por lista
(`app/analyzer/lists.py`) para poder decir qué lista y qué regla coincidió.

- `third_party` se pasa explícito (`check_network_urls_with_hostnames`): es el que
  calculó la captura por dominio registrable, no el que deduciría el motor. Así
  listas y análisis usan la misma definición (y funciona con `fixtures.test`).
- La navegación principal no se consulta contra las listas.
- Los motores no se pueden usar desde otro hilo que el que los creó: todo el
  análisis corre en un único hilo dedicado (`app/analysis.py`).

## Consecuencias y limitaciones
- **Sin releases desde 2022**: el `adblock-rust` empaquetado es antiguo. Las
  opciones de filtro más nuevas que no entiende se ignoran (regla descartada), así
  que puede haber *menos* coincidencias que en un bloqueador actual, nunca más.
  Revisar al subir de versión de Python (depende del wheel abi3).
- El motor agrupa reglas equivalentes: el texto reportado puede ser varias reglas
  unidas por `<+>`. Se guarda acotado a 300 caracteres.
- Reemplazable: toda la dependencia está detrás de `FilterLists.match()`.
