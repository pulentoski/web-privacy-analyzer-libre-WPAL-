# Lista de CMP de IAB Europe (data/iab/cmp-list.json)

La descarga `scripts/update-cmp-list.sh`; fecha, URL y sha256 en `MANIFEST.json`.

| Archivo | Fuente | Licencia |
|---|---|---|
| `cmp-list.json` | IAB Europe — https://cmplist.consensu.org/v2/cmp-list.json (la que publica https://iabeurope.eu/cmp-list/) | **Sin licencia explícita** |

Verificado el 2026-10-06:

- El archivo JSON no trae ningún aviso de licencia.
- La página https://iabeurope.eu/cmp-list/ solo dice "© IAB Europe. All Rights
  Reserved" y enlaza a unos términos de uso generales.
- Las *especificaciones técnicas* del TCF sí tienen licencia (Creative Commons
  Attribution 3.0, según el repositorio de IAB Tech Lab), pero esa licencia habla
  de las especificaciones, no de este registro.

Qué se usa: únicamente el par **identificador → nombre** de cada CMP, para poder
decir "cmpId 28 = OneTrust LLC". Es un dato factual de un registro público que el
propio estándar obliga a consultar. Aun así, **para un uso comercial conviene
confirmarlo con IAB Europe**. Si el archivo se elimina, el analizador sigue
funcionando y muestra solo el número (`CMP 28`).

Atribución: "CMP list: IAB Europe Transparency & Consent Framework".
