# ADR 018 — Reportes exportables: HTML autocontenido, PDF y sha256

Estado: aceptado · Fase: F8

## Decisiones
1. **Una exportación es una instantánea** (`api/app/routes/reports.py`, tabla
   `report_files`): el JSON del reporte, el HTML generado **a partir de ese JSON
   ya serializado** y un PDF del mismo HTML. Los tres comparten el `sha256` del
   JSON, que va impreso en el documento y en la cabecera `X-Report-Sha256`.
   Serialización canónica: claves ordenadas, sin espacios, UTF-8.
2. **Dos niveles en un documento** (`api/app/report_html.py`, funciones puras):
   resumen ejecutivo para quien dirige una pyme (lenguaje simple, trato de usted,
   qué se encontró, por qué importa, 3 a 5 recomendaciones) y anexo técnico
   (metodología, hallazgos con nivel y referencias, terceros por organización y
   país, fingerprinting, TCF y Consent Mode, limitaciones). Cada frase del
   resumen sale de un dato del reporte.
3. **Siempre presentes**: fecha, URL, versiones (analizador, listas, base IP),
   leyenda de niveles, atribuciones (DB-IP, CC BY 4.0) y el aviso "no constituye
   asesoría legal", al inicio y al final.
4. **Enmascarado por defecto** (`api/app/masking.py`): de cada valor de query o
   fragmento de 9 o más caracteres queda el prefijo de 4 y el largo. Mostrar los
   valores completos es una opción explícita (`reveal: true`), produce **otra**
   instantánea con otro sha256 y el documento lo advierte.
5. **PDF en el worker**, que ya tiene Chromium (`worker/app/render.py`): `page.pdf`
   con el navegador **sin proxy** (no tiene ruta a internet), contexto offline,
   JavaScript desactivado y toda request abortada y contada. El resultado guarda
   `network_requests_attempted`, que debe ser 0. El PDF solo se acepta si su
   `sha256` sigue siendo el de la instantánea vigente.
6. **El HTML no confía en su contenido**: todo dato capturado se escapa; no hay
   scripts, enlaces ni recursos externos; lleva una CSP `default-src 'none'`
   dentro del archivo y se sirve como adjunto con `sandbox`.
7. **Marca opcional**: nombre por `REPORT_BRAND_NAME` o `nombre.txt`; logo
   `logo.png`/`logo.jpg` (máx. 300 KB, validado por firma; no SVG) en un
   directorio del host **fuera del repo** (`REPORT_BRAND_DIR`). Sin marca, el
   encabezado es neutro.
8. **Grupos de Privacy Test**: mismo mecanismo, con su propio schema
   (`group-report-1.0.0`). El reporte de un scan usa `report-1.2.0`; los schemas
   anteriores se conservan.

## Límites
- Exportar de nuevo reemplaza la instantánea anterior del mismo tipo.
- `report_files` no se borra en cascada con el scan.
- La ruta de una URL no se enmascara: un identificador puesto en la ruta queda
  visible.

## Verificación
`api/tests/test_reports_api.py` (enmascarado, sha256, marca, escape),
`worker/tests/f8/test_render.py` (0 requests de red) y
`e2e/tests/test_reports.py` (botones y texto del PDF con pypdf).
