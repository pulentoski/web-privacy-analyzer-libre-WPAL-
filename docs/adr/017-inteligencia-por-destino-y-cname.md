# ADR 017 — Inteligencia por destino y CNAME cloaking

Estado: aceptado · Fase: F8

## Decisiones
1. **Dos fuentes que no se arbitran** (`api/app/destinations.py`):
   - dueño del **dominio**: mapa de entidades de F3;
   - red y país de la **IP** observada por el proxy (ADR 016): DB-IP Lite, offline.
   Un dominio de una empresa servido desde la nube de otra es normal. Si no
   coinciden se muestran ambas (`sources_differ`) y no se elige una.
2. **País = "ubicación aproximada del servidor por IP".** Así se rotula siempre.
   No indica dónde se almacenan ni procesan los datos.
3. **Sin dato, con motivo.** Un dominio sin IP dice por qué (`ip_reason`): el
   proxy no completó la conexión, el scan es anterior al registro, o la request
   no salió. Una IP privada no se geolocaliza ("no aplica").
4. **CNAME cloaking**: un subdominio del propio sitio cuyo CNAME apunta a un
   tercero de medición o publicidad (`data/cname_trackers.yaml`, lista propia y
   corta). La cadena CNAME es EVIDENCIA; que haya seguimiento es INFERENCIA.

## El resolutor no es una vía de SSRF
`api/app/cname.py` es el único código de la api que consulta DNS con un nombre
tomado de un sitio analizado. Su superficie es mínima a propósito:
- solo acepta hostnames que **ya están en la captura** del scan (si no,
  `NotInCapture`); ningún endpoint recibe un hostname como entrada;
- solo subdominios first-party, con sintaxis estricta: nada de IPs ni nombres de
  una etiqueta (`db`, `localhost`);
- hace **una consulta de nombres** (`gethostbyname_ex`) y **ninguna conexión** al
  destino, así que no puede alcanzar servicios internos;
- timeout de 3 s, caché de 1 h, 30 hostnames por scan y 120 consultas por minuto
  en todo el proceso. El resultado se guarda en `scan_cnames`.

## Límites
- Solo detecta destinos de la lista; un CNAME hacia un tracker desconocido no se
  marca.
- El DNS se consulta desde la red de la api, al pedir el reporte, no en el momento
  del scan.

## Verificación
`api/tests/test_reports_api.py`: detección en el fixture
(`metrics.site.fixtures.test`), rechazo de hostnames ajenos a la captura, IPs y
nombres internos, timeout, caché, tope por scan y rate limit.
