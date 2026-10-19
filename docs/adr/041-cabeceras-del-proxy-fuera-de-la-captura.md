# ADR 041 — Proxy-Authorization y Proxy-Connection fuera de la captura

Estado: aceptada · Versión: 1.5.3 · Analizador 1.18.0 (sin cambios) · Schema de reporte 1.11.0 (sin cambios)

## Contexto

Chromium sale a internet por el egress-proxy autenticándose con un usuario por scan (`scan-<id>`) y `PROXY_SCAN_SECRET`
(ADR del proxy, `launcher.launch_kwargs`). En las requests `http://` el navegador manda la petición al proxy en claro, con
`Proxy-Authorization: Basic base64(scan-<id>:<secreto>)` y `Proxy-Connection`. Playwright entrega esas cabeceras junto con
las del sitio y la captura las guardaba en `scan_requests.request_headers`. De ahí llegaban al detalle de request (con
«Mostrar identificadores completos») y al HAR exportado con `include_sensitive=true`. El secreto del proxy quedaba en la
base y podía salir en un archivo que se comparte. Se detectó en la v1.5.2. En los scans reales guardados no había ningún
caso (todos https), pero cualquier sitio http lo producía.

## Decisión

- **No se guardan.** `network_monitor.clean_headers` descarta `proxy-authorization` y `proxy-connection`, sin importar
  mayúsculas, en las cabeceras de request y de respuesta. No son del sitio analizado sino del salto al proxy, así que no
  son evidencia de nada. El HAR importado tampoco las guarda; `Proxy-Authorization` sigue contando como credencial
  descartada en el aviso del import.
- **Se limpian las guardadas.** La migración 0017 las quita de `scan_requests` (request y respuesta) y del staging de HAR
  importados, conservando el resto de las cabeceras y su orden. Es irreversible a propósito: el downgrade no las restaura.
- **Defensa en la salida.** La api las filtra igual (`app/proxy_headers.py`) en el detalle de request (enmascarado y
  completo), en el HAR exportado (nunca, ni con `include_sensitive=true`) y en la comparación de visitas. El JSON, el
  HTML y el PDF del reporte no llevan cabeceras.
- **Pruebas con el secreto real.** `worker/tests/v153` hace un scan del sitio de fixtures (http) con el worker real y
  busca en todas las salidas de la api la cabecera, el secreto y el usuario del proxy, en claro y en base64. Es el único
  contenedor de test que tiene el secreto; el e2e no lo recibe y busca en la vista y en el texto del PDF la cabecera, el
  usuario y el prefijo en base64 del usuario, que no depende del secreto.

## Consecuencias

- El analizador no leía esas cabeceras: puntaje, clasificación y hallazgos no cambian. Lo verifica la regresión, y las
  huellas de los scans reales no cambian (no tenían esas cabeceras).
- Una instalación que haya escaneado sitios http antes de 1.5.3 sigue teniendo el secreto en los HAR o reportes que ya
  descargó. Se recomienda rotar `PROXY_SCAN_SECRET` (`./scripts/rotate-secrets.sh`).
- Los respaldos anteriores a la migración (`backups/`) conservan las cabeceras hasta que se borren.
