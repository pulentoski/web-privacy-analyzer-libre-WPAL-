# ADR 025 — Importar, exportar y comparar HAR; terceros del resumen por organización (v1.3)

Estado: aceptada · Fecha: 2026-10-10

## Contexto
- El resumen ejecutivo (HTML/PDF) seguía diciendo «195 se dirigieron a terceros» en AliExpress: la
  cifra `capture.third_party`, la columna «Tipo» de destinos y «De terceros» por país salían de
  `scan_requests.third_party` (otro dominio), no de `request_analysis.party` (otra organización).
- El scan lo hace un Chromium automatizado, sin sesión. El navegador real del usuario puede recibir
  otro tráfico (olas de sincronización de socios publicitarios, bloqueos de su extensión).

## Decisiones
1. **Una sola fuente para «terceros».** Todas las cifras salen de `request_analysis.party =
   'third_party'`; sin análisis (o anterior a v1.2.1) se cae al criterio por dominio. Se añaden
   `capture.same_org`, `capture.blocked_by_client` y `destinations.domains[].party`
   (schema `report-1.5.0`). El resumen ejecutivo informa aparte las requests a la misma organización.
2. **Importar HAR en dos pasos sin estado.** `POST /api/har/inspect` (no guarda nada) lista las
   cargas y lo sensible; `POST /api/har/import?load=` guarda la carga elegida. El archivo viaja como
   cuerpo crudo (sin dependencia de multipart), máximo 50 MB (`HAR_MAX_BYTES` en la api y
   `client_max_body_size 50m` solo en `/api/har/`); el original nunca se conserva.
3. **La api valida y depura; el worker convierte.** La api no tiene la PSL ni el analizador. Deja
   las entradas normalizadas en `har_imports` (staging) y el worker las convierte al formato del
   monitor de red (`worker/app/har_capture.py`) y sigue el camino normal: mismas tablas, mismo
   analizador, mismo reporte. El worker borra el staging al cerrar el job. No hay navegación.
4. **Datos sensibles.** Cookie, Set-Cookie, Authorization y Proxy-Authorization: se advierte y
   se descarta el valor antes de guardar; queda `{name, value: "", redacted, length}`. Los arreglos
   `cookies` y los cuerpos de respuesta no se guardan. Todo lo demás es texto acotado.
5. **Cargas.** Una por `pageref`; las entradas sin `pageref` se suman a la página en cuya ventana
   de tiempo caen y el resto se agrupa por silencios de 30 s. Por defecto, la que tiene documento y
   más requests; el usuario puede elegir otra.
6. **Lo que un HAR no trae se declara.** Sin instrumentación de fingerprinting
   (`fingerprinting.instrumented = false`), sin snapshot de cookies/storage, sin frames de
   WebSocket. La alerta de «navegador automatizado» no aplica. La IP del destino es la que
   registró el navegador (`serverIPAddress`).
7. **`net::ERR_BLOCKED_BY_CLIENT`** = «bloqueadas por una extensión del navegador», conteo aparte
   (`capture.blocked_by_client`); no son bloqueos del proxy.
8. **Fuga de búsqueda** (`search_leak`, EVIDENCIA): parámetro `q`, `query`, `keywords`, `search` o
   `k` con texto (no identificador, número ni URL) enviado a un host distinto del de la página.
   Reglas en `data/har_signals.yaml`; incluye reglas contextuales por proveedor (aplus de Alibaba:
   `exp_type=search_door` → `exp_page_area`), porque esa telemetría no usa los nombres habituales.
   El hallazgo dice a quién se envió (tercero, misma organización u otro host del propio sitio) y
   no afirma quién escribió el término.
9. **Ola de sincronización** (`sync_wave`, EVIDENCIA): la mayor ráfaga de requests cuyo host o ruta
   contiene `sync`/`cookiematch`/`usermatch` hacia ≥ 3 organizaciones con ≤ 3 s entre requests.
   «Iniciada por» = host de la primera request de la ráfaga (los píxeles suelen salir sin Referer ni
   stack, así que no se atribuye por iniciador). Vale para scans y para HAR.
10. **Comparar** (`GET /api/scans/{id}/compare/{otro}`): exige un scan y un HAR importado.
    Organizaciones de terceros solo en uno u otro, estado de la ola, bloqueos por extensión y una
    conclusión de una línea por plantilla. La diferencia se observó; su causa no queda demostrada.
11. **Exportar** (`GET /api/scans/{id}/har`): HAR 1.2 sin Cookie, Set-Cookie ni Authorization por
    defecto (`include_sensitive=true` es explícito); se puede volver a importar.
12. El decodificador de query acepta espacios en los valores cuando hay varios pares (un query ya
    URL-decodificado), sin cambiar el orden de los decodificadores. Analizador 1.7.0.

## Consecuencias
- Los scans anteriores necesitan reanálisis (`scripts/reanalyze.sh`) para tener `sync_wave`; hasta
  entonces la comparación dice «medición no disponible», no «sin ola».
- Un HAR es lo que el usuario capturó: puede estar editado. Se analiza como dato no confiable.
