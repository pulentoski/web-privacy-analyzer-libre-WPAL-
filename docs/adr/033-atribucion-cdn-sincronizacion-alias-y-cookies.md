# ADR 033 — Librerías en CDN público, sincronización entre organizaciones, alias de organización y propósito de cookies (v1.4.6)

Estado: aceptada · Fecha: 2026-10-14

## Contexto
Los scans reales de laserena.cl, userena.cl y es.aliexpress.com mostraron cinco imprecisiones:

- Los scripts y hojas de estilo de jsDelivr se atribuían a «Prospect One», la empresa dueña del CDN, y los de cdnjs a
  Cloudflare. Quien escribió el código es la librería (bootstrap, leaflet…); el CDN solo lo distribuye.
- UserWay (`cdn.userway.org`, `api.userway.org`) quedaba como «organización no disponible» y sin tipo de servicio.
- userena.cl envía a UserWay el valor de su ítem `uw-uid` y eso aparecía en el grupo 5, «Sincronización de
  identificadores», aunque una sola organización lo recibió. Además, un valor enviado al propio sitio y a UN tercero
  contaba como sincronización entre dos organizaciones: el sitio contaba como la segunda.
- laserena.cl llama a `apis.munilaserena.cl`, de la misma municipalidad, y se informaba como tercero de dueño desconocido.
- Las cookies se contaban todas igual en el índice: una cookie de sesión o de antibot pesaba lo mismo que `_fbp`.

## Decisiones
1. **Librería, no la empresa del CDN.** `organizations.yaml §public_cdns` declara los hosts de jsDelivr, cdnjs y unpkg y
   los prefijos de ruta tras los que viene el nombre del paquete (`/npm/`, `/gh/` con dos tramos, `/ajax/libs/`, `/`).
   La organización mostrada de la request (`request_analysis.entity`) pasa a ser «librería <paquete> en CDN público
   (<cdn>)»; si la ruta no permite leerlo (`/combine/`, caracteres fuera de un nombre de paquete), «librería en CDN
   público (<cdn>)». El nombre viene de la URL (dato no confiable): se acepta solo con forma de nombre de paquete y
   acotado. La clasificación `party` sigue saliendo del dominio (el CDN sigue siendo un tercero): solo cambia a quién se
   atribuye el recurso. En «Servicios de terceros» las librerías de un CDN cuentan como UNA organización, para que el
   conteo no crezca por partir un CDN en varias filas.
2. **Librerías conocidas.** La ruta se compara con `benign_libraries.yaml` (la misma regla que ya evitaba marcar como
   fingerprinting la lectura de canvas de una librería de gráficos): coincidencia = `library.benign` con su etiqueta. Es
   contexto, no cambia puntajes.
3. **UserWay** entra al catálogo propio por sufijo (`userway.org`) y como tipo de servicio «widget de accesibilidad».
4. **Sincronización = 2 o más organizaciones distintas del sitio.** Los dueños del sitio (sus dominios propios y los de
   su misma organización) no cuentan. Con exactamente una organización externa:
   - si el valor coincide con una cookie o storage, el hallazgo es `persistent_id_org` (grupo 1, «Identificadores
     persistentes»): «Identificador persistente enviado a <org>», EVIDENCIA;
   - si el valor viajó al propio sitio y a una sola organización (antes contaba como sincronización), también
     `persistent_id_org`, con el dato de que llegó al sitio.
   Un valor que llegó a dos dominios de la MISMA organización externa sigue sin informarse, como antes: no hay evidencia
   de persistencia ni de sincronización. `persistent_id` (grupo 5) queda para los valores guardados que además llegaron a
   2 o más organizaciones. El componente `persistent_id_recipients` del índice no cambia; `id_sync` cuenta solo
   valores que llegaron a 2 o más organizaciones externas.
5. **Alias de organización** en un archivo propio, `data/org_aliases.yaml` (organización → dominios), genérico: cualquier
   dueño con varios dominios registrables que el mapa de entidades no agrupa. Gana sobre el catálogo y el mapa; entra en
   `lists_version`. Primer alias: Municipalidad de La Serena (laserena.cl, munilaserena.cl). Solo se agregan dueños
   verificables; un alias equivocado ocultaría un tercero, por eso no se infiere de nombres parecidos.
6. **Propósito de cookies por su nombre** (`data/cookie_purposes.yaml`): funcional, analítica, publicidad; lo demás
   «sin clasificar» (no se inventa un propósito). Reglas exactas o con `*`, evaluadas publicidad → analítica → funcional.
   Las reglas funcionales son estrechas (`session`, `PHPSESSID`, `laravel_session`, `ci_session`; ni `*session*` ni
   `*_session`) para no clasificar como funcional una cookie de publicidad: el reanálisis de aliexpress mostró
   `appier_session` (Appier) y `taboola_session_id` (Taboola). Se aplica a todas las cookies del snapshot, también las del propio dominio. Es INFERENCIA:
   `cookie_purpose` (analítica y publicidad, grupo 1) y `cookie_purpose_functional` (solo lista técnica, porque no
   describe un método de seguimiento); conteo en `site.summary.cookie_purposes` (panel «Cookies por propósito» del
   Resumen) y en `persistent_cookie.details.purposes`.
7. **Las cookies funcionales no suman al índice**: `stored_items` = cookies no funcionales + storage. Una cookie
   «sin clasificar» sigue sumando, como antes.

## Consecuencias
- Analizador 1.13.0. Los scans guardados se actualizan con `scripts/reanalyze.sh`. El reporte sigue en `report-1.7.0`
  (el `summary` es un objeto abierto); un análisis anterior no muestra «Cookies por propósito» (no se inventa «0»).
- En el Panel, una librería en CDN público aparece como su propia fila («librería bootstrap en CDN público
  (jsDelivr)») en lugar de agregarse bajo la empresa del CDN.
- El propósito por nombre falla con nombres propios de cada sitio (p. ej. el hash de sesión de Joomla): quedan «sin
  clasificar» y siguen sumando al índice. Se corrigen agregando reglas al YAML.
- `session_token_third_party` y `server_side_meta` siguen en el grupo 5: no son el mismo identificador recibido por
  varias organizaciones, pero tampoco un identificador guardado; moverlos queda fuera de esta versión.
