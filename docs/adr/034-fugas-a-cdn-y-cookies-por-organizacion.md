# ADR 034 — Fugas hacia un CDN público y propósito de cookies por la organización (v1.4.7)

Estado: aceptada · Fecha: 2026-10-15 · Amplía [ADR 033](033-atribucion-cdn-sincronizacion-alias-y-cookies.md)

## Contexto
- Tras la v1.4.6 se verificó si la fuga por Referer de laserena.cl hacia cdnjs (Cloudflare) se había perdido al
  atribuir los recursos a la librería. No se perdió: el hallazgo `referer_leak` y el componente
  `url_leak_recipients` del índice siguen, porque `party` sale del dominio. Pero la frase decía que la URL «se
  transmitió a librería bootstrap-icons en CDN público (cdnjs)»: la api nombra al receptor con la entidad de alguna
  request del dominio, y esa entidad ahora es una librería. Quien recibe la request (y su Referer) es el servidor del
  CDN, no el autor de la librería.
- En aliexpress, 74 de 79 cookies quedaban «sin clasificar»: nombres propios de Alibaba y de adtech común que no
  estaban en `cookie_purposes.yaml`, y cookies de dominios cuyo giro ya se conoce (Criteo, PubMatic…).

## Decisiones
1. **La librería cambia la atribución del recurso, no el receptor de sus fugas.** El analizador guarda el receptor en
   `details.recipient` de `url_leak` y `referer_leak` y en `reasons[].data.recipient` de la request: «CDN público
   <cdn> (<dueño del dominio>)» si todas las requests del grupo fueron al mismo CDN público; si el grupo mezcla hosts,
   la organización dueña del dominio (p. ej. «Cloudflare»). Nunca una librería. La api usa `recipient` antes que su
   mapa dominio → entidad; los análisis anteriores (sin `recipient`) se nombran como antes.
2. **Cookies en dos pasos**, ambos INFERENCIA y con su base (`basis`):
   (a) nombre conocido (`purposes`); (b) si no, el tipo de servicio de la organización dueña del dominio de la cookie
   (`by_service_type`): publicidad (advertising, mobile_advertising, conversion_pixel, dmp, data_broker), analítica
   (analytics, audience_measurement, session_recording) y funcional (cdn, library_cdn, antifraud). Sin nombre ni tipo,
   «sin clasificar» (basis = null). El paso (b) no se aplica a la organización del sitio salvo que tenga tipo: una
   cookie del propio dominio la puede haber creado un script de terceros y eso no se observa.
3. Las frases dicen la base («inferencia por el nombre» / «por la organización»); el Resumen informa cuántas cookies se
   clasificaron de cada forma (`cookie_purposes.by_basis`). Las funcionales por la organización tampoco suman al índice.
4. **Nombres nuevos**: Alibaba/AliExpress funcionales (aep_usuc_f, intl_locale, xman_us_f, _m_h5_tk; JSESSIONID ya
   estaba), de seguridad contadas como funcionales (isg, tfstk, l) y de analítica (cna, ali_apache_id); adtech
   (cto_bundle, MUID, _uetsid, _uetvid, tuuid, A3; IDE y _ttp ya estaban).

## Consecuencias
- Analizador 1.14.0; `reanalyze.sh --all` actualiza los scans guardados.
- `l` y `cna` son nombres cortos y genéricos: en otro sitio podrían no ser de Alibaba. Se aceptan porque la regla es
  inferencia y se dice; si aparecen falsos positivos, se quitan del YAML.
- Clasificar por la organización puede errar cuando una organización tiene varios giros (Google: antibot, mapas,
  publicidad): se usa el giro de la organización o del dominio de la cookie, no el de cada producto.
