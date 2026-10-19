# ADR 039 — Detalle de request enmascarado, marca y dueño, subdominios publicitarios y regla concreta

Estado: aceptada · Versión: 1.5.1 · Analizador 1.18.0 · Schema de reporte 1.11.0 (sin cambios)

## Contexto

1. Los reportes exportados enmascaraban los identificadores (ADR 018), pero el detalle de request de la interfaz mostraba
   todo completo: URL, parámetros, cookies, cabeceras y cadena de redirección.
2. Una request a px.ads.linkedin.com quedaba como «social» porque la categoría salía del dominio registrable (linkedin.com).
3. El mapa de entidades nombra al dueño («Microsoft»); quien lee espera ver la marca («LinkedIn»).
4. adblock-rust, con su motor optimizado, une reglas parecidas en un solo filtro y devuelve el bloque completo
   («/gtm.js <+> /gtm/gtm- <+> …») como «la regla que coincidió».

## Decisión

### Enmascarado en la api, no en el navegador
`GET /api/scans/{id}/requests/{rid}` enmascara por defecto; `?reveal=true` entrega los valores completos. Así el navegador no
recibe el valor completo mientras el interruptor está desactivado. Para las URLs se aplica la misma regla que en el reporte
(`mask_url`). Para los valores libres (cookies, cabeceras, decodificaciones y cuerpo) se usa `mask_identifiers`, que enmascara
las URLs citadas, los correos y cada tramo con forma de identificador (`looks_like_id`), y deja lo legible como está. Un
parámetro marcado `identifier_like` por el análisis se enmascara entero. La elección vale para una request: al pasar a otra
vuelve a enmascarado.

El HTML/PDF exportado no incorpora el detalle de request (decisión de la persona usuaria): solo lleva las URLs de las
requests de rastreo, que ya se enmascaraban, y un test verifica que el identificador del fixture no aparece.

### Marca solo como presentación
`data/brands.yaml` relaciona cada marca con su dueño y sus dominios. La organización (`entity`) sigue siendo el dueño: es la
que agrupa, decide «misma organización», resuelve el giro del servicio y cuenta en el índice. Por eso cambiar `entity`
podía alterar el análisis y se descartó. La api añade `brand` aparte, y solo si el dueño resuelto es exactamente el
declarado: con otro mapa u otro perfil de licencia no aparece una marca equivocada. El JSON del reporte no cambia; el
HTML/PDF calcula «Marca (Dueño)» al generarse.

### Categoría por etiqueta de subdominio
`data/host_categories.yaml`: si una etiqueta completa del host, a la izquierda del dominio registrable, es `ads`,
`adservice`, `adserver` o `adsystem`, la request se categoriza como Publicidad. Gana sobre `domain_categories.yaml` y la
lista, nunca se aplica al propio sitio y es INFERENCIA. La categoría se decide después del puntaje, así que score, banda e
índice no cambian. Cambia «Datos por categoría» (Publicidad).

### Regla concreta
Motor sin optimizar (`adblock.Engine(filter_set, optimize=False)`): devuelve la regla escrita en la lista. Las coincidencias
son las mismas. Medido con EasyPrivacy: unos 19 µs por consulta, frente a 6 µs con el motor optimizado; despreciable frente
a la captura. Si varias reglas coinciden se informa una de ellas.

### Título de la página y volcado con tráfico en curso (correcciones encontradas en la regresión)
- Mientras dura una navegación, `page.title()` devuelve el título provisional de la pestaña («Loading <URL>», texto de la
  interfaz de Chromium), aunque `document.title` ya tenga el real. Medido: 60 de 89 lecturas durante cinco navegaciones;
  en las mismas lecturas, `document.title` era el real. El título se lee de `document.title` (`page_title`), como ya se leían
  las metaetiquetas (`page_meta`). Es un dato del sitio y se sanea igual. Afectaba la captura interactiva detenida en ese
  momento y, en principio, los scans parciales. Se descartó esperar el evento `load`: un scan parcial perdería un título que
  el documento ya tiene. No se determinó qué navegación estaba en curso en la corrida que falló.
- El volcado previo al cierre de v1.5.0 recorría todas las requests después de esperar al navegador; una request llegada en
  ese intervalo no estaba construida (`KeyError: 'built'`) y la captura interactiva fallaba. Ahora trabaja sobre una copia
  fija, como antes de v1.5.0.

## Consecuencias

- Analizador 1.18.0. Los análisis anteriores muestran el bloque de reglas y la categoría anterior hasta reanalizar.
- La api del detalle de request cambia su valor por defecto (enmascarado). Los clientes que necesiten el valor completo
  piden `reveal=true`.
