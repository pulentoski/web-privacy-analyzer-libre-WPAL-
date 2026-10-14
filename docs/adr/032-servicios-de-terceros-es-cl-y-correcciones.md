# ADR 032 — Servicios de terceros sin señales de rastreo, perfil es-CL y correcciones de capturas reales (v1.4.5)

Estado: aceptada · Fecha: 2026-10-13

## Contexto
Dos scans reales (laserena.cl y municoquimbo.cl) mostraron huecos y errores:

- laserena.cl no tiene rastreadores y la pestaña Rastreadores quedaba vacía, aunque la página contacta a ocho
  organizaciones (antibot, mapas, clima, CDN de librerías).
- En la captura interactiva, dos descargas del decodificador draco desde gstatic.com tras un clic se informaron
  como «Su interacción se envió a gstatic.com».
- reCAPTCHA recibió `hl=en`: el navegador del worker se presentaba en inglés y en UTC.
- `maps.googleapis.com`, `fonts.googleapis.com` y `ajax.googleapis.com` quedaban sin organización, y
  `e-mailit.com` mostraba como dueño el nombre de la persona que registró el dominio.
- municoquimbo.cl envía datos a 5 IDs `G-` y 2 `UA-` de Google Analytics y eso no se decía en ningún lado.
- Un iframe que no carga muestra la página de error de Chromium (`chrome-error://chromewebdata/`), cuyo código
  pasa por la instrumentación como si fuera del sitio.

## Decisiones
1. **Servicios de terceros sin señales de rastreo.** El analizador agrupa las requests a otra organización que
   no alcanzan la banda de rastreador por (organización, tipo de servicio) y las guarda en
   `site.summary.third_party_services` con conteo y `evidence_refs`. La request es EVIDENCIA; el tipo de servicio
   es contexto (INFERENCIA), igual que el «giro» de v1.2.1. Sin dueño conocido cada dominio es su propia fila: dos
   dominios «no disponibles» no se tratan como la misma organización. El `summary` del reporte es un objeto
   abierto, así que el schema sigue en `report-1.7.0`.
2. **El tipo de servicio se decide por request**, no por organización: Google es mapas, fuentes, CDN de
   librerías y antibot según el host y la ruta. Se usan los patrones `urls` de `service_types.yaml`, que ya
   tenían prioridad. Para un GRUPO de URLs (el giro de una organización en Rastreadores) un patrón solo se
   aplica si lo cumple la mayoría: un `gen_204` de Maps no vuelve «mapas» a todo Google.
3. **Qué es un envío.** «Su interacción se envió a X» afirma una secuencia temporal; para que la afirmación
   valga, lo que sigue a la interacción debe ser un envío de datos. Cuentan los métodos con cuerpo, beacon,
   ping y cualquier GET con parámetros (incluido el pixel). No cuentan las descargas de recursos estáticos ni
   los dominios cuyo giro es distribuir archivos, salvo que usen un método con cuerpo o un beacon. Las listas
   viven en `interaction_signals.yaml`.
4. **Catálogo propio de organizaciones** (`data/organizations.yaml`). El mapa de entidades busca por dominio
   registrable; `googleapis.com` está en la Public Suffix List, así que cada subdominio es su propio dominio
   registrable y ninguno aparece en el mapa. El catálogo asigna organización por sufijo de host y gana sobre el
   mapa. También declara dominios de dueño desconocido. Es dato propio (no hereda la licencia NC del mapa de
   DuckDuckGo) y entra en `lists_version`.
5. **Nunca nombres de personas.** El mapa de entidades trae como «dueño» el nombre del registrante cuando no
   hay empresa. Como no hay una lista de personas, la regla es conservadora y vive en YAML: un nombre de 2 a 4
   palabras solo con letras es una persona salvo que lleve una forma jurídica o un término de organización, se
   parezca a uno de sus dominios o la entidad tenga 3 o más dominios; un nombre de pila conocido lo decide
   antes que el parecido con el dominio. Se prefiere perder el nombre de una empresa pequeña («no disponible»
   es un resultado honesto) antes que publicar el de una persona. Medido sobre el mapa actual: 1.687 de 19.148
   entidades pasan a «no disponible»; ninguna de las organizaciones con giro conocido se pierde.
6. **Frames de error del navegador.** El monitor de fingerprinting descarta los lotes que llegan desde
   `chrome-error://` y solo cuenta cuántos fueron; el analizador y la api filtran además las filas ya
   guardadas de scans anteriores. Queda `site.summary.error_frames` y una nota «un recuadro no cargó».
7. **Varias cuentas de analítica.** Las reglas de `account_ids.yaml` marcadas `account: true` identifican una
   cuenta de medición. Dos o más del mismo proveedor dan el hallazgo `analytics_accounts` (EVIDENCIA: los IDs
   se observaron en las requests). Se cuentan todos los IDs observados, también los que solo aparecen al
   cargar la etiqueta. Un ID con forma de servicio descontinuado (`UA-`) da `discontinued_tag`, nota
   informativa. Ninguno de los dos entra en los ocho grupos: sus frases hablan de otra cosa y contarlos ahí
   falsearía los conteos; aparecen en la lista técnica de Hallazgos y en los reportes.
8. **Perfil base en español de Chile.** `WORKER_LOCALE` (es-CL) y `WORKER_TIMEZONE` (America/Santiago), validados
   al arrancar. Playwright con `locale` anuncia un solo idioma; un Chrome real anuncia también el genérico. Se
   comprobó con el sitio de fixtures que ningún mecanismo por sí solo deja todas las requests iguales: la orden
   CDP `Emulation.setUserAgentOverride` (userAgent vacío, `acceptLanguage: es-CL,es`) fija navigator.languages y
   la cabecera de las navegaciones, y `extra_http_headers` la de los subrecursos. Con los dos, todas las
   requests llevan `es-CL,es;q=0.9`. Los flags `--lang`/`--accept-lang` se descartaron: mezclan `en-US` en la
   lista. Los perfiles de emulación de Opciones avanzadas no cambian.

## Consecuencias
- Analizador 1.12.0. Los scans guardados se actualizan con `scripts/reanalyze.sh` sin volver a navegar.
- Un scan nuevo y uno anterior del mismo sitio pueden diferir por el idioma: el sitio ahora responde en español.
- La regla de personas da falsos positivos sobre empresas pequeñas sin forma jurídica en el nombre; se corrigen
  en `organizations.yaml §persons.not_persons`.
- El Accept-Language de un iframe de otro proceso depende de que su sesión CDP reciba la misma orden; el monitor
  de red la envía al adjuntarse, igual que hace con el resto de su configuración.
