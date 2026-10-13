# ADR 021 — Experiencia de usuario: frases técnicas, progreso real, borrado y temas visuales

Estado: aceptado · Fase: F10 (versión 1.1.0)

Objetivo de la fase: que una persona que no programa entienda qué le hicieron, sin perder
rigor. Regla: primero una frase técnica y técnicamente correcta de QUÉ pasó; después, el
detalle técnico, a un clic. Se mantienen los niveles de evidencia, el trato de usted y la
prohibición de prometer anonimato.

## Decisiones

1. **Frases técnicas por plantilla, no por IA** (`data/explanations.yaml`,
   `api/app/explain.py`). Una plantilla por señal (frase de cada request) y por tipo de
   hallazgo, con una variante por nivel de evidencia. Se rellenan con datos reales
   (organización, parámetro, dato leído). Dos garantías que impone el código, además de los
   tests: una frase que no es EVIDENCIA siempre lleva un matiz («podría», «es compatible
   con»…) y, si no lo llevara o faltara un dato, se usa la frase genérica de ese nivel; un
   YAML que redacte una inferencia como hecho **no carga**. Las frases se generan en la api
   porque las usan la interfaz y el reporte exportado: una sola implementación.
2. **El analizador deja los hechos sueltos.** Cada razón de una request lleva ahora `data`
   (parámetro, API, otros destinos) además del texto, para no tener que interpretar frases.
   Es parte de `ANALYZER_VERSION` 1.4.0.
3. **«Hallazgos por grupo»**: siete grupos fijos y en orden (identificadores persistentes,
   fingerprinting, fugas de URL y Referer, exfiltración de atributos, sincronización de
   identificadores, consentimiento (TCF / Consent Mode), fuera del alcance observable). Los
   `id` internos de cada grupo no cambiaron (etiquetado, equipo, navegacion, datos,
   identificador, consentimiento, no_visible). Cada grupo tiene
   hasta dos frases —una para lo observado y otra, con matiz, para lo inferido—, su conteo,
   los niveles y sus hallazgos con evidencia. Un grupo sin hallazgos dice «No se observó en
   esta visita». El séptimo es fijo. Va en el reporte como `story` (schema `report-1.4.0`) y
   en el resumen ejecutivo del HTML/PDF. La lista técnica completa se conserva debajo.
4. **Lectura y propósito, separados.** En el grupo «Fingerprinting» la lectura de una API es un
   hallazgo EVIDENCIA (`fp_read`, generado de las llamadas registradas, con sus referencias)
   y el propósito (fingerprinting) sigue siendo INFERENCIA.
5. **Nuevo hallazgo `persistent_cookie`** (EVIDENCIA): cookies que vencen a más de un día
   del fin de la visita, por dominio registrable. Evidencia: las requests que la fijaron o
   la enviaron; si la creó un script y nunca viajó, la primera request de la visita. La
   duración se calcula contra la hora de la visita, no contra el reloj: re-analizar da lo
   mismo. No suma al puntaje.
6. **Falso positivo de «mismo valor enviado a varias organizaciones»**
   (`data/shared_constants.yaml`, `worker/app/analyzer/constants.py`). Un valor compartido
   solo cuenta si puede distinguir a un visitante. Se descartan: versiones de software
   (`153.0.8010.12` era la de Chrome, en 11 scans), valores contenidos en las cabeceras del
   navegador (User-Agent, Client Hints, Accept-Language), valores leídos de APIs de entorno,
   claves de configuración reconocibles (IDs de medición de Google, tamaños de anuncios,
   nombres de dominio) y parámetros documentados como constantes. Lo descartado se cuenta y
   se guarda con su motivo (`site.summary.shared_values_excluded`): nada desaparece en
   silencio. Además, una versión con puntos deja de tener «forma de identificador».
7. **Progreso real** (`jobs.progress`, migración 0009). El worker publica etapa, requests
   capturadas, inicio de la captura y el máximo (`SCAN_TIMEOUT_S`). Etapas: en cola →
   abriendo el sitio → capturando → analizando → generando resultado → listo / falló. La
   barra muestra la etapa, el contador y los segundos frente al máximo: **ningún porcentaje**.
   El mismo componente sirve para los grupos de Privacy Test («corrida k de N»).
8. **El progreso se escribe con `synchronous_commit = off`**, solo en su transacción. Con el
   disco ocupado por el navegador, el fsync del WAL tardaba más de 3 s (medido) y el
   contador aparecía cuando la captura ya había terminado. El progreso es efímero; el
   resultado del scan se sigue guardando con commit síncrono.
9. **Borrado del historial** (`DELETE /api/scans/{id}`, `DELETE /api/scans` con
   `{"confirm": "BORRAR"}`). Usa la cascada existente; el código solo enumera tablas (leídas
   del catálogo) para medir. Se informa cuántos scans, grupos y reportes se borraron y el
   tamaño de los datos borrados. Borrar el último scan de un grupo borra el grupo.
   Deshabilitado en modo demo: `scripts/demo.sh` arranca la api con `DEMO_MODE` y esta
   responde 403. `backups/` no se toca: la api ni siquiera lo tiene montado.
10. **Tema clásico por defecto, cómic opcional.** El tema cómic solo cambia el estilo
    visual (tipografía, bordes, trama); los textos son los mismos en ambos y no hay globos
    ni onomatopeyas. Tipografías Bangers y Comic Neue (SIL OFL
    1.1) como dependencias `@fontsource` fijadas a versión exacta: Vite las copia a
    `/assets` y se sirven desde el mismo origen. La CSP no cambia (`font-src 'self'`) y
    `assetsInlineLimit: 0` impide que algo se incruste como `data:`. Los íconos son SVG en
    línea. El reporte para clientes no usa nada de esto.
11. **Glosario** (`data/glossary.yaml`, `GET /api/glossary`): 22 términos con equivalente
    breve y definición técnica (sin analogías), tooltip accesible (cursor y teclado) y un panel «¿Qué es esto?» por
    pestaña.

## Desviaciones respecto del encargo

- **Dirección de la sincronización.** El ejemplo pedía «Taboola le pasó a Google su
  identificador y Google le respondió con el suyo». Lo observable es que el mismo valor
  llegó a ambas, no quién se lo pasó a quién. La frase dice: «Sincronización de identificadores
  (cookie syncing): Taboola y Google recibieron el mismo identificador; el valor común
  permite correlacionar sus registros del mismo navegador». Los nombres de parámetro y la
  redirección 302 figuran en el detalle técnico del hallazgo, no en la frase.
- **Canvas: dimensiones.** La frase nombra la API leída (toDataURL o getImageData) pero no
  las dimensiones del canvas: están en el detalle técnico del hallazgo.
- **El reporte.** En el PDF/HTML la sección se titula «Hallazgos por grupo»; los grupos y
  sus frases son los mismos que en la interfaz.
- **«Borrar todo» en los tests automáticos.** El stack de pruebas usa la base real. La suite
  de la api ejecuta el borrado completo dentro de una transacción que revierte, y la E2E
  simula solo la respuesta de ese DELETE. El borrado real se ejecutó a mano como criterio de
  aceptación, con respaldo previo y restauración posterior.
- **Corridas en paralelo.** Un grupo de Privacy Test corre hasta `MAX_CONCURRENT_SCANS`
  scans a la vez, así que puede haber más de una «corrida k de N» en pantalla.
- **«Organización» sin dueño conocido.** Cuando el mapa de entidades no conoce un dominio,
  las frases lo nombran por su dominio y lo cuentan como una organización aparte (la misma
  regla que ya usaba el analizador).

## Limitaciones

- En una sola visita no se puede saber qué valores comparte «la mayoría de los usuarios».
  El filtro reconoce formas, el entorno del navegador y una lista corta de constantes
  documentadas; lo demás se mide comparando visitas limpias (Privacy Test). Un token con
  forma de nombre de dominio (`abc.def.com`) quedaría descartado por error.
- El espacio «liberado» es el tamaño de las filas borradas (comprimidas, sin índices).
  Postgres reutiliza ese espacio; el archivo en disco no se achica hasta un `VACUUM FULL`.
- El log de conexiones del proxy (volumen `scanlog`) no se borra con el historial: rota por
  tamaño (docs/adr/016) y la api no tiene acceso a él.
- Los scans anteriores a esta fase necesitan re-analizarse (`/reanalyze`, sin navegar) para
  tener razones con `data`; sin eso, sus frases caen en la genérica del nivel.
- Los tooltips dentro de tablas con desplazamiento horizontal pueden quedar recortados; la
  definición también está en el glosario.

## Revisión de redacción (v1.1.0)

Antes de cerrar la fase se revisaron los textos, sin cambiar funcionalidad:

- **Registro técnico.** Interfaz, `data/explanations.yaml`, `data/glossary.yaml`, paneles
  «¿Qué es esto?» y resumen ejecutivo del PDF/HTML: trato de usted, sin exclamaciones,
  onomatopeyas ni analogías. Cada frase nombra el mecanismo por su término técnico y lo
  explica en una línea. Los niveles de evidencia no cambian: una Inferencia se redacta como
  compatible o posible, y el código sigue rechazando un YAML que la redacte como hecho.
- **Glosario.** El campo `analogy` se eliminó de términos y paneles; los paneles llevan
  `definition` (contenido de la vista) y `method` (cómo se obtiene).
- **Pestañas.** Resumen · Hallazgos · Rastreadores · Fingerprinting · Tráfico (requests),
  con subtítulo técnico de una línea.
- **Tema.** Clásico por defecto; cómic opcional y solo visual.
- **Nombre de la comparación entre asistentes.** La función de "Mi exposición" que compara
  huellas mediante hashes en memoria se denomina «Comparación grupal de huellas» y la guía
  es `docs/GUIA-DEMOSTRACION.md`. Las rutas de la API (`/api/exposure/room`,
  `/api/exposure/compare`, `/api/exposure/purge`), las variables de entorno y los
  `data-testid` no se renombraron: no contenían el nombre anterior y cambiarlos rompería
  compatibilidad con clientes y scripts existentes.
- **Compatibilidad.** El schema del reporte sigue siendo `report-1.4.0`: `story.steps[]`
  conserva sus campos e `id`; solo cambian los textos (`title`, `technical`, frases).
