# ADR 030 — Registro de interacción, agrupación, catálogo y acentos (v1.4.2)

Estado: aceptada · Fecha: 2026-10-12

## Contexto
Capturas reales (aliexpress interactiva, biobiochile) mostraron: textos de «visita automatizada» en capturas
donde navegó una persona; listas de 285 hallazgos con decenas de filas casi iguales; organizaciones sin tipo de
servicio; un host `on.aws` recibiendo eventos de Meta sin rótulo; un generador de QR marcado como canvas
fingerprinting; scripts inline con «Organización no disponible»; y ninguna señal sobre si el sitio observa clics,
desplazamiento o teclado, que es justo lo que una captura interactiva permite ver.

## Decisiones
1. **Registro de interacción, tres fuentes con niveles distintos** (`data/interaction_signals.yaml`):
   - *Escucha* (EVIDENCIA): la instrumentación envuelve `EventTarget.addEventListener` y los manejadores `onX` y
     cuenta, por script, qué tipos de evento pide (clic, mouse, desplazamiento, teclado, escritura, toque,
     visibilidad). Solo tipo de evento y script: nunca el evento. Que escucha es un hecho; para qué, no se afirma.
     Estas APIs (`events.*`) no entran en la tabla de fingerprinting.
   - *Datos de interacción en payloads* (INFERENCIA): parámetros cuyo nombre corresponde a coordenadas,
     profundidad de desplazamiento, permanencia, elemento o exposición (calibrado con nombres reales:
     `percent_scrolled`, `_et`, `gokey.exposure`). El nombre no prueba el contenido. `x`, `y` o `duration` no cuentan.
   - *Correlación en capturas interactivas* (EVIDENCIA de la secuencia temporal): el relé VNC de la api lee de los
     mensajes RFB del cliente la hora y el tipo (clic, desplazamiento, tecla) de cada interacción —nunca el keysym ni
     la posición— y los guarda en `interactive_sessions.interactions`. El analizador busca envíos a otras
     organizaciones en los 2 s siguientes. Se informa «Su interacción se envió a X» solo si hay ≥ 2 interacciones
     seguidas de envío y los envíos observados superan 2× lo esperable por el ritmo de esa organización FUERA de las
     ventanas (descarta balizas periódicas). Un clic seguido de una navegación no cuenta: el tráfico de la página
     nueva no es un envío del clic. Lo que se afirma es la secuencia, no el contenido del envío.
   - *Grabación de sesión* (INFERENCIA): requests a un servicio de ese giro (Clarity, Hotjar…).
   - Grupo nuevo «Registro de interacción» en Hallazgos y reportes: los grupos pasan de siete a ocho
     (schema `report-1.7.0`). La línea de tiempo va en `site.summary.interaction`.
2. **Textos según el origen.** `steps[].fixed_by_source` en `explanations.yaml`: en una captura interactiva el
   grupo fijo dice que hubo navegación humana y que lo no observable es el tratamiento en servidores. «Durante la
   sesión» en capturas interactivas y HAR. Rótulo «captura interactiva · N páginas» en el encabezado.
3. **Hallazgos repetidos en una fila**: clave = tipo + nivel + organizaciones. La fila dice cuántos hallazgos
   reúne (cada uno es un valor, parámetro o script distinto) y cuántas requests distintas los respaldan; se
   despliega al detalle. Nada se descarta: es presentación (`groups` en `/findings`). En Rastreadores, las requests
   de una organización se agrupan por tipo de señal.
4. **Catálogo de tipo de servicio**: 13 redes publicitarias nuevas, «publicidad móvil», «DMP» y «broker de datos».
   Patrones `urls:` para un producto concreto dentro de una organización: `facebook.com/tr` y `fbevents.js` son
   «publicidad (pixel de conversión)» aunque Meta siga siendo red social para lo demás.
5. **Rastreo del lado del servidor** (`data/server_side_tracking.yaml`): host con sufijo de nube genérico que
   recibe `_fbp`/`fbp` o ≥ 2 claves del payload de un evento de Meta → «posible servidor de Conversions API de
   Meta». INFERENCIA: el reenvío a Meta ocurre entre servidores. Las mismas claves hacia un dominio con dueño
   conocido no se rotulan.
6. **Librerías benignas** (`data/benign_libraries.yaml`): si el script que leyó el canvas coincide (por la ruta de
   su URL) con un generador de QR, gráficos, PDF, etc., no se infiere fingerprinting; la lectura queda como
   EVIDENCIA («lectura de canvas por librería conocida»). Límite declarado: un script puede llamarse como una
   librería sin serlo; por eso la lectura nunca desaparece.
7. **Scripts inline o eval**: son código del documento donde corrieron; se atribuyen a la organización de ese
   documento y, si no se conoce, a su host.
8. **Misma organización**: una request con `party = same_org` se describe como «Recurso de la misma organización
   (X)», no «Request a tercero».
9. **HAR exportado**: una entrada en `log.pages` por página visitada (cada entrada va con la última página cargada
   antes de ella) y `creator.version` desde `app/version.py`.
10. **Las pruebas no dejan scans**: `scripts/purge-test-scans.sh` (hosts de prueba, mismo criterio que
    `is_test_scan`) al terminar `scripts/test.sh`, más limpieza al final de las suites api y e2e.
11. **Acentos por modo** en «Analizar un sitio»: tokens `--acc-*` en un único bloque de `index.css`, para ambos
    temas; borde, título, ícono y botón usan el mismo. Contraste AA comprobado en e2e. Cada modo conserva título e ícono.
12. **Indicador como consola de mando** (diseño propio): mini con tres cuadros; vista completa con tres placas en
    triángulo alrededor de un círculo, bloque de estado y detalle. «ALERTA» parpadea solo con RAM > 85 % y no
    parpadea con `prefers-reduced-motion`. En Clásico, versión sobria con los mismos datos.

## Riesgos
| Riesgo | Tratamiento |
|---|---|
| Registrar la interacción del usuario es en sí un dato sensible | Solo hora y tipo; el keysym y la posición no se leen; tope de 3000; se borra con el scan |
| «Evidencia» por pura coincidencia temporal | Línea base por organización fuera de las ventanas, mínimo de interacciones, exclusión de navegaciones; el texto dice «secuencia temporal» |
| Envolver `addEventListener` altera el sitio o delata la instrumentación | Mismo envoltorio (Proxy con `toString` nativo) que el resto; cubierto por las pruebas de perfil base |
| Lista de librerías benignas usada para evadir | La lectura sigue registrada como Evidencia; solo se retira la inferencia |
| Análisis anteriores sin estas mediciones | `interaction` ausente = no se muestra; `available: false` = se dice que no se registró. Reanalizar: `scripts/reanalyze.sh` |
