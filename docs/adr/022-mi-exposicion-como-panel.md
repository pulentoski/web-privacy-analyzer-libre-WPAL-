# ADR 022 — "Mi exposición" como panel (F10.1)

Estado: aceptada · Fecha: 2026-10-08

## Contexto
La vista `#/exposure` se leía como un documento: mucho texto en el cuerpo, sin
resumen, sin noción de qué atributo identifica más, y con una IP interna de
Docker presentada junto a "IP observada" cuando se abre desde el propio equipo.

## Decisión
1. **Panel.** Tarjetas de resumen (atributos expuestos, hash corto, GPU, IP y
   tipo, contexto seguro, hora de lectura) y cuadrículas
   atributo | valor | identificabilidad | ⓘ. Las explicaciones pasan al tooltip
   ⓘ (accesible con teclado); los valores largos se truncan con "ver más". El
   aviso de privacidad queda en dos líneas con "Más información" desplegable.
   No cambia nada de ADR 011: nada se guarda; hashes solo con opt-in.
2. **Nivel de identificabilidad cualitativo.** `data/identifiability.yaml`
   asigna Alto / Medio / Bajo a cada atributo y cabecera, con justificación. La
   API lo valida al cargar y lo sirve en `GET /api/exposure/identifiability`
   (bajo `/api/exposure/`, así también existe en modo exposición).
   - No se publican bits de entropía: el proyecto no tiene población de
     referencia y no inventa cifras (regla 2). La interfaz lo rotula como
     "estimación cualitativa".
   - Un atributo sin entrada se muestra con "—", nunca con un nivel supuesto.
     Un test del frontend exige que todos los ids del catálogo tengan entrada.
3. **Acceso local.** La API añade `ip.access`. Si la IP observada pertenece a
   `DOCKER_INTERNAL_NETWORKS` (por defecto `172.30.0.0/16`, las redes de
   `docker-compose.yml`) o es loopback, es `local`: la página dice "Acceso
   local…" y no la presenta como IP del visitante. Privada fuera de esas redes:
   `lan`, "IP privada (misma red local)". Pública: país y ASN como antes.
   `ip.kind` no cambia (compatibilidad). Para loopback el texto nombra loopback
   y no Docker, porque eso es lo que el servidor ve.
4. **Lectura fresca.** "Actualizar" repite las tres lecturas (conexión,
   colector, cruce con scans) y muestra la hora. `/api/exposure/server` ya
   respondía `Cache-Control: no-store`; queda cubierto por test.
5. **Cruce con scans compacto.** Una línea desplegable por atributo: cuántas
   organizaciones lo leyeron o recibieron y la fecha del scan más reciente
   (`last_scan_at`, nuevo en `/api/exposure/scan-usage`). Antes era una lista
   suelta de dominios dentro de la celda (p. ej. "on.aws" al final de la página).
6. **Redacción.** Trato de usted; "grupo" en lugar del término anterior para la
   comparación y "administrador" para quien la purga. El parámetro de la vista
   pasa a `#/exposure?admin=1`.

## Nombres que se conservan (compatibilidad)
Renombrarlos rompería despliegues y clientes existentes; no son texto visible:
`GET /api/exposure/room`, cabecera `X-Presenter-Token`, variable
`EXPOSURE_PRESENTER_TOKEN`, códigos de error `ROOM_FULL` y `PURGE_DISABLED`,
módulo `api/app/exposure_room.py` y los `data-testid` `room-*` / `presenter-*`.

## Consecuencias
- El nivel es una opinión documentada, no una medida: cambiarlo es editar el YAML.
- Si se cambian las subredes de `docker-compose.yml` hay que ajustar
  `DOCKER_INTERNAL_NETWORKS`; si no, una visita local se rotularía como LAN.
- Las etiquetas de `ip.label` cambiaron de texto; quien las comparara
  literalmente debe usar `ip.kind` / `ip.access`.

## Anexo F10.2 — origen del "texto suelto" y alcance del cruce
- **Origen confirmado** (reproducido con el frontend de v1.1.0 en un navegador):
  lo pintaba el componente `Usage` de `frontend/src/views/Exposure.jsx`, que en
  cada fila añadía bajo el valor "lo leyeron scripts de: …" / "se envió en una
  request a: …" con las etiquetas de `GET /api/exposure/scan-usage`. La última
  fila de la última tabla ("Estado de los permisos") dejaba esas etiquetas como
  texto sin contexto al final de la sección 2.
- **Dato**: la etiqueta es la organización o, si se desconoce, el dominio
  registrable. "on.aws" venía de un scan real (request a
  `od-….ecs.us-east-2.on.aws`, sin organización conocida; la PSL empaquetada no
  tiene ese sufijo, así que el dominio registrable queda en `on.aws`).
  "tracker-a" venía de `tracker-a.fixtures.test`: scans del sitio de fixtures
  hechos por las suites de tests.
- **Corrección**: el cruce es un `<details>` dentro de su fila (F10.1) y ya no
  cuenta scans de fixtures ni de tests (`is_test_scan`: `*.fixtures.test` y
  nombres reservados por RFC 2606/6761). `jobs` no tiene una marca "creado por
  tests"; se usa el host porque las suites solo pueden escanear esos nombres.
- **Garantía**: `test_no_text_outside_the_panel_sections` (e2e) exige que todo
  texto visible esté dentro de una sección del panel y de su caja, con los
  desplegables cerrados y abiertos, en modo normal y presentación.
- Pendiente, fuera de alcance: el dominio registrable `on.aws` es impreciso
  (depende de la PSL que trae `tldextract`).
