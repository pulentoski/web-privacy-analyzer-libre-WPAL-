# ADR 037 — Linker de Google (_gl), cookie que coincide y aviso de consentimiento

Estado: aceptada · Versión: 1.4.10 · Analizador 1.17.0 · Schema de reporte 1.10.0

## Contexto

1. La tabla del índice en `docs/SPEC.md` seguía con `tracker_domains` en 30 y sin `first_party_telemetry`, que existe
   desde v1.3.4 (ADR 028). Nada comprobaba que el SPEC y `data/scoring.yaml` coincidieran.
2. Desde v1.4.9, si el valor de una cookie viajaba en la URL o el cuerpo de una request que no envió cookies, el texto
   decía «un script copió el valor de la cookie». Que la request no lleve la cabecera Cookie no prueba que un script haya
   leído la cookie: la instrumentación no registra lecturas de `document.cookie` ni de storage.
3. `consent.user_interaction` se confundía con las interacciones de la captura interactiva (clics, desplazamientos y
   teclas del relé, `summary.interaction`). Significa otra cosa: que el escenario pulsó un botón del aviso de consentimiento.
4. El parámetro `_gl` (linker de Google) solo se trataba como parámetro de la URL de entrada (`url_cleaning`). En una
   captura interactiva de AliExpress (2026-10-15), el enlace «superdeals» abrió una pestaña nueva en
   `www.aliexpress.com/ssr/…?…&_gl=1*8k5w2*_gcl_au*…*_ga*…*_ga_VED1YSGNC7*…`. La request de esa navegación no quedó
   registrada (pestaña nueva); la URL consta en la línea de tiempo y en el `frame_url` de las requests de la página.

## Decisión

### Índice en el SPEC
La tabla del SPEC copia `scoring.yaml §site_exposure` (componente, tope y k). `frontend/src/lib/spec.test.js` compara las
dos y falla si difieren. Se ejecuta en el frontend porque es la suite que en CI tiene el checkout completo; `scripts/test.sh`
monta `docs/` y `data/` en su contenedor. El test lee el bloque del YAML con un parser estricto: una línea con otra forma
hace fallar el test, no se ignora.

### Cookie: «coincide» y «copió»
- Por defecto: «el valor enviado coincide con la cookie «X»» (o con el ítem de storage). Es lo observado.
- «Un script copió el valor de la cookie X» solo si la captura registró que el MISMO script que inició la request leyó
  esa cookie o ese ítem (`capture.storage_reads`: `{script_url, kind: cookie|local|session, name}`). Hoy ninguna captura
  lo registra y no se añade instrumentación nueva, así que en la práctica siempre se usa el primer texto.
- `copied_cookie` (análisis 1.16.0) ya no activa la frase de copia; el detalle nuevo es `matched_cookie` y, si hubo
  lectura, `copied_by_script`.

### `consent.banner_interaction`
Se renombra `consent.user_interaction` a `consent.banner_interaction`; en la interfaz y en el HTML, «Interacción con el aviso
de consentimiento». La api lee los análisis anteriores con el nombre viejo (`consent_section`). El schema 1.10.0 exige el
nombre nuevo; los schemas anteriores se conservan.

### Linker de Google (_gl)
- **Dónde se busca:** en la query o el fragmento de las URL de navegación (documentos), de los saltos 3xx, de la línea de
  tiempo de la captura interactiva y de la URL final, cuando esa navegación no quedó como request. Se registran el origen
  (Referer, cadena de redirección, página anterior o URL de entrada), el destino, sus dominios registrables y la cadena
  de redirección.
- **Qué se decodifica:** solo el formato reconocido (`1*<hash>*<nombre>*<valor>*…`, valores en base64 con «.» de relleno).
  Se informan solo los campos extraídos, con el valor enmascarado (prefijo de 4 y largo, como los reportes). No se supone
  que haya `_ga` o `_gcl_au`. Si el formato no coincide, solo consta la presencia. El hash no se verifica, porque depende
  del navegador y de la hora.
- **Qué se concluye:** la presencia de `_gl` y su transferencia en una URL capturada (EVIDENCIA). Nunca que el destino
  reconoció al visitante ni que se completó una atribución.
- **Destino:** se clasifica con el mismo criterio que el resto del análisis (`party` y mapa de entidades, con alias y
  catálogo propio): propio, misma organización, tercero u «Organización no disponible». El hallazgo dice qué criterio
  resolvió la organización: dominio registrable, mapa de entidades (o su catálogo propio) o alias (`FilterLists.entity_basis`).
- **Puntos:** señal por request `linker_transfer` (EVIDENCIA, 15), solo si el destino es un tercero conocido y hay una
  request de navegación a la que atribuirla. No hay componente nuevo del índice (decisión del usuario frente a un
  componente con tope propio: así no se mueven los topes ni el índice de los demás scans). Con propio, misma
  organización u «Organización no disponible» no suma.
- **Hallazgos:** `gl_linker` (tercero; grupo «Identificadores persistentes») y `gl_linker_info` (los demás; solo en la lista
  técnica). Si otra regla ya informó esa transferencia (sincronización por redirección, sincronización de identificadores
  o identificador persistente) en la misma request y con el mismo valor (el `_gl` o un campo decodificado), no se crea
  otro hallazgo ni se puntúa otra vez; el resumen lo indica (`duplicate_of`).
- Resumen: `site.summary.linker.items[]`. En la interfaz, el panel «Linker de Google (_gl)» del Resumen separa presencia,
  campos decodificados y destino.

## Consecuencias

- Tras `./scripts/reanalyze.sh --all`, los textos de cookie de los scans guardados dicen «coincide»; ninguno dice «copió».
- AliExpress (captura interactiva): `_gl` consta en la navegación de es.aliexpress.com a www.aliexpress.com, con
  `_gcl_au`, `_ga` y `_ga_VED1YSGNC7` decodificados y enmascarados. Es propio por dominio registrable, así que no suma.
- Una navegación en pestaña nueva sigue sin request propia: el `_gl` se detecta por la línea de tiempo y la evidencia son
  las requests de ese documento. Sin request de navegación, un `_gl` hacia un tercero se informa pero no suma.
- Si en el futuro se instrumentan las lecturas de cookies o storage, basta con llenar `storage_reads`: el analizador ya
  distingue «coincide» de «copió».
