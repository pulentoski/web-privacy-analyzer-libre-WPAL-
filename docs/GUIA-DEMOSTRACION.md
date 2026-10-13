# Guía para la demostración

Escrita para quien presenta: alguien que conoce redes, no necesariamente programación.
Solo hay que copiar comandos en una terminal y manejar un navegador.

La demo tiene dos partes independientes:

- **"Mi exposición"**: el público abre una página desde su celular y ve qué revela su
  propio navegador. Es lo único que se publica en la red.
- **El analizador**: usted, desde su equipo, analiza un sitio y recorre los resultados.
  El público solo lo ve proyectado.

## 1. Preparación (el día anterior)

1. **Arrancar y comprobar**, con el equipo conectado a internet:

   ```sh
   ./scripts/start.sh
   curl -s 127.0.0.1:8000/health
   ```

   Debe responder `{"status":"ok","database":true,"worker":true}`. Abra
   http://127.0.0.1:8080.

2. **Pregenerar el plan B** (sección 4): haga ahora los scans que piensa mostrar y
   descargue sus PDF. Quedan guardados aunque después no haya internet.

3. **Rotar secretos** si el equipo se usó en otra demostración o alguien vio el `.env`:
   `./scripts/rotate-secrets.sh`.

4. **Anotar el token de administrador**: es la línea `EXPOSURE_PRESENTER_TOKEN` de `.env`.
   Lo necesitará para vaciar el grupo. No lo proyecte.

## 2. Preparación (en el lugar de la demostración, 20 minutos antes)

1. **Red.** Conecte el equipo a la red que usará el público. Debe ser una red donde los
   dispositivos se vean entre sí: muchas redes de invitados aíslan a los clientes
   (aislamiento de clientes o *AP isolation*) y entonces los celulares no llegarán a su
   equipo. Si es así, comparta internet desde su propio teléfono o lleve un router.

2. **Arrancar con la red nueva**:

   ```sh
   ./scripts/start.sh
   ```

   Este paso detecta la IP actual. No lo omita aunque el sistema ya estuviera andando.

3. **Publicar "Mi exposición" y generar el certificado**:

   ```sh
   DEMO_MODE=exposure ./scripts/demo.sh
   ```

   El comando imprime dos direcciones y una **huella del certificado**. Cópielas en una
   diapositiva:

   - `https://<IP>:8443/` — la recomendada. El navegador mostrará una advertencia
     porque el certificado es autofirmado (no lo emitió una autoridad). Es esperable.
   - `http://<IP>:8088/` — sin advertencia, pero el navegador entrega menos información.

4. **Probar desde su celular**, conectado a la misma red:
   - abra `https://<IP>:8443/`;
   - en la advertencia, mire los detalles del certificado y compare la huella SHA-256 con
     la de la terminal; si coincide, continúe;
   - debe ver la página "Mi exposición" con su IP y los datos de su navegador.

   Si no carga: revise que el celular esté en la misma red, que el cortafuegos del
   equipo permita los puertos 8443 y 8088, y que la red no aísle clientes.

5. **Comprobar que nada más quedó publicado**: desde el celular,
   `http://<IP>:8080/` **no** debe responder.

6. Abra en su equipo http://127.0.0.1:8080 y active el **modo presentación** (botón
   arriba a la derecha): letra grande y alto contraste.

## 3. Guion de la demo

### 3.1 Mi exposición, con la audiencia (10 min)

1. Proyecte la dirección https y la huella. Explique la advertencia: "el certificado lo
   hice yo hace diez minutos; por eso su navegador no lo conoce. Compare la huella".
2. Pida que abran la página. Recorra con ellos las secciones:
   - **Tarjetas de resumen**: atributos expuestos, huella corta, GPU, IP observada,
     contexto seguro y hora de lectura. El botón "Actualizar" vuelve a leer todo.
   - **1. Datos expuestos en la conexión (IP y cabeceras HTTP)**: en la red del lugar
     la IP es privada; la página lo dice y no la presenta como pública. Desde el
     propio equipo del servidor dice "Acceso local" (red interna de Docker).
   - **2. Atributos accesibles mediante APIs del navegador**: pantalla, idioma, zona
     horaria, tarjeta gráfica… cada fila lleva valor, nivel de identificabilidad
     (Alto / Medio / Bajo, estimación cualitativa) y un ⓘ con la explicación.
   - **3. Huella del navegador (hash combinado)**: un resumen de todos esos valores.
3. Si quiere comparar entre asistentes, pídales marcar la casilla de consentimiento del
   **4. Comparación de huellas en grupo**. Solo viajan resúmenes (hashes), se guardan en memoria y se borran
   solos a las dos horas. Abra en su equipo
   `http://127.0.0.1:8080/#/exposure?admin=1` para ver cuántos participan.
4. Mensaje: "nadie les pidió permiso para nada de esto, y no usamos cookies".

### 3.2 Panel y análisis de un sitio (5 min)

1. Abra http://127.0.0.1:8080: el **Panel** resume lo ya analizado (organizaciones
   "presentes en k de N sitios", atributos del navegador más leídos y más enviados, ranking
   por índice de exposición) y la tarjeta **Mi exposición** de su propio navegador.
2. Menú **Analizar un sitio**: escriba la dirección de un sitio conocido por el público y
   pulse analizar. Si pega una dirección copiada de un anuncio, muestre el aviso de
   parámetros de seguimiento y el botón **Limpiar URL** (por defecto se analiza limpia y se
   guardan las dos). Mientras avanza la barra (hasta un minuto), explique: "un
   navegador real, encerrado en un contenedor, está visitando el sitio una vez y
   anotando cada comunicación". La barra muestra la etapa real y cuántas requests van
   capturadas: léalas en voz alta, son un buen gancho.
3. Si falla o tarda, pase al plan B sin disculparse: abra un scan del **Historial**.

### 3.3 Recorrido por los resultados (15 min)

Siga el orden del menú, de arriba hacia abajo; cada pestaña responde una pregunta.

| Pestaña | Pregunta | Qué mostrar |
|---|---|---|
| **Resumen** | ¿Qué tan expuesto queda el visitante? | La frase de resumen, el índice (0–99) y su desglose; el grafo sitio → organizaciones. Diga que es una estimación para comparar, no una nota |
| **Hallazgos** | ¿Qué se observó durante la visita? | Recorra los siete grupos en orden. Señale el color de cada frase: verde es lo observado, amarillo es una inferencia y por eso dice "podría" |
| **Rastreadores** | ¿Qué organizaciones recibieron requests con señales de seguimiento? | Las organizaciones y la frase técnica de cada conexión; abra "Ver detalle técnico" en una para mostrar las razones. Al final, los **ID de cuenta del sitio**: identifican al sitio ante su proveedor, no a quien lo visita |
| **Fingerprinting** | ¿Se puede reconocer el dispositivo sin cookies? | La tabla "Atributos de su navegador que leyó este sitio" (atributo · leído por · enviado a) y los scripts que hicieron las lecturas. Subraye: la lectura es el hecho; "compatible con fingerprinting" es una inferencia |
| **Tráfico (requests)** | ¿Dónde está la evidencia? | Abra una request: arriba la frase técnica, y con "Ver detalle técnico" la dirección exacta, sus parámetros y cabeceras |

Si alguien pregunta por una palabra, pase el cursor sobre el término subrayado, sobre el ⓘ
del panel, o abra «¿Qué es esto?»: cada pestaña describe su contenido y el método con que
se obtiene. La pantalla lleva poco texto a propósito; "Límites de la medición" está plegado
en el Resumen: ábralo al menos una vez. Para unir las dos mitades de la demostración, abra
**Mi exposición** y elija el scan en **Comparar con un scan**: marca cuáles de los atributos
del navegador leyó ese sitio y a quién los envió. El
tema **Clásico** viene por defecto; **Unidad Púrpura** (oscuro) es opcional y solo cambia el estilo visual. El
**modo presentación** funciona en ambos.

Cierre el recorrido en la evidencia: es lo que distingue esta herramienta de una lista
de opiniones.

### 3.4 Opciones avanzadas con el perfil incoherente (8 min)

1. Menú **Analizar un sitio** → despliegue **Opciones avanzadas**. Misma dirección;
   escenario "sin interacción"; perfiles **Navegador real** e **incoherente-demo**;
   1 corrida. El botón pasa a decir "Analizar (2 scans)".
2. Al terminar, muestre:
   - la **conclusión de una línea** al inicio del resultado, con su nivel de evidencia;
   - la alerta **FINGERPRINT INCONSISTENTE**: el perfil dice ser un sistema y su tarjeta
     gráfica o su zona horaria dicen otro. "Disfrazarse mal llama más la atención";
   - la tabla **qué cambió y qué permaneció**: la fila de la dirección IP no cambia con
     ningún perfil.
3. Si el sitio tiene un banner de cookies de una plataforma conocida, repita con los
   escenarios "aceptar" y "rechazar": la conclusión resume el cambio ("Al rechazar: 47 → 12
   requests de rastreo; 3 organizaciones siguieron recibiendo datos"). Si el banner no se
   reconoce, lo dice ("Banner no reconocido: los escenarios fueron equivalentes").

### 3.5 Descargar el PDF (3 min)

1. Vuelva al scan y pulse **Descargar PDF**.
2. Muestre la primera página (resumen para quien dirige el negocio, con
   recomendaciones) y salte al anexo técnico.
3. Señale tres cosas: los identificadores van **enmascarados** por defecto; el documento
   imprime el **sha256** del JSON del que salió; y el aviso de que **no es asesoría
   legal**.

## 4. Plan B: sin internet o con la red caída

Lo que funciona **sin internet**:

- "Mi exposición" completa (todo ocurre entre el celular y su equipo), salvo el botón
  opcional "ver mi IP pública".
- El **Panel** y el **Historial**, y abrir cualquier scan o grupo de Opciones avanzadas ya
  hecho, con todas sus pestañas.
- Descargar el PDF o el HTML de un scan ya hecho.

Lo que **no** funciona: analizar un sitio nuevo.

Preparación del plan B, el día anterior y con internet:

1. Analice los 2 o 3 sitios que piensa mostrar. Quedan en el **Historial** y alimentan el
   **Panel**.
2. Ejecute las Opciones avanzadas con el perfil incoherente sobre uno de ellos y deje abierta
   la pestaña del resultado, o anote su dirección (`#/privacy/<id>`).
3. Descargue el PDF de cada uno y guárdelos en una carpeta a mano.
4. Como último recurso, en `docs/samples/` hay reportes de ejemplo y en
   `docs/images/` capturas de cada vista.

Durante una demo (`DEMO_MODE`) no se puede borrar el historial: nadie del público puede
dejarlo sin sus scans preparados.

Atención: los scans con más de 30 días se borran solos (`SCAN_RETENTION_DAYS`). Si
prepara la demostración con mucha anticipación, repita los scans la semana anterior.

Si la red del lugar no deja que los celulares lleguen a su equipo, haga "Mi
exposición" solo desde su propio navegador, proyectada.

## 5. Qué no afirmar

| No diga | Diga |
|---|---|
| "Con este perfil usted queda anónimo" o "esto lo oculta" | "Cambió lo que el navegador dice ser; la dirección IP y otras características siguen siendo las mismas" |
| "Este sitio lo está rastreando" | "Se observaron estas comunicaciones con señales de seguimiento, con este nivel de evidencia" |
| "Hace fingerprinting" | "Lee estas características, un patrón compatible con fingerprinting; es una inferencia" |
| "El servidor está en tal ciudad" o "sus datos se guardan en tal país" | "La dirección IP del servidor corresponde aproximadamente a tal país; eso no dice dónde se almacenan los datos" |
| "Su huella es única" | "No tenemos una población de referencia para afirmar eso" |
| "Este sitio incumple la ley" o "esto es ilegal" | "Esto es lo que se observó; si cumple o no una norma lo evalúa un profesional" |
| "El sitio hace esto siempre" | "Esto ocurrió en una visita automatizada, desde esta red; otra visita puede diferir" |
| "No encontramos nada, es seguro" | "En esta visita no se observó; hay tráfico que la herramienta no ve" |

Un sitio de terceros no es un rastreador por sí solo, y el nombre de un parámetro no
prueba qué contiene.

## 6. Al terminar

1. **Vaciar el grupo** si usó la comparación grupal de huellas: en
   `http://127.0.0.1:8080/#/exposure?admin=1`, con el token de administrador.

2. **Apagar el modo demo**:

   ```sh
   ./scripts/demo.sh down
   ```

3. **Comprobar** que ya no hay nada publicado en la red:

   ```sh
   docker compose ps frontend
   ```

   En la columna de puertos solo debe aparecer `127.0.0.1:8080`. Desde el celular, la
   dirección de la demo ya no debe responder.

4. Si proyectó o compartió por error el `.env` o el token:
   `./scripts/rotate-secrets.sh`.

5. Si no va a usar más el equipo: `docker compose --profile test down` detiene todo y
   conserva los datos.
