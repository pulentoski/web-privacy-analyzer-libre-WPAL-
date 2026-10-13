# ADR 014 — Privacy Test: corridas, consentimiento, perfiles e identificadores persistentes

Estado: aceptado · Fase: F7

## Qué responde
"¿Qué cambia, qué permanece y qué sigue identificándome?" al cambiar la respuesta
al banner de cookies o lo que el navegador dice ser. **Nunca** "quedaste oculto":
la interfaz y la API solo describen lo observado (un test recorre todos los
textos del frontend buscando esas palabras).

## Decisiones
1. **Un test es un grupo de scans** (`test_groups`): escenarios × perfiles ×
   corridas, hasta `MAX_GROUP_JOBS` (10). Cada corrida es un scan normal con
   `options` (`scenario`, `profile`, `run`) y **cuenta para el rate limit**: o
   caben todas o no se crea ninguna. Las corridas se encolan intercaladas para que
   los grupos se midan en momentos parecidos.
2. **Toda comparación usa agregados** (lección del ADR 009): mediana y rango de
   los conteos y, por dominio, "apareció en k de N corridas". Las corridas
   fallidas no entran en N. La comparación se calcula al leer
   (`api/app/privacy.py`, funciones puras), no se guarda.
3. **Consentimiento sin adivinar.** `data/cmp_selectors.yaml` lista plataformas
   (OneTrust, Didomi, Cookiebot, Quantcast) con el selector exacto de cada botón.
   Solo se pulsa un selector de esa lista. Si no hay banner reconocido, o la
   plataforma no tiene un botón conocido para el escenario (Quantcast y
   "rechazar": su botón secundario puede ser "más opciones"), el escenario queda
   `no_aplicable` con su motivo. El estado resultante se verifica con
   `__tcfapi('getTCData')` y, si no existe, con la cookie de la plataforma.
4. **Frontera antes/después.** Al pulsar se anota cuántas requests iban
   capturadas (`interaction_seq`). "Antes de cualquier interacción" es todo lo
   anterior (o el scan entero si no se pulsó); "después de rechazar", lo
   posterior. Los hallazgos son EVIDENCIA y llevan una nota: no son un juicio
   sobre el cumplimiento de ninguna norma.
5. **Perfiles solo Chromium** (`data/profiles/`): simular Safari o Firefox con un
   motor Chromium se delata solo. `{major}` se sustituye por la versión real del
   motor. Orden de aplicación:
   1. opciones del contexto (UA, idioma, zona, viewport, pantalla, DPR, táctil);
   2. init script `profile_spoof.js` (platform, CPU, memoria, WebGL), **antes**
      que la instrumentación de fingerprinting (ADR 007): así esta registra los
      valores emulados, que son los que ve el sitio;
   3. por página, CDP `Emulation.setUserAgentOverride` con `userAgentMetadata`,
      para que `navigator.userAgentData` y las cabeceras `Sec-CH-UA-*` coincidan.
   Misma técnica de apariencia nativa que F4 (Proxy + `toString`).
6. **Sondeo aparte.** Lo que "ve un script" se lee en un segundo contexto limpio
   con el mismo perfil y sin instrumentación, en una página https servida por
   Playwright (no sale a la red). Así el sondeo no ensucia el registro de
   fingerprinting del scan. Lo que "ve el servidor" son las cabeceras capturadas
   de la navegación principal.
7. **Detector de inconsistencias** (`analyzer/consistency.py`, reglas en
   `data/consistency_rules.yaml`): sistema operativo según UA, `platform`, Client
   Hints, cabeceras y GPU; JS frente a cabeceras; zona horaria frente a idioma;
   móvil frente a pantalla y táctil; y artefactos del propio mecanismo
   (`toString` no nativo, propiedades donde no deben estar). Los valores son
   EVIDENCIA; "combinación poco común o detectable", INFERENCIA.
8. **Identificadores persistentes.** Cada corrida usa un navegador nuevo. Un
   valor con forma de identificador que un tercero recibe **igual en ≥ 2 corridas
   del mismo perfil** es EVIDENCIA de que se repite sin cookies. Qué lo origina es
   INFERENCIA, según lo que pase al cambiar de perfil: cambia (depende de
   atributos emulados), cambia en parte (la parte fija no depende de ellos: por
   ejemplo la IP) o se mantiene (IP, atributos no modificados, **o una constante
   del sitio**, que también se repite). Por eso se ordenan primero los que
   cambian con el perfil.
9. **La IP no cambia** y se dice en el formulario, en la tabla (fila "Dirección
   IP: la misma en todas las corridas") y en la lista de lo que sigue observable.

## Limitaciones
- **Emulación incompleta.** Los iframes de terceros en otro proceso y los workers
  no reciben el `userAgentMetadata` ni el init script: pueden ver valores reales.
  La huella de canvas y de audio es la del equipo real. Fuentes, códecs y otros
  rasgos no se tocan. Un perfil "coherente" según estas reglas no es
  indistinguible de un equipo real.
- **El detector solo conoce sus reglas.** Cero inconsistencias significa que
  ninguna regla saltó, no que el perfil sea indetectable para un sitio.
- **Repetido no es identificador.** Claves de sitio, versiones y parámetros fijos
  también se repiten; con un solo perfil no se distinguen. La lista puede ser
  larga en sitios con publicidad.
- **CMP**: solo cuatro plataformas y su primera capa. Banners propios, textos
  traducidos o segundas capas quedan `no_aplicable`. Los selectores cambian con
  las versiones de cada plataforma.
- **Pocas corridas** (máximo 5): una diferencia entre grupos puede ser variación
  normal del sitio.
- "Solo después de aceptar" se decide por ruta exacta del recurso: una URL con un
  identificador en la ruta parecería siempre nueva.
