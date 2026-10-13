# ADR 008 — Perfil base del navegador: no presentarse como bot

Estado: aceptado · Fase: F5

## Contexto
Hasta F4 el worker usaba Chromium en modo headless. Un sitio lo veía así:
`User-Agent: … HeadlessChrome/153.0.0.0 …`, `navigator.webdriver === true`, y
pantalla, ventana y viewport idénticos (1280x720). Muchos sitios y redes de
publicidad tratan distinto a un cliente que se declara automatizado (sirven menos
anuncios, otro contenido o un desafío), así que lo medido no representaba lo que
recibe una persona. Eso es un problema de **validez de la medición**, no de
anonimato.

OpenWPM (Englehardt & Narayanan, 2016), la referencia de este proyecto, mide con
un navegador real completo (Firefox, con ventana sobre un display virtual Xvfb
cuando corre en servidores) y no con un motor headless, precisamente para que los
sitios se comporten como ante un usuario.

## Decisión
1. **Chromium con ventana real sobre un display virtual (Xvfb)**, no headless.
   El worker arranca `Xvfb :99` (1920x1080x24, `-nolisten tcp`: solo socket Unix,
   sin puertos) y lo vigila: si muere, el worker se detiene y el contenedor se
   reinicia. `HEADLESS=true` permite volver al modo anterior.
2. **Sin emulación de viewport** (`no_viewport`): pantalla (1920x1080) y ventana
   (1440x900) son las reales del display, coherentes entre sí.
3. **`--disable-blink-features=AutomationControlled`**: `navigator.webdriver`
   pasa a `false`.
4. **No se falsea nada.** El User-Agent, los Client Hints, la plataforma, el
   número de CPU, la memoria, la zona horaria, el idioma y la GPU son los que el
   Chromium real reporta en el contenedor. Solo se quitan las dos marcas que
   declaran automatización. Esto es la línea base; el spoofing (presentarse como
   otro dispositivo) es F7.

Verificado desde el sitio de fixtures (`tests/fingerprint/test_base_profile.py`):
la cabecera `User-Agent` que recibe el servidor es `… Chrome/153.0.0.0 …` sin
"Headless", `Sec-CH-UA` trae `"Chromium";v="153"` (misma versión mayor), y lo que
lee JavaScript coincide con lo que viaja en las cabeceras.

## Consecuencias y limitaciones
- **Sigue siendo distinguible de una persona** por otros medios: GPU por software
  (SwiftShader), zona horaria UTC, idioma en-US, IP de centro de datos o
  doméstica según dónde corra, ausencia de historial, cookies e interacción.
  El perfil base evita declararse bot; no garantiza pasar por humano.
- Más memoria y CPU por scan que en headless.
- Quitar `navigator.webdriver` es lo que hacen las herramientas de evasión de
  detección. Aquí se hace para medir lo que ve un usuario, sobre sitios públicos
  y una visita por scan; no para evadir controles de acceso.
- Los scans anteriores a F5 se hicieron con el perfil headless: no son
  comparables con los nuevos.
