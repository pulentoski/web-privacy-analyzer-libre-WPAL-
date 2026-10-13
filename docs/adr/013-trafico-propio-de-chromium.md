# ADR 013 — Tráfico propio de Chromium

Estado: aceptado · Fase: F7

## Contexto
En F6 apareció en el log del proxy tráfico que no viene de ninguna página: lo
genera el propio navegador del worker. Medido con el navegador inactivo 60 s en
`about:blank` (registro de red de Chromium): 11 requests a
`accounts.google.com/ListAccounts`, `android.clients.google.com` (registro y
checkin de GCM), `mtalk.google.com`, `update.googleapis.com` (actualizador de
componentes), `clients2.google.com/time` y `www.google.com` (página y
`/async/folae`). Playwright ya pasa `--disable-background-networking`,
`--disable-component-update`, `--disable-sync` y `--disable-default-apps`; con
ventana real (ADR 008) no bastan.

No contamina los resultados (Playwright no lo captura), pero sale desde la IP de
quien opera el worker y hacia un tercero, en cada scan.

## Decisión
Tres capas, porque ninguna cubre todo por sí sola:

1. **Políticas gestionadas** (`worker/chromium-policies/wpa.json`, copiadas en la
   imagen a la ruta de "Chrome for Testing", que es el binario de Playwright):
   sin buscador por defecto, sin sugerencias, sin predicción de red, sin
   variaciones, sin consultas de hora, sin inicio de sesión. Eliminan
   `www.google.com` y `clients2.google.com`.
2. **Flags**: `--no-pings`, `--disable-domain-reliability`, y los servicios que
   las políticas no apagan (cuentas, GCM, actualizador de componentes) se apuntan
   a `blackhole.invalid`, un nombre reservado que nunca resuelve (RFC 6761).
   Ese host se añade a la lista de exclusión del proxy del navegador: la conexión
   falla dentro del contenedor y **no llega ninguna request al proxy**.
3. **Respaldo en el proxy**: Squid deniega `update.googleapis.com`,
   `clients2.google.com`, `clientservices.googleapis.com`,
   `android.clients.google.com`, `mtalk.google.com`,
   `optimizationguide-pa.googleapis.com`, `safebrowsing.googleapis.com`,
   `content-autofill.googleapis.com`, `*.gvt1.com` y `blackhole.invalid`.

Verificación: navegador inactivo 60 s → 0 líneas en el log del proxy (antes: 11).

## Desviación respecto del pedido
Se pidió denegar en el proxy también `accounts.google.com`. **No se hizo**: ese
dominio y `www.google.com` los usan sitios reales (inicio de sesión con Google,
reCAPTCHA, búsquedas), y bloquearlos alteraría la medición de esos sitios, que es
el propósito del proyecto. El tráfico *propio* hacia ellos se elimina con las
capas 1 y 2. Si aun así se quieren denegar, es una línea en
`egress-proxy/squid.conf.template`.

## Riesgos y limitaciones
- **`blackhole.invalid` queda fuera del proxy.** Una página que pida
  `http://blackhole.invalid/` se conectaría sin pasar por Squid. No es una vía de
  SSRF: el nombre no resuelve (el worker no tiene DNS externo, y `.invalid` está
  reservado para no existir). Squid también lo deniega por si algún día llegara.
- Las políticas y los flags dependen de la versión de Chromium: una versión nueva
  puede añadir servicios. El criterio de "60 s inactivo → 0 requests" hay que
  repetirlo al actualizar Playwright.
- Las políticas desactivan el buscador por defecto y el gestor de contraseñas del
  navegador del worker. Ninguna página puede leer eso directamente, pero es una
  configuración distinta de la de un Chrome recién instalado.
- Playwright desactiva por su cuenta varias funciones de Chromium (por ejemplo
  `ThirdPartyStoragePartitioning`); no se revisó cómo afecta eso a la medición.
