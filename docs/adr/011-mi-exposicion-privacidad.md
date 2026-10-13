# ADR 011 — "Mi exposición": privacidad por diseño

Estado: aceptado · Fase: F6

## Contexto
La página "Mi exposición" muestra a cada visitante qué revela su propio
navegador. Se va a usar en vivo, con el público de una demostración abriendo la página
desde sus equipos. Es decir: una herramienta que explica el fingerprinting tiene
delante, por un momento, las huellas de decenas de personas reales. Lo razonable
es no quedarse con ninguna.

Referencia: la Ley 21.719 (Chile) de protección de datos personales, en
particular los principios de finalidad, proporcionalidad (minimización: tratar
solo los datos necesarios) y que el consentimiento sea libre, informado,
específico e inequívoco. Este ADR describe decisiones de diseño orientadas por
esos principios; **no es un análisis de cumplimiento legal**.

## Decisiones
1. **El cálculo ocurre en el navegador.** `frontend/src/exposure/collector.js`
   lee los atributos y calcula los hashes (con un SHA-256 propio, porque
   `crypto.subtle` no existe fuera de https/localhost y la página puede abrirse
   por http en una red local). Ese archivo no hace ninguna request.
2. **Por defecto el servidor no guarda nada.**
   - No hay tabla ni archivo para la exposición (un test recorre todas las tablas
     antes y después de usar los endpoints).
   - `GET /api/exposure/server` devuelve al visitante lo que llegó en su request
     (IP y cabeceras) y lo olvida. Responde con `Cache-Control: no-store`.
   - Logs: el de la api registra solo método, ruta y estado. El de nginx se
     cambió para **todo** el sitio a `fecha método ruta estado` (sin IP, sin
     User-Agent y sin query string) y está **apagado** para `/api/exposure/`.
   - Ningún endpoint de exposición recibe valores por query string; la IP para la
     consulta offline viaja en el cuerpo de un POST.
3. **Nunca se solicita un permiso.** Solo `permissions.query` (estado). Un test
   instala trampas en `getCurrentPosition`, `getUserMedia`,
   `Notification.requestPermission` y `RTCPeerConnection` antes de cargar la
   página y exige que no se toque ninguna.
4. **La IP local no se intenta obtener.** No se usa WebRTC. La página explica que
   los navegadores actuales la ocultan (candidatos mDNS `.local`).
5. **IP honesta.** Se muestra la IP que el servidor observa, etiquetada según su
   tipo: una privada (RFC 1918) se presenta como "IP privada (misma red local)",
   nunca como "IP pública"; la del gateway de Docker o loopback, como "Acceso
   local" y nunca como la IP del visitante (ADR 022). `X-Forwarded-For` solo se acepta del proxy de
   confianza.
6. **Inteligencia IP offline** (`api/app/ipintel.py`, reutilizable en F8): DB-IP
   Lite país + ASN, licencia CC BY 4.0 verificada, con atribución visible. Para
   IPs privadas: "no aplica (red privada)". Solo país y sistema autónomo, nunca
   ciudad ni coordenadas; un dato ausente es "no_disponible".
7. **IP pública solo con opt-in.** Si el servidor ve una IP privada, un botón
   permite consultar `api.ipify.org`, avisando antes que **ese tercero verá la IP
   pública**. No hay consulta automática (un test E2E lo verifica contando las
   requests a otros hosts). Es la única excepción de `connect-src` en la CSP.
8. **Comparación grupal de huellas, opt-in y solo hashes.**
   - Casilla de consentimiento explícita; sin marcarla el botón está deshabilitado
     y el servidor rechaza el envío (`CONSENT_REQUIRED`).
   - Viajan un hash por atributo y el combinado. El servidor rechaza cualquier
     cosa que no sea un sha256 en hexadecimal de un atributo del catálogo
     (`HASHES_ONLY`): un valor en claro enviado por error invalida todo el envío.
   - Los hashes llevan una **sal por grupo** que entrega el servidor: no son
     comparables entre grupos ni con tablas precalculadas.
   - Se guardan en la **memoria del proceso** de la api (sin base de datos), con
     TTL de 2 h (`EXPOSURE_TTL_S`), tope de 500 participantes y rate limit por IP.
     No se guarda la IP junto a los hashes.
   - El administrador puede purgar el grupo con un token
     (`EXPOSURE_PRESENTER_TOKEN`); purgar también cambia la sal.
9. **Texto visible** en la página: qué se recolecta, qué no sale del navegador y
   qué sale (la visita, y los dos opt-in).
10. **La huella combinada no se presenta como única.** La página dice que no se
    puede afirmar su unicidad sin una población de referencia; la comparación grupal de huellas
    solo afirma "única en este grupo".
11. **Cruce con los scans**: por cada atributo se indica qué organizaciones (o
    dominios) lo leyeron o lo enviaron en los scans guardados, con enlace a la
    evidencia. Usa datos de los sitios escaneados, no del visitante.

## Limitaciones y riesgos que quedan
- **Un hash no es anonimato.** Atributos con pocos valores posibles (núcleos de
  CPU, resolución, zona horaria) se pueden revertir probando candidatos, y el
  servidor conoce la sal. La sal y el TTL limitan el daño; no lo eliminan. Por
  eso la participación es opcional y la página lo dice.
- **Mientras dura el grupo, los hashes existen en memoria** y quien administre el
  servidor podría leerlos. Reiniciar la api o purgar los borra.
- **El rate limit guarda en memoria, por hasta un minuto, la IP** de quien envía
  (no asociada a los hashes).
- **La visita en sí expone IP y cabeceras al servidor**, como cualquier página.
  No se guardan, pero el visitante debe confiar en quien opera la instancia.
- **Detrás del NAT de Docker**, las visitas desde el propio equipo llegan con la
  IP del gateway de Docker, no con la real.
- En **contexto no seguro** (http en la LAN, que es el caso del modo demo) el
  navegador oculta varias APIs; la página lo explica, pero un sitio https vería
  más de lo que aquí se muestra.
- El grupo vive en un solo proceso: no sirve con varias réplicas de la api.
- `api.ipify.org` es un tercero fuera de nuestro control; declara no registrar
  visitas, pero eso no se puede verificar.
