# ADR 035 — Navegación con frame ACCEPT_CH, scans fallidos y parciales, alerta antibot con señal dura y correcciones de reglas (v1.4.8)

Estado: aceptada · Fecha: 2026-10-15 · Modifica [ADR 024](024-terceros-por-organizacion-y-representatividad.md) y [ADR 026](026-antibot-200-e-indice-parcial-del-har.md) (regla de «visita posiblemente bloqueada»)

## Contexto
- music.youtube.com (y en ese momento también www.youtube.com y www.google.com) fallaba con `NAVIGATION_TIMEOUT` y una
  sola request, también en la captura interactiva. curl por el egress-proxy respondía 200 en menos de 1 s; Squid
  registraba `TCP_TUNNEL/200` sin denegaciones. El net-log de Chromium mostró TLS y HTTP/2 completos, la recepción de
  un frame `ACCEPT_CH` (Client Hints por ALPS) y la navegación terminada en `URL_REQUEST_DELEGATE_CONNECTED` con
  `net_error -3` (`ERR_ABORTED`): Chromium reinicia la request para enviar los hints pedidos y ese reinicio queda
  abortado sin avisar a Playwright, que espera hasta el timeout. Con `--disable-features=AcceptCHFrame` las tres
  esperas (`commit`, `domcontentloaded`, `load`) llegan en segundos.
- Un scan fallido guarda lo capturado (1 request) y se analizaba como cualquier otro: la interfaz mostraba índice 0,
  «Nada observado ni inferido» y la alerta «el sitio pudo detectar el navegador automatizado» por pocas requests.
  Nada de eso es una medición del sitio.
- La alerta también saltaba por pocas requests o por rastreo anómalo, que no prueban un bloqueo.

## Decisiones
1. **`--disable-features=AcceptCHFrame`** en `CHROMIUM_ARGS` (`worker/app/browser/launcher.py`): vale para el scan y
   para la captura interactiva, que usan el mismo `launch_kwargs`. Debe haber un solo `--disable-features` (Chromium
   se queda con el último).
2. **Scan fallido = «Sin medición».** El error guarda `net_error`, el código `net::ERR_*` real de Chromium (del
   mensaje de `goto` o del `requestfailed` del documento principal); `null` si no hubo (p. ej. tiempo agotado sin
   respuesta). La api lo expone (`failure`, `measured`, y en jobs anteriores lo busca en el mensaje); la interfaz no
   muestra índice, resumen ni pestañas que digan «no se observó», sino el motivo, el código y las requests capturadas
   antes del fallo. Historial: «Sin medición». Reporte: `scan.failure` (schema `report-1.8.0`).
3. **Scan parcial.** Si `goto` agota el tiempo pero ya hubo respuestas (p. ej. una redirección respondida y un
   destino que no contesta), el scan no falla: termina con `result.partial` (`navigation_timeout`, requests,
   respuestas, `net_error`) y `end_reason = navigation_timeout_partial`, y se analiza con el aviso «Scan parcial».
   No corre el escenario de consentimiento (ya no queda tiempo). En la captura interactiva, la sesión sigue abierta.
4. **Alerta antibot solo con señal dura**: estado 403/429/503, título de desafío o firma antibot en la URL marcan la
   visita («el sitio pudo detectar el navegador automatizado») y la excluyen del ranking. Pocas requests o rastreo
   anómalo sin señal dura dejan una nota de nivel POSIBLE (`blocking.possible_variant`): «La página podría haber
   mostrado una versión distinta al navegador automatizado; compare con un HAR propio.», sin excluir del ranking.
   Con señal dura, las blandas acompañan como detalle. Nunca hay veredicto en un scan fallido, en una captura
   interactiva ni en un HAR (`not_applicable`); en un scan parcial no cuentan las señales blandas (el corte las explica).

### Correcciones de reglas (segunda parte de v1.4.8)
5. **Bandas: única fuente `data/scoring.yaml`.** La banda 21–40 se llamaba «Posible», igual que el nivel de evidencia
   POSIBLE: ome.tv (índice 37) aparecía como «Posible» y se leía como un nivel. Se renombra a **«Bajo-moderado»**. La
   api lee nombres y orden de `scoring.yaml` (`app/bands.py`) en vez de repetirlos; el frontend conserva su lista y un
   test la compara con el archivo. El schema `report-1.8.0` lleva el nombre nuevo. Valen para requests y para el índice.
6. **Servicios de terceros sin señales de rastreo**: no entran las organizaciones cuyo tipo de servicio es de
   publicidad o de analítica (mismos grupos que `cookie_purposes.yaml §by_service_type`), aunque esa request no llegue
   a la banda de rastreador; se cuentan en `third_party_services.excluded_requests`.
7. **Fuga de búsqueda**: no se informa si el valor es igual al título, a la meta description o a una meta keyword de
   la página (normalizado). El worker guarda ahora `result.page_meta` (description y keywords, texto acotado); los scans
   anteriores solo tienen el título, así que con `reanalyze.sh` el filtro usa solo el título. Descartes en
   `summary.search_leaks_page_text`.
8. **Servidor CAPI de Meta**: un host de nube inferido como Conversions API cuenta como el dominio de Meta
   (`server_side_tracking.yaml §meta.owner_domain`) en la sincronización (dueño) y en los componentes del índice que
   cuentan dominios; se muestra como «Meta (vía servidor CAPI, inferencia)». La detección se hace antes de buscar
   sincronización.
9. **Fuga de URL**: el valor debe contener la URL de la página entera (origen y ruta), seguida del fin del valor o de
   un separador (`?`, `#`, `&`, `=`, comillas…). «https://sitio/otra-ruta» en la portada o «https://sitio.otro.example»
   son coincidencias parciales y ya no cuentan. En airbnb.cl, el `event_id` de Pinterest
   (`…_https://www.airbnb.cl/`, con la portada como página) contiene la URL entera y **se sigue informando**.
10. **Catálogo**: Liferay (`lfr.cloud`, `liferay.com`; tipo `cms_analytics`, «plataforma CMS/analítica», que cuenta
    como analítica), Podscribe (`pdscrb.com`; tipo `ad_attribution`, publicidad), alias INACAP (`inacap.cl`,
    `inacapmovil.cl`). Las cookies `l` y `cna` se clasifican por el nombre solo si son de alibaba.com, aliexpress.com,
    alicdn.com o mmstat.com (`cookie_purposes.yaml §name_domains`).
11. **WebRTC** (grupo 2): además de la creación de `RTCPeerConnection`, la instrumentación envuelve el getter
    `RTCPeerConnectionIceEvent.candidate` (cubre `onicecandidate` y `addEventListener`) y anota solo el TIPO de
    dirección de cada candidato leído (IP local, IP pública, nombre mDNS), nunca la dirección. Hallazgos EVIDENCIA:
    `webrtc_connection` (la página creó conexiones) y `webrtc_ice_exposed` (recibió candidatos con IP local o pública).
    `webrtc_ip_discovery` sigue como INFERENCIA del propósito. Con la política del worker
    (`disable_non_proxied_udp`) los candidatos con IP casi nunca aparecen en un scan.
12. Test e2e de consentimiento: espera a que la imagen del banner termine de cargar antes de medirla (era intermitente).

## Efecto en la medición
- Sin el frame, el navegador no envía en la **primera** request de cada origen los Client Hints de alta entropía
  que el servidor pide por ALPS (`Sec-CH-UA-Arch`, `-Bitness`, `-Model`, `-Full-Version-List`, `-Platform-Version`,
  `-WoW64`). Los sigue enviando desde la siguiente request, porque la cabecera `Accept-CH` de la respuesta sigue
  activa. Un Chrome normal los mandaría ya en la primera; la diferencia es de una request por origen.

## Alternativa pendiente
- Revisar si el aborto lo causa la interceptación de requests de Playwright (`Fetch` para la autenticación del proxy)
  y no Chromium en sí. Si fuera así, se podría quitar el flag autenticando el proxy de otra forma (p. ej. por IP de la
  red `sandbox`, perdiendo la atribución por scan del ADR 016) o cuando Playwright lo corrija.

## Consecuencias
- Bandas renombradas: los análisis guardados con «Posible» se corrigen con `reanalyze.sh --all`.
- Analizador 1.15.0; `reanalyze.sh --all` aplica la regla nueva de la alerta a los scans guardados.
- Scans que antes salían «posiblemente bloqueados» solo por pocas requests o rastreo anómalo vuelven al ranking del
  Panel, con la nota POSIBLE.
