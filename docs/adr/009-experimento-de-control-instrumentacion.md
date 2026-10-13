# ADR 009 — ¿La instrumentación cambia el comportamiento del sitio? Experimento de control

Estado: aceptado · Fase: F5

## Contexto
En F4, el scan instrumentado de biobiochile.cl vio 23 dominios de terceros,
contra 47 del scan de F3 (sin instrumentación). Quedó la duda de si la
instrumentación de fingerprinting (ADR 007) altera lo que hace el sitio.

## Método
- 6 scans de https://www.biobiochile.cl, alternando: sin instrumentación
  (`options.fp_instrumentation=false`) y con ella, 3 de cada uno, en ese orden.
- Todos con el perfil base nuevo (ADR 008), el mismo worker y la misma red,
  entre las 23:52 y las 23:56 UTC del 2026-10-06.
- Excepción justificada a la regla de "un solo scan" por sitio.

## Resultados

| # | Instrumentación | Requests | Dominios de terceros | Requests de tracking | Duración |
|---|---|---|---|---|---|
| 1 | no | 409 | 23 | 75 | 19,0 s |
| 2 | sí | 406 | 23 | 92 | 14,0 s |
| 3 | no | 765 | 56 | 329 | 47,1 s |
| 4 | sí | 977 | 111 | 526 | 50,1 s |
| 5 | no | 414 | 23 | 72 | 17,8 s |
| 6 | sí | 809 | 61 | 391 | 58,3 s |

| Métrica | Sin instrumentación: media (rango) | Con instrumentación: media (rango) |
|---|---|---|
| Requests totales | 529 (409–765) | 731 (406–977) |
| Dominios de terceros | 34 (23–56) | 65 (23–111) |
| Requests de tracking | 159 (72–329) | 336 (92–526) |

## Conclusión
**No hay evidencia de que la instrumentación reduzca o altere la actividad del
sitio.**

- El sitio es **bimodal por sí solo**: hay visitas "cortas" (~410 requests, 23
  dominios de terceros, 14–19 s) y "largas" (765–977 requests, 56–111 dominios,
  47–58 s). Los dos modos aparecen en **ambos** brazos: sin instrumentación
  (corta, larga, corta) y con ella (corta, larga, larga).
- Los rangos de los dos brazos se solapan por completo y el valor de 23 dominios
  que motivó la duda aparece tres veces, dos de ellas sin instrumentación.
- La media del brazo instrumentado es *mayor*, no menor; con 3 scans por brazo y
  esta dispersión, esa diferencia no es interpretable.

La diferencia observada en F4 se explica por la variación propia del sitio
(probablemente si se dispara o no la subasta publicitaria y el vídeo), no por la
instrumentación. No se cambió nada en ella.

## Limitaciones de este experimento
- n = 3 por brazo: no permite descartar un efecto pequeño, solo uno grande y
  sistemático.
- Un solo sitio, una sola franja horaria.
- No se identificó qué decide entre la visita corta y la larga.

## Consecuencias
- **Un scan aislado de un sitio con publicidad programática no es
  representativo**: dos visitas seguidas pueden diferir en más del doble. La
  interfaz lo advierte ("una sola visita") y el reporte lo lista como limitación.
  Para comparar sitios o fechas hay que repetir scans y mirar rangos.
- Las visitas largas rozan `SCAN_TIMEOUT_S` (60 s): con un límite menor se
  cortarían.
- La opción `options.fp_instrumentation` del `POST /api/scans` queda disponible
  para repetir el control.
