# ADR 031 — El indicador de recursos reserva su hueco y se puede minimizar (v1.4.3)

Estado: aceptada · Fecha: 2026-10-13

## Contexto
El indicador de recursos (ADR 029) es una consola fija en la esquina inferior de todas las páginas. En
páginas largas tapaba el último tramo del contenido: el pie quedaba debajo de la consola y no se podía leer
ni pulsar. El `padding-bottom` fijo (`4.5rem`) no se correspondía con el alto real de la consola, que cambia
entre la versión mini, la vista completa y los dos temas.

## Decisiones
1. **El contenido reserva un hueco igual al alto de la consola.** `ResourceIndicator` mide con un
   `ResizeObserver` el alto del pie persistente (la consola mini o, minimizada, el ícono) y publica
   `--rc-reserved` en `:root`. El contenido (`.app-main`) usa `padding-bottom: var(--rc-reserved, 4.5rem)`,
   con el valor anterior como respaldo para el arranque y para cuando no hay indicador (modo demo, fallo de
   `/api/resources`). Se mide solo el pie persistente, no la vista completa desplegada: esa se abre por
   encima y tiene su propio desplazamiento, y reservar su alto empujaría el contenido sin motivo.
2. **La consola se puede minimizar a un ícono.** Un botón «—» la colapsa a un cuadrado pequeño en la misma
   esquina; el ícono la restaura. Minimizada, el hueco reservado se achica solo. La alerta de RAM sigue
   visible como punto sobre el ícono.
3. **La preferencia se recuerda en localStorage** (`resources-minimized`), con `try/catch` en lectura y
   escritura: si el almacenamiento no está disponible, la interfaz funciona igual y la preferencia dura lo
   que dure la pestaña. Mismo criterio que el modo presentación (App.jsx).
4. **Ambos temas.** Los controles nuevos usan los tokens de color ya definidos para la consola (clásico y
   Unidad Púrpura); no se añaden colores nuevos.

## Consecuencias
- Prueba e2e (`test_v143.py`): en Panel, Analizar (simple y avanzado), Historial, Glosario y un scan, con un
  viewport bajo a propósito, el último elemento de cada ruta queda a la vista y su centro hace hit-test a sí
  mismo, no a la consola; y la consola se minimiza, recuerda la elección al navegar y restaura. En ambos temas.
- Pruebas unitarias (`v142.test.jsx`): minimizar/restaurar, persistencia en localStorage y lectura tolerante a
  fallo del almacenamiento.
- No cambia `GET /api/resources`, ni el sondeo cada 5 s con la pestaña visible, ni el aviso sobre 85 %.
