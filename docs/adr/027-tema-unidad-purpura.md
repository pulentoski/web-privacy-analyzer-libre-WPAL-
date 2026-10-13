# ADR 027 — Tema «Unidad Púrpura» en lugar del tema Cómic

Estado: aceptada · Fecha: 2026-10-10

## Contexto
El tema opcional era «Cómic» (Bangers + Comic Neue, contornos gruesos, semitono). Se pide
reemplazarlo por un tema oscuro con estética de interfaz de mando: el selector queda
Clásico / Unidad Púrpura y Clásico sigue por defecto.

## Decisiones
1. **Diseño original.** Solo color, líneas finas, esquinas cortadas, franjas diagonales y
   tipografía. Sin personajes, robots, logos, nombres ni frases de ninguna serie o franquicia, y
   sin textos añadidos: la interfaz dice lo mismo en los dos temas.
2. **Paleta**: fondo `#0b0614`, superficies `#150b26` / `#1e1036`, morado `#4b1f7a` / `#6b2fb3`
   (líneas y acción principal), verde neón `#7cff4f` (estado activo, enlaces y valores capturados),
   naranja `#ff7a1a` (alertas, banda «Alto» y franjas de aviso), rojo `#c8102e` solo para la banda
   «Muy alto».
3. **Sin imágenes en el CSS.** La cuadrícula hexagonal y las franjas son gradientes
   (`conic-gradient`, `repeating-linear-gradient`): la CSP no cambia y no hay `data:` en estilos.
4. **Esquinas cortadas sin `clip-path` en los paneles.** Se dibujan con pseudo-elementos del color
   del fondo, porque `clip-path` recortaría los tooltips del glosario. Los botones sí usan
   `clip-path`; su foco se dibuja por dentro.
5. **Colores de utilidad remapeados** (`html[data-theme="purple"] .bg-amber-50 …`) en vez de tocar
   cada componente: badges de nivel, bandas y avisos conservan su significado y el tema clásico no
   cambia. Las bandas llevan `data-band` para sus colores propios.
6. **Lo capturado no se transforma**: `.captured` anula mayúsculas y espaciado (una URL distingue
   mayúsculas) y usa la fuente monoespaciada.
7. **Tipografías OFL locales**: Barlow Condensed (títulos) y JetBrains Mono (valores capturados),
   paquetes `@fontsource` con versión fija; `font-src 'self'`. Bangers y Comic Neue se eliminan.
8. **Migración**: una preferencia guardada `comic` se lee como `purple` y se reescribe.
9. **Modo presentación**: en Clásico sigue siendo negro sobre blanco; en Unidad Púrpura conserva el
   fondo oscuro con texto secundario y líneas más claros.
10. **Reportes PDF/HTML sin tema**: siguen sobrios; los tests comprueban que no llevan fuentes ni
    colores del tema.

## Consecuencias
- Un color de utilidad nuevo en un componente necesita su equivalente en el bloque del tema; la
  E2E de contraste AA (ambos temas, con y sin presentación, todas las vistas) lo detecta.
- Las ilustraciones y el logo son oscuros sobre blanco: conservan su marco o círculo blanco.

## Ajuste v1.3.3
- **Títulos de panel con franja de advertencia** (`.panel-head` en `Panel` y en la barra de progreso):
  mismo lenguaje que «Límites de la medición». Tono por `data-tone`: naranja por defecto, rojo para
  avisos de bloqueo y scans fallidos, morado con verde para paneles anidados (evita saturar de naranja).
  La franja queda sobre el texto, no detrás: el contraste AA se mide contra el fondo liso. Sin
  `clip-path` en el título (recortaría los tooltips); la esquina cortada es la del panel.
- **Ilustración giratoria** durante el scan o la importación de HAR: `<picture>` local, circular,
  `animation` CSS; el componente solo se monta mientras el proceso corre. Con
  `prefers-reduced-motion: reduce` se cambia el giro por un pulso de opacidad. En Clásico, borde gris.
