# Cómo contribuir

¡Gracias por tu interés! Este es un proyecto de investigación mantenido por una persona; las
contribuciones son bienvenidas dentro de ese contexto.

## Antes de empezar

- Lee `docs/SPEC.md` (la especificación) y, para decisiones de diseño, `docs/adr/`.
- Principio rector: **evidencia > suposición**. Ningún hallazgo sin `level` y `evidence_refs`;
  nunca se inventan datos (si falta, `no_disponible`); los datos del sitio analizado son no
  confiables.

## Flujo

1. Abre un *issue* describiendo el cambio antes de un PR grande.
2. Crea una rama desde `main`.
3. Haz el cambio con pruebas de lo afectado.
4. Ejecuta las pruebas (necesita Docker):

   ```sh
   ./scripts/start.sh --profile test   # levanta el stack de pruebas
   ./scripts/test.sh                   # api, worker (incl. SSRF), frontend y e2e
   ```

5. Verifica el endurecimiento y el escaneo de seguridad si tocas contenedores o dependencias:

   ```sh
   ./scripts/hardening-check.sh --profile test
   ./scripts/security-scan.sh
   ```

6. Envía el PR describiendo qué cambia y por qué, con la salida de las pruebas.

## Reglas de estilo y diseño

- No uses `|| true`, ni saltes pruebas, ni elimines funcionalidades para «pasar».
- El worker **no** sale a internet salvo por el `egress-proxy`. No cambies esto.
- Las decisiones de diseño no triviales se documentan en un ADR (`docs/adr/NNN-titulo.md`).
- Los secretos van solo en `.env`; mantén `.env.example` al día.

## Seguridad

Para reportar una vulnerabilidad, sigue `SECURITY.md` (no abras un issue público con el exploit).
