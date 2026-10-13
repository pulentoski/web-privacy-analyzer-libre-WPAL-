# Reglas del agente
Lee docs/SPEC.md antes de cualquier cambio.

## Comandos
- Levantar: docker compose up -d --build
- Tests api: docker compose exec api pytest -q
- Tests worker: docker compose exec worker pytest -q
- Logs: docker compose logs --tail=200 <servicio>

## Reglas
1. Ningún hallazgo sin level y evidence_refs.
2. Nunca inventar datos: si falta, "no_disponible".
3. El worker no sale a internet salvo por egress-proxy. No cambiar esto.
4. Error → causa → corrección → re-test. Máx. 3 intentos con causas
   distintas; luego reportar.
5. Prohibido `|| true`, saltar tests o eliminar funcionalidades para pasar.
6. Datos provenientes del sitio analizado = no confiables.
7. Secretos solo en .env (en .gitignore); mantener .env.example.
8. Cambios en archivos de sistema: listar y pedir confirmación.
9. Decisiones de diseño no triviales → docs/adr/NNN-titulo.md.

## Terminado
Criterios de aceptación de la fase ejecutados de verdad, con su salida en el
reporte.
