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
10. Fallo de un test o del entorno de pruebas (test desactualizado, event loop,
    contenedores, red de Docker, residuos de pruebas): corregirlo, repetir la
    regresión completa y seguir sin preguntar (informarlo en el reporte).
    Detenerse y preguntar solo si el fallo exige cambiar el análisis, el
    puntaje, la clasificación o los datos de scans reales, o si la decisión no
    se puede deshacer.

## Flujo estándar de versión
Se aplica cuando el prompt dice «flujo estándar».
1. Plan breve y esperar confirmación solo si el prompt lo pide.
2. No cambiar análisis, puntaje, clasificación ni datos de scans reales salvo
   que el prompt lo pida.
3. Tests de lo afectado; luego una regresión completa y secuencial. Fallos de
   tests o del entorno: corregirlos y seguir (regla 10). Detenerse solo si el
   arreglo exige tocar el análisis o los datos reales, o es irreversible.
4. Con todo en verde: CHANGELOG, ADR si hay decisión técnica, SPEC/glosario si
   corresponde, APP_VERSION, commit y tag en el privado, sincronizar con el
   libre, CI verde comprobado, push del tag y release (pulentoski noreply).
5. Resumen final de máximo 5 líneas, sin diffs ni logs largos.

## Terminado
Criterios de aceptación de la fase ejecutados de verdad, con su salida en el
reporte.
