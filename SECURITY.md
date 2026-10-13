# Política de seguridad

## Alcance y naturaleza

Esta es una **herramienta de investigación (beta)** para analizar la recolección de datos de
sitios web. Está pensada para ejecutarse **solo en `127.0.0.1`** (localhost), sin autenticación.
**No la expongas a internet ni a una red no confiable.** El modo demo en LAN
(`scripts/demo.sh`, `DEMO_MODE=1`) publica únicamente la página «Mi exposición».

El worker solo sale a internet a través del `egress-proxy` (Squid), que valida la IP resuelta en
cada conexión como defensa contra SSRF (ver `docs/THREAT-MODEL.md` y `docs/SPEC.md §Seguridad`).

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad:

1. **No** abras un issue público con los detalles de explotación.
2. Avisa de forma privada al autor a través de GitHub (mensaje privado o un *security advisory*
   en el repositorio: pestaña **Security → Report a vulnerability**).
3. Incluye: versión, pasos para reproducir, impacto y, si lo tienes, una propuesta de mitigación.
   Describe la *clase* del problema; no publiques un exploit funcional.

Se responderá lo antes posible. Al tratarse de un proyecto mantenido por una sola persona, no
hay un SLA formal.

## Buenas prácticas al usarla

- Mantén los secretos solo en `.env` (nunca los subas; está en `.gitignore`).
- No inicies sesión con cuentas reales en la **captura interactiva**: las cookies de una sesión
  iniciada quedan guardadas en la captura.
- Revisa los reportes antes de compartirlos (los identificadores van enmascarados por defecto).
- Ejecuta `./scripts/security-scan.sh` (pip-audit, npm audit, Trivy, gitleaks) y
  `./scripts/hardening-check.sh` para verificar el endurecimiento de los contenedores.
