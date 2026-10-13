#!/bin/sh
# Expone la interfaz en la red local para una demo. Por defecto todo escucha solo en
# 127.0.0.1; esta es la única forma de publicarlo.
#
#   DEMO_MODE=exposure ./scripts/demo.sh   # SOLO "Mi exposición": http :8088 y https :8443
#   DEMO_MODE=1 ./scripts/demo.sh          # interfaz COMPLETA en :8080 (permite lanzar scans)
#   ./scripts/demo.sh down                 # vuelve a solo-loopback
#
# DEMO_BIND cambia la dirección (por defecto HOST_LAN_IP de .env).
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" = "down" ]; then
    # La api vuelve a arrancar sin DEMO_MODE (el borrado del historial queda habilitado otra vez).
    DEMO_MODE=0 docker compose up -d --wait api frontend
    echo "Frontend de nuevo solo en 127.0.0.1:${FRONTEND_PORT:-8080}"
    exit 0
fi

mode="${DEMO_MODE:-0}"
case "$mode" in
    1|exposure) ;;
    *) echo "Modo demo desactivado. Usar DEMO_MODE=exposure (recomendado para demostraciones) o DEMO_MODE=1 (interfaz completa)." >&2; exit 1 ;;
esac

./scripts/refresh-lan-env.sh >/dev/null
bind="${DEMO_BIND:-$(sed -n 's/^HOST_LAN_IP=//p' .env | head -n 1)}"
[ -n "$bind" ] || { echo "No se pudo determinar la IP LAN (HOST_LAN_IP en .env)" >&2; exit 1; }

if [ "$mode" = "exposure" ]; then
    # Certificado nuevo si no hay, si es para otra IP o si vence en menos de un día.
    if ! openssl x509 -in .demo-certs/demo.crt -noout -checkend 86400 -checkip "$bind" 2>/dev/null | grep -q "does match"; then
        ./scripts/demo-cert.sh "$bind"
    fi
    cat >&2 <<AVISO
MODO EXPOSICION: en la red local queda accesible SOLO la página "Mi exposición":
    https://$bind:${EXPOSURE_HTTPS_PORT:-8443}/   (contexto seguro; el navegador advertirá del certificado autofirmado)
    http://$bind:${EXPOSURE_HTTP_PORT:-8088}/    (sin advertencia, pero el navegador oculta algunas APIs)
  - Desde la red local NO se pueden lanzar scans ni ver resultados (la API de scans responde 403).
  - La interfaz completa sigue solo en http://127.0.0.1:${FRONTEND_PORT:-8080}
  - Huella del certificado, para que el público la compare antes de aceptarlo:
$(openssl x509 -in .demo-certs/demo.crt -noout -fingerprint -sha256 | sed 's/^/      /')
  - Para terminar: $0 down
AVISO
    # La api arranca con DEMO_MODE: mientras dure la demo no se puede borrar el historial.
    DEMO_MODE="$mode" DEMO_BIND="$bind" docker compose -f docker-compose.yml -f docker-compose.exposure.yml up -d --wait api frontend
else
    cat >&2 <<AVISO
ATENCION: la interfaz COMPLETA quedará accesible desde la red local en http://$bind:${FRONTEND_PORT:-8080}
  - No tiene autenticación: cualquiera en esa red puede lanzar scans y ver los resultados.
  - Para una demostración es preferible DEMO_MODE=exposure, que solo publica "Mi exposición".
  - Para volver a solo-loopback: $0 down
AVISO
    DEMO_MODE="$mode" DEMO_BIND="$bind" docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --wait api frontend
fi
