#!/bin/sh
# Detecta el gateway y la IP LAN actuales del host y los escribe en .env
# (LAN_GATEWAY, HOST_LAN_IP). Ejecutar antes de los tests SSRF: esos valores
# quedan obsoletos cada vez que el equipo cambia de red.
set -eu

env_file="$(cd "$(dirname "$0")/.." && pwd)/.env"
[ -f "$env_file" ] || { echo "No existe $env_file (copiar .env.example)" >&2; exit 1; }

# `ip route get` devuelve la ruta que usaría el host para salir a internet:
#   1.1.1.1 via <gateway> dev <iface> src <ip-lan> ...
route=$(ip -4 route get 1.1.1.1 2>/dev/null) || { echo "Sin ruta por defecto IPv4" >&2; exit 1; }
gateway=$(printf '%s\n' "$route" | awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}')
host_ip=$(printf '%s\n' "$route" | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')

is_ipv4() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
is_ipv4 "$gateway" || { echo "No se pudo detectar el gateway LAN en: $route" >&2; exit 1; }
is_ipv4 "$host_ip" || { echo "No se pudo detectar la IP LAN en: $route" >&2; exit 1; }

changed=0
set_var() {
    current=$(sed -n "s/^$1=//p" "$env_file" | head -n 1)
    if [ "$current" = "$2" ]; then
        echo "$1=$2 (sin cambios)"
        return
    fi
    if grep -q "^$1=" "$env_file"; then
        sed -i "s/^$1=.*/$1=$2/" "$env_file"
    else
        printf '%s=%s\n' "$1" "$2" >> "$env_file"
    fi
    echo "$1: '${current}' -> '$2'"
    changed=1
}

set_var LAN_GATEWAY "$gateway"
set_var HOST_LAN_IP "$host_ip"

if [ "$changed" = 1 ]; then
    echo "Valores actualizados. Aplicar con: docker compose up -d"
fi
