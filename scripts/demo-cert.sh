#!/bin/sh
# Genera un certificado TLS AUTOFIRMADO para el modo exposición en la red local.
# Lo deja en .demo-certs/ (ignorado por git): la clave privada nunca entra al repositorio.
#
#   ./scripts/demo-cert.sh [IP]      # por defecto, HOST_LAN_IP de .env
#
# Dura 7 días a propósito. Los navegadores mostrarán una advertencia: nadie ha verificado
# este certificado. La huella SHA-256 que imprime sirve para que el público compruebe que
# acepta ESTE certificado y no otro (ver docs/adr/012).
set -eu
cd "$(dirname "$0")/.."

ip="${1:-$(sed -n 's/^HOST_LAN_IP=//p' .env | head -n 1)}"
printf '%s' "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || { echo "IP inválida: '$ip'" >&2; exit 1; }
command -v openssl >/dev/null || { echo "Falta openssl" >&2; exit 1; }

dir=.demo-certs
umask 077
mkdir -p "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 7 \
    -keyout "$dir/demo.key" -out "$dir/demo.crt" \
    -subj "/CN=$ip/O=Web Privacy Analyzer (demo local, autofirmado)" \
    -addext "subjectAltName=IP:$ip,IP:127.0.0.1,DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

# nginx corre sin privilegios (uid 101) y debe poder leer la clave; nadie más.
chmod 700 "$dir"
chmod 600 "$dir/demo.key"
chmod 644 "$dir/demo.crt"
if [ "$(id -u)" = "0" ]; then
    chown -R 101:101 "$dir"
else
    chmod 755 "$dir"; chmod 644 "$dir/demo.key"
    echo "AVISO: sin root no se puede asignar la clave al usuario de nginx; quedó legible para otros usuarios de este equipo." >&2
fi

echo "Certificado autofirmado para $ip (válido 7 días) en $dir/"
openssl x509 -in "$dir/demo.crt" -noout -fingerprint -sha256 -enddate | sed 's/^/  /'
