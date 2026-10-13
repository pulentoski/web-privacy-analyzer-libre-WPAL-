#!/bin/sh
# Helper de autenticación básica de Squid (docs/adr/016).
# No autentica personas: etiqueta cada conexión con el scan que la originó. Acepta cualquier
# usuario con forma "scan-<uuid>" que presente el secreto compartido con el worker.
# Squid entrega "usuario contraseña" por línea; se responde OK o ERR.
while read -r user pass; do
    if printf '%s' "$user" | grep -Eq '^scan-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        && [ -n "${PROXY_SCAN_SECRET:-}" ] && [ "$pass" = "$PROXY_SCAN_SECRET" ]; then
        echo OK
    else
        echo ERR
    fi
done
