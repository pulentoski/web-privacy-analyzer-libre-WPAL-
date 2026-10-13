#!/bin/sh
set -eu

: "${UPSTREAM_DNS:?UPSTREAM_DNS no está definido (ver .env.example)}"

# Una o más IPv4 separadas por espacios o comas. Se validan porque el valor se
# inserta en la configuración.
servers=$(printf '%s' "$UPSTREAM_DNS" | tr ',' ' ')
for server in $servers; do
    if ! printf '%s' "$server" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        echo "UPSTREAM_DNS debe contener solo direcciones IPv4: '$server'" >&2
        exit 1
    fi
done
[ -n "$servers" ] || { echo "UPSTREAM_DNS está vacío" >&2; exit 1; }

is_ipv4() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }

# Sitio de fixtures de los tests (docs/adr/003): solo con ALLOW_FIXTURES=1.
if [ "${ALLOW_FIXTURES:-0}" = "1" ]; then
    : "${FIXTURES_IP:?ALLOW_FIXTURES=1 requiere FIXTURES_IP}"
    is_ipv4 "$FIXTURES_IP" || { echo "FIXTURES_IP no es una IPv4: '$FIXTURES_IP'" >&2; exit 1; }
    printf '%s site.fixtures.test tracker-a.fixtures.test cdn-b.fixtures.test metrics.site.fixtures.test\n' "$FIXTURES_IP" > /tmp/fixtures-hosts
    fixtures_sed='/^@FIXTURES_OFF@/d; s/^@FIXTURES_ON@ //'
    echo "ALLOW_FIXTURES=1: sitio de fixtures permitido en $FIXTURES_IP (solo para tests)" >&2
else
    fixtures_sed='/^@FIXTURES_ON@/d; s/^@FIXTURES_OFF@ //'
fi

sed -e "s/__UPSTREAM_DNS__/$(echo $servers)/" -e "s/__FIXTURES_IP__/${FIXTURES_IP:-}/" -e "$fixtures_sed" \
    /etc/squid/squid.conf.template > /tmp/squid.conf
squid -f /tmp/squid.conf -k parse >/dev/null 2>&1 || {
    squid -f /tmp/squid.conf -k parse
    exit 1
}
# Logs de scans creados por una versión anterior (0640): el worker no podría leerlos.
for scanlog in /var/log/scanlog/access.jsonl*; do
    if [ -e "$scanlog" ]; then chmod 644 "$scanlog"; fi
done
# Rotación del log de scans: al pasar de SCANLOG_MAX_BYTES se rota y se conservan 5
# generaciones (rotate=5 en squid.conf). Retención máxima: unas 6 veces ese tamaño.
max_bytes="${SCANLOG_MAX_BYTES:-20000000}"
(
    while sleep "${SCANLOG_CHECK_S:-300}"; do
        size=$(stat -c %s /var/log/scanlog/access.jsonl 2>/dev/null || echo 0)
        if [ "$size" -gt "$max_bytes" ]; then
            squid -f /tmp/squid.conf -k rotate || echo "scanlog: la rotación falló; se reintenta en el próximo ciclo" >&2
        fi
    done
) &

# Indicador de recursos (v1.4): la api no comparte red con el proxy, así que la muestra va al
# volumen del log de scans y el worker la reenvía.
/usr/local/bin/report-resources.sh /var/log/scanlog/resources-egress-proxy.json 5 &

# -N: en primer plano, sin proceso maestro. -C: no capturar señales fatales.
exec squid -f /tmp/squid.conf -NYC
