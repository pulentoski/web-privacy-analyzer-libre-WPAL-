#!/bin/sh
# Verifica el endurecimiento de cada contenedor EN EJECUCIÓN (no lo que dice el compose) e
# imprime una tabla Markdown. Sale con error si alguna fila no cumple.
#   ./scripts/hardening-check.sh [--profile test]
set -eu
cd "$(dirname "$0")/.."
bad=0
echo "| Servicio | Usuario (uid) | cap_drop | no-new-privileges | Raíz solo lectura | Memoria | CPU | pids | Healthcheck | Estado |"
echo "|---|---|---|---|---|---|---|---|---|---|"
for service in $(docker compose "$@" ps --services | sort); do
    id=$(docker compose "$@" ps -q "$service")
    uid=$(docker exec "$id" id -u)
    user=$(docker exec "$id" id -un 2>/dev/null || echo "?")
    caps=$(docker inspect -f '{{join .HostConfig.CapDrop ","}}' "$id")
    added=$(docker inspect -f '{{join .HostConfig.CapAdd ","}}' "$id")
    nnp=$(docker inspect -f '{{range .HostConfig.SecurityOpt}}{{.}} {{end}}' "$id" | grep -c 'no-new-privileges:true' || :)
    ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id")
    mem=$(docker inspect -f '{{.HostConfig.Memory}}' "$id")
    cpu=$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$id")
    pids=$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$id")
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}sin healthcheck{{end}}' "$id")
    priv=$(docker inspect -f '{{.HostConfig.Privileged}}' "$id")
    # v1.4: el indicador de recursos lee cgroups; ningún contenedor monta el socket de Docker.
    sock=$(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$id" | grep -c 'docker.sock' || :)
    ok=OK
    [ "$sock" = "0" ] || { ok="REVISAR (docker.sock)"; bad=1; }
    [ "$uid" != "0" ] && [ "$caps" = "ALL" ] && [ -z "$added" ] && [ "$nnp" = "1" ] && [ "$ro" = "true" ] && [ "$mem" -gt 0 ] \
        && [ "$cpu" -gt 0 ] && [ "$pids" -gt 0 ] && [ "$health" = "healthy" ] && [ "$priv" = "false" ] || { [ "$ok" = OK ] && ok=REVISAR; bad=1; }
    echo "| $service | $user ($uid) | $caps | $([ "$nnp" = 1 ] && echo sí || echo NO) | $([ "$ro" = true ] && echo sí || echo NO) | $((mem / 1048576)) MiB | $(awk "BEGIN{print $cpu/1000000000}") | $pids | $health | $ok |"
done
exit $bad
