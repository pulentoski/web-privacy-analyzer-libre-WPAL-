#!/bin/sh
# Indicador de recursos (v1.4): escribe cada N segundos los contadores de cgroup v2 de ESTE
# contenedor (/sys/fs/cgroup, solo lectura) en un archivo JSON. Sin docker.sock.
#   report-resources.sh <archivo de salida> [intervalo en segundos]
out="$1"
interval="${2:-5}"
cg=/sys/fs/cgroup

num() { case "$1" in '' | *[!0-9]*) echo null ;; *) echo "$1" ;; esac; }
field() {
    while read -r key value _; do
        if [ "$key" = "$2" ]; then echo "$value"; return; fi
    done < "$1"
}

while :; do
    read -r ts _ < /proc/uptime
    read -r quota period < "$cg/cpu.max"
    read -r memory < "$cg/memory.current"
    read -r memory_max < "$cg/memory.max"
    read -r pids < "$cg/pids.current"
    read -r pids_max < "$cg/pids.max"
    printf '{"ts":%s,"cpu_usage_usec":%s,"memory_current":%s,"memory_inactive_file":%s,"memory_max":%s,"cpu_quota_usec":%s,"cpu_period_usec":%s,"pids_current":%s,"pids_max":%s}\n' \
        "$ts" "$(num "$(field "$cg/cpu.stat" usage_usec)")" "$(num "$memory")" "$(num "$(field "$cg/memory.stat" inactive_file)")" \
        "$(num "$memory_max")" "$(num "$quota")" "$(num "$period")" "$(num "$pids")" "$(num "$pids_max")" > "$out.tmp" \
        && mv "$out.tmp" "$out"
    sleep "$interval"
done
