#!/bin/bash
# OPS: monitoring poligonu NXMS — Prometheus + Grafana + cAdvisor + node-exporter
# + nxms-exporter (metryki domenowe: zadania, laby, Monero, kopanie).
#
# Wszystkie kontenery dzialaja w trybie host network; targety skraplania to
# 127.0.0.1. Konfiguracja i dashboardy z deploy/monitor/ (wolumeny nazwane
# trzymaja dane Prometheus/Grafana miedzy uruchomieniami).
#
# Usage: sudo bash tools/nxms-monitor.sh {up|status|down}
#   Grafana:   http://127.0.0.1:3000  (admin / haslo z NXMS_GRAFANA_PASSWORD)
#   Prometheus:http://127.0.0.1:9090
#   Metryki:   http://127.0.0.1:9105/metrics
# Legacy: nie zastepuje dashboardu NXMS (apps/nexum-dashboard) — to narzedzie
# operacyjne od pomiarow; widok "Pomiary" w dashboardzie linkuje do Grafany.
set -u

die() { printf 'nxms-monitor: %s\n' "$*" >&2; exit 1; }

dock() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
self=$(readlink -f -- "$0")
workspace=$(cd -- "$(dirname -- "$self")/.." && pwd -P)
monitor_dir=$workspace/deploy/monitor
label=io.nexum.monitor.workspace
grafana_password=${NXMS_GRAFANA_PASSWORD:-nexum-lab-2026}

action=${1:-}
case "$action" in up|status|down) ;; -h|--help|help) sed -n '2,16p' "$0"; exit 0 ;; *) echo "Usage: sudo bash tools/nxms-monitor.sh {up|status|down}"; exit 2 ;; esac
command -v docker >/dev/null 2>&1 || die 'brak docker.'
dock info >/dev/null 2>&1 || die 'brak dostepu do lokalnego API Dockera (uzyj sudo).'
[ -d "$monitor_dir" ] || die "brak konfiguracji: $monitor_dir"

docker_root=$(dock info --format '{{.DockerRootDir}}') || die 'nie mozna ustalic DockerRootDir.'
state_base=$HOME/.local/share
install -d -m 0755 "$state_base/nxms-tasks" "$state_base/nxms-lab" 2>/dev/null || true

containers="nxms-monitor-node nxms-monitor-cadvisor nxms-monitor-exporter nxms-monitor-prom nxms-monitor-grafana"

is_running() { [ "$(dock container inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

run_if_absent() { # run_if_absent <nazwa> <opis> <docker run...>
    local name=$1; shift; shift
    if dock container inspect "$name" >/dev/null 2>&1; then
        is_running "$name" || dock start "$name" >/dev/null
    else
        dock run -d --name "$name" --label "$label=$workspace" "$@" >/dev/null || die "nie udalo sie uruchomic $name"
    fi
    printf '%-22s %s\n' "$name" "$(is_running "$name" && echo running || echo stopped)"
}

case "$action" in
    up)
        run_if_absent nxms-monitor-node "node-exporter" \
            --network host --restart unless-stopped --security-opt no-new-privileges \
            --mount "type=bind,source=/,target=/host,readonly" \
            prom/node-exporter:latest --path.rootfs=/host

        run_if_absent nxms-monitor-cadvisor "cAdvisor" \
            --network host --restart unless-stopped \
            --privileged --device /dev/kmsg \
            -v /:/rootfs:ro -v /var/run:/var/run:ro -v /sys:/sys:ro \
            -v "$docker_root":/var/lib/docker:ro -v /dev/disk/:/dev/disk:ro \
            gcr.io/cadvisor/cadvisor:latest -port 8090

        run_if_absent nxms-monitor-exporter "nxms-exporter" \
            --network host --restart unless-stopped --security-opt no-new-privileges \
            -e NXMS_TASKS_STATE=/state/nxms-tasks \
            -e NXMS_LAB_STATE=/state/nxms-lab/lab.json \
            -e NXMS_MONITOR_DAEMON=http://127.0.0.1:38081 \
            -e NXMS_EXPORTER_PORT=9105 \
            --mount "type=bind,source=$state_base,target=/state,readonly" \
            --mount "type=bind,source=$monitor_dir/nxms-exporter.py,target=/opt/nxms-exporter.py,readonly" \
            alpine:3.23 sh -c 'apk add --no-cache python3 >/dev/null 2>&1 && exec python3 /opt/nxms-exporter.py'

        run_if_absent nxms-monitor-prom "prometheus" \
            --network host --restart unless-stopped --security-opt no-new-privileges \
            --mount "type=bind,source=$monitor_dir/prometheus.yml,target=/etc/prometheus/prometheus.yml,readonly" \
            -v nxms-monitor-prom-data:/prometheus \
            prom/prometheus:latest

        run_if_absent nxms-monitor-grafana "grafana" \
            --network host --restart unless-stopped --security-opt no-new-privileges \
            -e GF_SECURITY_ADMIN_PASSWORD="$grafana_password" \
            -e GF_USERS_ALLOW_SIGN_UP=false \
            --mount "type=bind,source=$monitor_dir/grafana/provisioning,target=/etc/grafana/provisioning,readonly" \
            -v nxms-monitor-grafana-data:/var/lib/grafana \
            grafana/grafana:latest

        printf '\nGrafana: http://127.0.0.1:3000 (admin / %s)\nPrometheus: http://127.0.0.1:9090\nMetryki NXMS: http://127.0.0.1:9105/metrics\n' "$grafana_password"
        ;;
    status)
        for name in $containers; do
            printf '%-22s %s\n' "$name" "$(is_running "$name" && echo running || echo stopped)"
        done
        curl -s -m 5 http://127.0.0.1:9105/metrics 2>/dev/null | grep -c '^nxms_' | sed 's/^/metryki nxms_ (liczba probek): /'
        ;;
    down)
        for name in $containers; do
            dock container inspect "$name" >/dev/null 2>&1 && dock rm -f "$name" >/dev/null 2>&1 && echo "usunieto $name"
        done
        printf 'Wolumeny danych zostaly (nxms-monitor-prom-data, nxms-monitor-grafana-data).\n'
        ;;
esac
