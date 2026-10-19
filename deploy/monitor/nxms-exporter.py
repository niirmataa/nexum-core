#!/usr/bin/env python3
"""OPS: nxms-exporter — metryki NXMS dla Prometheus (lab/poligon).

Wystawia /metrics z danych domenowych NXMS bez sekretow:
  - zadania dockerowe (tools/nxms-stack.sh) z ~/.local/share/nxms-tasks/,
  - instancje labu multisig (tools/l.sh) z ~/.local/share/nxms-lab/lab.json,
  - stan daemon Monero (wysokosc, trudnosc, polaczenia, kopanie).
Uruchamiany przez tools/nxms-monitor.sh w kontenerze (host network).
"""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TASKS_DIR = Path(os.environ.get("NXMS_TASKS_STATE", str(Path.home() / ".local/share/nxms-tasks")))
LAB_STATE = Path(os.environ.get("NXMS_LAB_STATE", str(Path.home() / ".local/share/nxms-lab/lab.json")))
DAEMON = os.environ.get("NXMS_MONITOR_DAEMON", "http://127.0.0.1:38081").rstrip("/")


def _read_jsons(directory):
    out = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                out.append(data)
    return out


def _esc(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def collect():
    lines = []

    def metric(name, value, labels=""):
        lines.append(f"{name}{labels} {value}")

    for task in _read_jsons(TASKS_DIR):
        task_id = _esc(task.get("id", ""))
        labels = f'{{task="{task_id}",kind="{_esc(task.get("kind", ""))}",state="{_esc(task.get("state", ""))}"}}'
        metric("nxms_task_info", 1, labels)
        roles = [r for r in (task.get("roles") or []) if isinstance(r, dict)]
        active = sum(1 for r in roles if r.get("state") == "active")
        metric("nxms_task_roles_active", active, f'{{task="{task_id}"}}')
        metric("nxms_task_roles_total", len(roles), f'{{task="{task_id}"}}')

    try:
        lab = json.loads(LAB_STATE.read_text())
    except (OSError, ValueError):
        lab = {}
    for instance in lab.get("instances") or []:
        if not isinstance(instance, dict):
            continue
        lab_id = _esc(instance.get("id", ""))
        try:
            confirmations = int(instance.get("confirmations") or 0)
        except (TypeError, ValueError):
            confirmations = 0
        metric("nxms_lab_confirmations", confirmations,
               f'{{lab="{lab_id}",state="{_esc(instance.get("state", ""))}"}}')
        try:
            funded = float(instance.get("funded_xmr") or 0)
        except (TypeError, ValueError):
            funded = 0.0
        metric("nxms_lab_funded_xmr", funded, f'{{lab="{lab_id}"}}')

    try:
        with urllib.request.urlopen(DAEMON + "/get_info", timeout=3) as response:
            info = json.loads(response.read())
        metric("nxms_monero_height", int(info.get("height") or 0))
        metric("nxms_monero_difficulty", int(info.get("difficulty") or 0))
        metric("nxms_monero_outgoing_peers", int(info.get("outgoing_connections_count") or 0))
        metric("nxms_monero_synchronized", 1 if info.get("synchronized") else 0)
        metric("nxms_monero_reachable", 1)
    except Exception:
        metric("nxms_monero_reachable", 0)

    try:
        with urllib.request.urlopen(DAEMON + "/mining_status", timeout=3) as response:
            mining = json.loads(response.read())
        metric("nxms_mining_active", 1 if mining.get("active") else 0)
        metric("nxms_mining_hashrate", int(mining.get("speed") or mining.get("speed_10s") or 0))
    except Exception:
        metric("nxms_mining_active", 0)

    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/metrics":
            body = collect().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("NXMS_EXPORTER_PORT", "9105"))
    print(f"nxms-exporter: http://127.0.0.1:{port}/metrics", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
