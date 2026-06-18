#!/bin/sh
set -e

echo "=== Starting Docker daemon ==="

# Kill any existing dockerd
killall dockerd 2>/dev/null || true
sleep 1

# Start dockerd in background
dockerd --storage-driver=overlayfs --iptables=false > /tmp/dockerd.log 2>&1 &

# Wait for Docker socket
for i in $(seq 1 30); do
    if docker info > /dev/null 2>&1; then
        echo "Docker daemon ready after ${i}s"
        docker info --format 'Server: {{.ServerVersion}}'
        exit 0
    fi
    sleep 1
done

echo "ERROR: Docker daemon failed to start"
cat /tmp/dockerd.log
exit 1
