#!/bin/bash
set -e

echo "=== Building Secure Ping Docker image ==="
docker build -f Dockerfile.secure-ping -t nxms-secure-ping .

echo ""
echo "=== Running Secure Ping test ==="
docker run --rm nxms-secure-ping
