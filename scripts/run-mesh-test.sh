#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MESH_DIR="$SCRIPT_DIR/deploy/mesh"

echo "============================================"
echo " NXMS 10-Node Mesh Test"
echo "============================================"
echo ""

# Generate identities if not already done
if [ ! -f "$MESH_DIR/peers.json" ]; then
    echo "[1/3] Generating identities..."
    bash "$SCRIPT_DIR/scripts/gen-mesh-identities.sh"
else
    echo "[1/3] Identities already exist, skipping generation."
fi

# Start the mesh
echo ""
echo "[2/3] Starting 10-node mesh..."
docker compose -f "$SCRIPT_DIR/docker-compose.mesh.yml" up -d --build

echo "  Waiting for all nodes to be ready..."
sleep 5

# Check all nodes are running
RUNNING=$(docker compose -f "$SCRIPT_DIR/docker-compose.mesh.yml" ps --status running -q | wc -l)
echo "  Running containers: $RUNNING / 10"

if [ "$RUNNING" -lt 10 ]; then
    echo "  ERROR: Not all nodes started!"
    docker compose -f "$SCRIPT_DIR/docker-compose.mesh.yml" ps
    exit 1
fi

# Run ping test from node-01 to each other node
echo ""
echo "[3/3] Running PING test: node-01 → node-02..10"

for i in $(seq -w 2 10); do
    TARGET="node-$i"
    echo "  PING $TARGET ..."

    # Use the node image to send a PING
    RESULT=$(docker run --rm \
        --network nxms-mesh_nxms-net \
        -v "$MESH_DIR/identities/node-01:/vault:ro" \
        -v "$MESH_DIR/peers.json:/peers.json:ro" \
        nxms-node-img \
        nexum-node ping --peer "$TARGET" --vault /vault --peers /peers.json 2>&1 || true)

    echo "    $RESULT"
done

echo ""
echo "============================================"
echo " Mesh test complete."
echo ""
echo " To stop: docker compose -f docker-compose.mesh.yml down"
echo " To view logs: docker compose -f docker-compose.mesh.yml logs -f"
echo "============================================"
