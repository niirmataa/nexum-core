#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MESH_DIR="$SCRIPT_DIR/deploy/mesh"
NODE_COUNT=10

echo "=== Generating $NODE_COUNT NXMS node identities ==="

# Build node image first
docker build -f Dockerfile.node -t nxms-node-img "$SCRIPT_DIR"

# Generate identities using the node image
for i in $(seq -w 1 $NODE_COUNT); do
    NODE_ID="node-$i"
    OUT_DIR="$MESH_DIR/identities/$NODE_ID"
    mkdir -p "$OUT_DIR"

    docker run --rm \
        -v "$OUT_DIR:/out" \
        nxms-node-img \
        nexum-node gen-identity --id "$NODE_ID" --out-dir /out

    echo "  $NODE_ID ✓"
done

# Build peers.json
echo ""
echo "=== Building peers.json ==="

PEERS_JSON='{"nodes":['
FIRST=true
for i in $(seq -w 1 $NODE_COUNT); do
    NODE_ID="node-$i"
    IDENTITY_FILE="$MESH_DIR/identities/$NODE_ID/identity.json"
    KEM=$(jq -r '.kem_pk_b64' "$IDENTITY_FILE")
    SIG=$(jq -r '.sig_pk_b64' "$IDENTITY_FILE")

    if [ "$FIRST" = false ]; then
        PEERS_JSON+=','
    fi
    FIRST=false

    PEERS_JSON+="{\"id\":\"$NODE_ID\",\"addr\":\"$NODE_ID:9000\",\"kem_pk_b64\":\"$KEM\",\"sig_pk_b64\":\"$SIG\"}"
done
PEERS_JSON+=']}'

echo "$PEERS_JSON" | jq '.' > "$MESH_DIR/peers.json"

echo ""
echo "=== Identities written to $MESH_DIR/identities/ ==="
echo "=== peers.json written to $MESH_DIR/peers.json ==="
ls -la "$MESH_DIR/identities/"*/
