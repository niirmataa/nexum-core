#!/bin/bash
# setup-falcon.sh — copy Falcon C sources into the Xcode project tree
# Run once after cloning, before opening .xcodeproj

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/../../tools/nexum-cli/vendor/falcon"
DEST_DIR="${SCRIPT_DIR}/NexumVault/FalconC"

if [ ! -d "$VENDOR_DIR" ]; then
    echo "ERROR: Vendor directory not found: $VENDOR_DIR"
    exit 1
fi

mkdir -p "$DEST_DIR/src"
mkdir -p "$DEST_DIR/include"

# Copy headers
cp "$VENDOR_DIR/falcon.h"   "$DEST_DIR/include/"
cp "$VENDOR_DIR/internal.h" "$DEST_DIR/include/"
cp "$VENDOR_DIR/shake.h"    "$DEST_DIR/include/"
cp "$VENDOR_DIR/fpr-double.h" "$DEST_DIR/include/"

# Copy sources
for f in falcon-enc.c falcon-fft.c falcon-keygen.c falcon-sign.c falcon-vrfy.c frng.c shake.c; do
    cp "$VENDOR_DIR/$f" "$DEST_DIR/src/"
done

echo "Falcon C sources copied to $DEST_DIR"
echo "Headers in $DEST_DIR/include/"
echo "Sources in $DEST_DIR/src/"
