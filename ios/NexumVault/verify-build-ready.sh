#!/bin/bash
# verify-build-ready.sh — check that all required files exist before opening Xcode
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ERRORS=0

check() {
    if [ -f "$1" ]; then
        echo "  OK   $1"
    else
        echo "  MISS $1"
        ERRORS=$((ERRORS + 1))
    fi
}

echo "=== Nexum Vault — Build Readiness Check ==="
echo ""

echo "--- Swift Sources ---"
for f in \
    NexumVault/App/NexumVaultApp.swift \
    NexumVault/Models/VaultKey.swift \
    NexumVault/Models/Challenge.swift \
    NexumVault/Models/AuditEntry.swift \
    NexumVault/Services/CanonicalJSON.swift \
    NexumVault/Services/FalconCrypto.swift \
    NexumVault/Services/VaultStore.swift \
    NexumVault/Services/ChallengeParser.swift \
    NexumVault/Services/SignatureService.swift \
    NexumVault/Services/CallbackClient.swift \
    NexumVault/Services/AuditLogStore.swift \
    NexumVault/Services/QRScanner.swift \
    NexumVault/Services/BiometricAuth.swift \
    NexumVault/Views/VaultHomeView.swift \
    NexumVault/Views/CreateVaultView.swift \
    NexumVault/Views/PublicKeyView.swift \
    NexumVault/Views/ScanChallengeView.swift \
    NexumVault/Views/ChallengeReviewView.swift \
    NexumVault/Views/SignatureResultView.swift \
    NexumVault/Views/SettingsView.swift \
    NexumVault/Bridging/FalconBridge.h \
    NexumVault/NexumVault.entitlements \
    NexumVault/Resources/Info.plist; do
    check "$SCRIPT_DIR/$f"
done

echo ""
echo "--- Falcon C Headers ---"
for f in falcon.h internal.h shake.h fpr-double.h; do
    check "$SCRIPT_DIR/NexumVault/FalconC/include/$f"
done

echo ""
echo "--- Falcon C Sources ---"
for f in falcon-enc.c falcon-fft.c falcon-keygen.c falcon-sign.c falcon-vrfy.c frng.c shake.c; do
    check "$SCRIPT_DIR/NexumVault/FalconC/src/$f"
done

echo ""
echo "--- Xcode Project ---"
check "$SCRIPT_DIR/NexumVault.xcodeproj/project.pbxproj"

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "=== ALL CHECKS PASSED ==="
    echo "Open NexumVault.xcodeproj in Xcode, set your team, build to device."
else
    echo "=== $ERRORS FILE(S) MISSING ==="
    echo "Run setup-falcon.sh if FalconC files are missing."
    exit 1
fi
