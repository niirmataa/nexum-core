# Nexum Vault — Build Instructions

## Prerequisites

- macOS 14+ (Sonoma)
- Xcode 15+
- iOS 17+ device (Secure Enclave / biometrics don't work in Simulator)

## First-time setup

```bash
cd ios/NexumVault
bash setup-falcon.sh
open NexumVault.xcodeproj
```

`setup-falcon.sh` copies Falcon C sources from `../../tools/nexum-cli/vendor/falcon/`
into `NexumVault/FalconC/src/` and `NexumVault/FalconC/include/`.

These files are gitignored — they must be copied before building.

## Xcode configuration

1. Open `NexumVault.xcodeproj`
2. Select **NexumVault** target → **Signing & Capabilities**
3. Set your **Team** (personal or org)
4. Change **Bundle Identifier** if needed (default: `com.nexum.vault`)
5. Connect an iOS 17+ device
6. Select device as build target (NOT Simulator)

## Build

```
Cmd+B
```

## Run

```
Cmd+R
```

On first launch:
- iOS will ask for Face ID / Touch ID permission
- iOS will ask for Camera permission (for QR scanning)
- Create a vault key pair
- Scan a challenge QR or paste JSON manually

## Troubleshooting

### "FalconBridge.h not found"
Run `setup-falcon.sh` first. Verify `NexumVault/FalconC/include/falcon.h` exists.

### "Undefined symbol: falcon_keygen_new"
The C source files need to be in the Xcode project's compile sources.
If they're missing, drag `NexumVault/FalconC/src/*.c` into the Xcode project
under **NexumVault** target → **Build Phases** → **Compile Sources**.

### "Signing requires a development team"
Set your Apple ID in Xcode → Settings → Accounts, then select your team
in the target's Signing & Capabilities.

### Camera shows black screen
Ensure camera permission is granted in iOS Settings → Nexum Vault → Camera.

## Project structure

```
ios/NexumVault/
├── NexumVault.xcodeproj/
├── setup-falcon.sh              ← run once on macOS
├── NexumVault/
│   ├── App/                     ← @main, lock screen
│   ├── Models/                  ← VaultKey, Challenge, AuditEntry
│   ├── Services/                ← 9 services (FalconCrypto, VaultStore, etc.)
│   ├── Views/                   ← 7 SwiftUI views
│   ├── Bridging/FalconBridge.h  ← C header import
│   ├── FalconC/                 ← C sources (copied by setup script)
│   │   ├── include/             ← falcon.h, internal.h, shake.h, fpr-double.h
│   │   └── src/                 ← 7 C files (keygen, sign, vrfy, fft, enc, frng, shake)
│   ├── NexumVault.entitlements
│   └── Resources/Info.plist
└── NexumVaultTests/             ← 26 unit tests + test vectors
```
