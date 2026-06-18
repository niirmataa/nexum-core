# NexumVault — runbook dla agenta: realna, testowalna apka BEZ Maca

Cel: doprowadzić projekt do stanu, w którym **logikę podpisu Falcon da się zbudować, uruchomić i przetestować na Linuksie** (bez macOS/Xcode), a samą apkę iOS budować i testować w chmurze (runner macOS w CI), z opcją wgrania na iPhone przez TestFlight.

Pomysł przewodni: ciężka część (Falcon) jest w **C** — kompiluje się wszędzie. Logika (kanoniczny JSON, parser wyzwań, modele, hash) jest w Swift/Foundation. Jedyny blokujący import to `CryptoKit` (Apple-only) w jednym pliku → podmieniamy na `swift-crypto`. Dzięki temu powstaje **prawdziwa apka CLI na Linuksie**, która robi realny podpis i którą można odpalić od ręki.

---

## Kontekst repo (przeczytaj najpierw)

- Katalog projektu iOS: `nexum-core/ios/NexumVault/` (tu jest `Package.swift`).
- Pakiet rdzenia: `NexumVaultCore/Sources` (+ testy `NexumVaultCore/Tests`).
- Apka iOS (UI, Xcode): `NexumVault/{App,Models,Services,Views,Bridging,FalconC}` + `NexumVault.xcodeproj`.
- Źródła Falcona (C): `nexum-core/tools/nexum-cli/vendor/falcon/`
  - biblioteka: `falcon-enc.c falcon-fft.c falcon-keygen.c falcon-sign.c falcon-vrfy.c frng.c shake.c`
  - nagłówki: `falcon.h internal.h shake.h fpr-double.h`
  - (NIE bierz do biblioteki: `test_falcon.c`, `tool.c` — to harnessy).
- Interfejs C dla Swifta: `falcon.h` (most `NexumVault/Bridging/FalconBridge.h` po prostu go `#include`uje).
- `CryptoKit` w Core: **tylko** `NexumVaultCore/Sources/Challenge.swift` (SHA-256, prywatny enum `SHA256`).
- Wektory testowe: `NexumVaultTests/TestVectors/{sample_challenge.json, sample_response.json, test_vectors.json}`.
- `.gitattributes` z normalizacją `eol=lf` już jest — zachowaj.

## Złote zasady (trzymaj się ich w każdym kroku)

1. **Nie psuj apki iOS.** Pliki w `NexumVault/` (target Xcode) mają dalej się kompilować na Macu.
2. **`NexumVaultCore` musi pozostać niezależny od platformy** — żadnych `import UIKit/SwiftUI/Security/LocalAuthentication/CryptoKit`. Dozwolone: `Foundation`, `Crypto` (swift-crypto), `CFalcon`.
3. **Commituj po każdej fazie** (osobne commity), z opisem co i dlaczego. Nic nie nadpisuj „na ślepo".
4. Po każdej fazie uruchom kryterium akceptacji i pokaż wynik.

---

## FAZA 0 — Postaw Swift na Linuksie

> **PROMPT DO AGENTA:**
> Zainstaluj toolchain Swift na tej maszynie Linux używając **swiftly** (oficjalny rekomendowany sposób; patrz https://www.swift.org/install/linux/swiftly). Kroki:
> 1. Pobierz i zainstaluj swiftly zgodnie z instrukcją ze swift.org, potem `swiftly install latest` i `swiftly use latest`.
> 2. Doinstaluj zależności systemowe, które wskaże swiftly (clang, libstdc++, itp.).
> 3. (Jeśli to Ubuntu 26.04, alternatywnie zadziała `apt install swift` z universe — ale preferuj swiftly dla powtarzalności.)
> **Akceptacja:** `swift --version` i `clang --version` wypisują wersje bez błędu.

---

## FAZA 1 — Ujednolicenie zduplikowanych plików (Core = źródło prawdy)

Te 6 plików istnieje podwójnie (w `NexumVault/{Models,Services}` i `NexumVaultCore/Sources`) i **już się rozjechały**: `FalconCrypto` (≈283 linie różnicy), `Challenge` (≈145), `VaultKey` (≈52), `AuditEntry` (≈39), `ChallengeParser` (≈22), `CanonicalJSON` (≈14).

> **PROMPT DO AGENTA:**
> Dla każdej z par plików: `FalconCrypto`, `Challenge`, `VaultKey`, `AuditEntry`, `ChallengeParser`, `CanonicalJSON` (lokalizacje: `NexumVault/Models|Services/<X>.swift` vs `NexumVaultCore/Sources/<X>.swift`):
> 1. Wygeneruj diff i **krótki raport** (plik `RECONCILE_REPORT.md`): co różni, która wersja jest nowsza/pełniejsza, ryzyka.
> 2. Ustal **wersję z `NexumVaultCore` jako źródło prawdy** dla czystej logiki i modeli — ale najpierw upewnij się (czytając kod), że Core nie zgubił funkcjonalności, której używa apka. Jeśli apka ma coś, czego Core nie ma, przenieś to do Core.
> 3. Wyjątek: `FalconCrypto`. W `NexumVaultCore` to ma być **protokół** `FalconCryptoProtocol` + typy wartości (kontrakt, czysty Swift). Konkretna, oparta na C implementacja zostaje poza Core (apka + CLI) i **konformuje** do tego protokołu. Nie wciągaj C do Core.
> 4. Usuń z targetu apki te pliki, które przejęło Core, i zamiast nich rób `import NexumVaultCore`. (Faktyczne wpięcie pakietu do `.xcodeproj` jest w Fazie 5 — tu chodzi o ujednolicenie źródła w plikach.)
> **Akceptacja:** każdy z 6 typów ma dokładnie jedną definicję „prawdy" w Core; `RECONCILE_REPORT.md` opisuje decyzje; nic nie skasowane bez odnotowania w raporcie.

---

## FAZA 2 — Port `CryptoKit` → `swift-crypto` (Core buduje się na Linuksie)

> **PROMPT DO AGENTA:**
> 1. W `NexumVaultCore/Sources/Challenge.swift` zamień `import CryptoKit` na `import Crypto` oraz `CryptoKit.SHA256` na `SHA256` (API swift-crypto jest zgodne: `SHA256.hash(data:)`).
> 2. W `Package.swift` dodaj zależność i wepnij ją do targetu Core:
> ```swift
> dependencies: [
>     .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
> ],
> // w targecie NexumVaultCore:
> dependencies: [.product(name: "Crypto", package: "swift-crypto")],
> ```
> 3. Usuń no-opowy `exclude: ["FalconC"]` z targetu Core (nie ma takiego katalogu pod `Sources`).
> 4. Zbuduj i przetestuj sam rdzeń.
> **Akceptacja:** `swift build` i `swift test` (target `NexumVaultCore`) przechodzą **na Linuksie**. To pierwszy zielony kamień milowy — czysta logika działa bez Maca.

---

## FAZA 3 — C-target `CFalcon` (Falcon kompilowany przez SwiftPM)

> **PROMPT DO AGENTA:**
> Utwórz w pakiecie target C dla Falcona:
> 1. Katalog `Sources/CFalcon/` z układem dla SwiftPM:
>    - `Sources/CFalcon/include/` → skopiuj nagłówki `falcon.h internal.h shake.h fpr-double.h` z `../../tools/nexum-cli/vendor/falcon/`.
>    - `Sources/CFalcon/include/module.modulemap`:
>      ```
>      module CFalcon {
>          header "falcon.h"
>          export *
>      }
>      ```
>    - `Sources/CFalcon/` → skopiuj źródła `falcon-enc.c falcon-fft.c falcon-keygen.c falcon-sign.c falcon-vrfy.c frng.c shake.c` (BEZ `test_falcon.c`, `tool.c`).
> 2. (Najlepiej dopisz to kopiowanie do `setup-falcon.sh`, żeby było powtarzalne i nie commituj skopiowanych źródeł — patrz istniejący `.gitignore`.)
> 3. W `Package.swift` dodaj `.target(name: "CFalcon", path: "Sources/CFalcon")` (w razie potrzeby `cSettings` z `headerSearchPath("include")`).
> **Akceptacja:** `swift build --target CFalcon` kompiluje bibliotekę Falcona na Linuksie bez błędów.

---

## FAZA 4 — Prawdziwa apka CLI `nexum-vault-cli` (realny podpis, do testowania od ręki)

> **PROMPT DO AGENTA:**
> 1. Dodaj `.executableTarget(name: "NexumVaultCLI", dependencies: ["NexumVaultCore", "CFalcon"], path: "Sources/NexumVaultCLI")`.
> 2. W tym targecie umieść `FalconCryptoC.swift` — konkretną implementację `FalconCryptoProtocol` z Core, wołającą API z `falcon.h` przez moduł `CFalcon` (zaadaptuj istniejący `NexumVault/Services/FalconCrypto.swift`, który już używa tych funkcji C).
> 3. Napisz `main.swift` (CLI), który wykonuje **pełny, realny przepływ**:
>    - `generate` → tworzy parę kluczy Falcon, wypisuje publiczny (base64url),
>    - `sign --challenge <plik.json>` → wczytuje wyzwanie, robi kanoniczny JSON (Core), liczy hash, **podpisuje Falconem (C)**, **weryfikuje** podpis, wypisuje JSON odpowiedzi.
> 4. Uruchom na wektorze testowym:
>    ```
>    swift run nexum-vault-cli sign --challenge NexumVaultTests/TestVectors/sample_challenge.json
>    ```
> 5. Dodaj test integracyjny (round-trip: keygen → sign → verify == true) korzystający z `CFalcon`.
> **Akceptacja:** `swift run nexum-vault-cli ...` na Linuksie produkuje poprawny, **zweryfikowany** podpis i sensowny JSON odpowiedzi; `swift test` (z testem round-trip) jest zielony. To jest „realna apka, którą testujemy bez Maca".

---

## FAZA 5 — CI: Linux (rdzeń) + chmurowy macOS (apka iOS), opcjonalnie TestFlight

> **PROMPT DO AGENTA:**
> Utwórz `.github/workflows/ci.yml` z dwoma jobami:
> 1. **Linux** (`runs-on: ubuntu-latest`, obraz/kontener ze Swiftem): `swift build` + `swift test` (rdzeń + CLI + round-trip Falcon). To „bramka" działająca bez Maca.
> 2. **macOS** (`runs-on: macos-26` — najnowszy GA runner z aktualnym Xcode; `macos-15` jako fallback): `xcodebuild test -scheme NexumVault -destination 'platform=iOS Simulator,name=iPhone 16'`. Buduje i testuje **prawdziwą apkę iOS** na chmurowym Macu — bez własnego sprzętu.
> **Akceptacja:** oba joby zielone na pushu.
>
> **Opcjonalnie — apka na Twoim iPhonie (TestFlight):** wymaga konta **Apple Developer Program (≈$99/rok)**. Dodaj job macOS: `xcodebuild archive` → eksport `.ipa` → upload do App Store Connect (`xcrun altool`/`fastlane pilot`) z kluczem App Store Connect API trzymanym w GitHub Secrets. Wtedy instalujesz build przez aplikację TestFlight na telefonie. Sam build na simulatorze (job wyżej) konta nie wymaga.

---

## Kolejność i kamienie milowe

1. Faza 0 → Swift stoi.
2. Faza 2 (po 1) → **rdzeń zielony na Linuksie** (najszybszy realny dowód, że logika działa).
3. Fazy 3–4 → **CLI robi realny podpis na Linuksie** (apka do testowania bez Maca).
4. Faza 5 → CI + ścieżka na iPhone.

> Wskazówka dla agenta: jeśli któreś dokładne polecenie instalacyjne się zmieniło, kieruj się oficjalną stroną https://www.swift.org/install/linux/ — ale trzymaj się struktury i kryteriów akceptacji powyżej.
