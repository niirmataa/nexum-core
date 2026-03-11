# NXMS ROADMAP

## Cel

To repo ma być jednym spójnym rdzeniem systemu auto-multisig, bez mieszania starych flow,
eksperymentów i ścieżek awaryjnych w krytycznej ścieżce runtime.

Docelowe założenia:
- `nxms-transport` jako jedyny wire format
- `nxms-mailbox` jako relay/store-and-forward
- `nxms-signer` jako node z kluczami i lokalną logiką wykonawczą
- `nxms-escrow-orchestrator` jako automat i control-plane
- `nxms-monero-core` jako rdzeń domenowy Monero / multisig
- `tools/nexum-cli` jako wąskie narzędzie ręczne user-auth / crypto
- komunikacja między hostami tylko przez Tor
- deployment docelowo na Alpine Linux
- brak legacy direct flow w głównej ścieżce

## Zasady ogólne

### Tagi dla wszystkiego
Każdy moduł, plik albo feature ma mieć jeden z tagów:
- CORE
- OPS
- MANUAL

### Twarde zasady
- Nie dodawaj drugiego równoległego flow.
- `tools/nexum-cli` nie może być dependency ścieżki krytycznej runtime.
- Break-glass i shadow mode nie mogą być domyślną drogą działania.
- Każda nowa rzecz musi mieć decyzję w docs i test.

## Etap A — zamrożenie modelu guard quorum
- [x] Zapisać `auth guard quorum 2 z 5` jako warunek istnienia systemu.
- [x] Dodać `docs/NXMS_AUTH_GUARD_QUORUM_MODEL.md`.
- [x] Dodać `docs/NXMS_AUTH_GUARD_SECURITY_MODEL.md`.
- [x] Dodać `docs/NXMS_SYSTEM_P0_PAIN_POINTS.md`.
- [ ] Zamrozić model zagrożeń `partial compromise over time` dla guardów.
- [ ] Zamrozić klasy operacji `A/B/C` i invariants `2x Falcon + KEM package`.
- [ ] Zamrozić lifecycle guard secrets: rotate / revoke / quarantine / resurrection.
- [ ] Zamienić guard quorum na pełny invariant kodu i runtime gate.

## Etap 0 — zamrożenie starego świata
- [ ] Zamknąć stare repo jako archiwum eksperymentu.
- [ ] Utworzyć nowe repo robocze `nxms-core`.
- [ ] Dodać `README.md`.
- [ ] Dodać `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`.
- [ ] Dodać `docs/DECISIONS.md`.

## Etap 1 — szkielet nowego repo
- [ ] Utworzyć `crates/`, `tools/`, `docs/`, `deploy/`, `tests/`.
- [ ] Dodać root `Cargo.toml` jako workspace.
- [ ] Dodać `docs/REPO_LAYOUT.md`.

## Etap 2 — migracja fundamentów transportu
- [ ] Przenieść `nxms-transport`.
- [ ] Przenieść `nxms-mailbox`.
- [ ] Przenieść `nxms-mailbox-client`.
- [ ] Uruchomić testy roundtrip i push/pull/ack.

## Etap 3 — wydzielenie `nxms-monero-core`
- [ ] Dodać crate `nxms-monero-core`.
- [ ] Przenieść logikę domenową Monero / multisig.
- [ ] Nie przenosić `escrow_http/*`.

## Etap 4 — migracja `nxms-signer`
- [ ] Przenieść `nxms-signer`.
- [ ] Potwierdzić action token verification.
- [ ] Potwierdzić sign i submit flow.
- [x] Wyłączyć shadow mode domyślnie.

## Etap 5 — migracja `nxms-escrow-orchestrator`
- [ ] Przenieść orchestrator bez `http_flow.rs`.
- [ ] Zostawić tylko automat workflow.

## Etap 6 — zawężenie `nexum-cli`
- [ ] Utrzymać `tools/nexum-cli/` jako osobne narzędzie MANUAL dla auth/crypto primitives.
- [ ] Usunąć z docelowego kontraktu `nexum-cli` rolę operator tooling, escrow surface i UI helpera.
- [ ] Wydzielić osobno operator emergency console i osobno guard-admin tooling.

## Etap 7 — cięcie legacy
- [ ] Usunąć stare HTTP pathy z runtime core.
- [ ] Usunąć direct legacy sign/submit z głównego flow.
- [x] Oznaczyć break-glass jako awaryjne.

## Etap 8 — Alpine/OpenRC
- [ ] Dodać OpenRC dla mailbox, signer, orchestrator.
- [ ] Sprawdzić build na Alpine/musl.
- [ ] Zrobić lokalne smoke testy na Alpine WSL.

## Etap 8a — Monero/Tor-only runtime
- [x] Zapisać Monero Tor-only jako prerequisite dla signera.
- [x] Dodać baseline `monerod-stagenet` over Tor-only i `wallet-rpc` loopback-only.
- [ ] Udowodnić natywny source build Monero na Alpine/musl.
- [ ] Udowodnić `monerod-stagenet` over Tor-only na Alpine/OpenRC.
- [ ] Udowodnić `wallet-rpc` loopback-only na Alpine/OpenRC.

## Etap 9 — testy E2E
- [x] `tests/workspace_smoke.rs`
- [x] `tests/e2e_transport_mailbox.rs`
- [x] `tests/e2e_sign_submit.rs`
- [x] `tests/e2e_orchestrated_flow.rs`
- [x] Zdefiniować i utrzymywać P0 truth matrix dla `nxms-signer` w `docs/NXMS_SIGNER_P0_TEST_MATRIX.md`.
- [x] Zdefiniować i utrzymywać P0 truth matrix dla `nxms-mailbox` w `docs/NXMS_MAILBOX_P0_TEST_MATRIX.md`.
- [x] Zdefiniować i utrzymywać P0 truth matrix dla `nxms-escrow-orchestrator` w `docs/NXMS_ORCHESTRATOR_P0_TEST_MATRIX.md`.

## Etap 10 — release criteria
- [ ] Każda większa zmiana ma decyzję w docs.
- [ ] Każda większa zmiana ma test.
- [ ] Żadna zmiana nie otwiera drugiego flow.
