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
- `tools/nexum-cli` jako narzędzie ręczne / operatorskie / recovery
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

## Etap 6 — przeniesienie `nexum-cli`
- [ ] Przenieść do `tools/nexum-cli/`.
- [ ] Zostawić jako MANUAL / recovery / operator tooling.

## Etap 7 — cięcie legacy
- [ ] Usunąć stare HTTP pathy z runtime core.
- [ ] Usunąć direct legacy sign/submit z głównego flow.
- [x] Oznaczyć break-glass jako awaryjne.

## Etap 8 — Alpine/OpenRC
- [ ] Dodać OpenRC dla mailbox, signer, orchestrator.
- [ ] Sprawdzić build na Alpine/musl.
- [ ] Zrobić lokalne smoke testy na Alpine WSL.

## Etap 9 — testy E2E
- [x] `tests/workspace_smoke.rs`
- [x] `tests/e2e_transport_mailbox.rs`
- [x] `tests/e2e_sign_submit.rs`
- [x] `tests/e2e_orchestrated_flow.rs`
- [x] Zdefiniować i utrzymywać P0 truth matrix dla `nxms-signer` w `docs/NXMS_SIGNER_P0_TEST_MATRIX.md`.
- [x] Zdefiniować i utrzymywać P0 truth matrix dla `nxms-mailbox` w `docs/NXMS_MAILBOX_P0_TEST_MATRIX.md`.

## Etap 10 — release criteria
- [ ] Każda większa zmiana ma decyzję w docs.
- [ ] Każda większa zmiana ma test.
- [ ] Żadna zmiana nie otwiera drugiego flow.
