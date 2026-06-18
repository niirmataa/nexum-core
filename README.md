# Nexum Core / NXMS

Nexum Core jest roboczym rdzeniem systemu **NXMS**: eksperymentalnej architektury auto-multisig escrow opartej o rozdzielone role, wlasny transport wiadomosci, lokalne signery i komunikacje Tor-only.

Repo jest skladane jako czysty workspace dla core runtime. Nie jest jeszcze finalna produkcja i nie powinno byc opisywane jako gotowy, audytowany system finansowy. Obecny cel to dojsc do spójnego, testowalnego i staging-ready ukladu komponentow.

## Source Of Truth

Najwazniejszy dokument architektoniczny:

- `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`

Jesli README, starsze notatki albo kod pomocniczy sa z nim sprzeczne, wygrywa `NXMS_STACK_SOURCE_OF_TRUTH.md`.

Dokumenty wspierajace:

- `docs/NXMS_ROADMAP.md`
- `docs/PROJECT_STATUS.md`
- `docs/reference/ARCHITECTURE.md`
- `docs/reference/REPO_LAYOUT.md`
- `docs/reference/SECURITY_PROOF.md`
- `docs/reference/THREAT_MODEL_NXMS_MAILBOX.md`

## Model Systemu

NXMS ma docelowo prowadzic proces escrow od admission, przez workflow multisig, do podpisania, submitu, potwierdzenia i zamkniecia procesu. Reczna interwencja operatora ma byc ograniczona i nie moze zastepowac krytycznej sciezki runtime.

Glowne zasady:

- `NxmsEnvelope` jest kanonicznym wire formatem.
- `nxms-mailbox` jest jedynym relayem store-and-forward.
- `nxms-transport` odpowiada za pakowanie, podpisy, szyfrowanie i binding wiadomosci.
- `nxms-signer` jest capability node z lokalnymi kluczami i lokalnym audytem.
- `nxms-escrow-orchestrator` prowadzi workflow end-to-end.
- `nxms-monero-core` trzyma logike domenowa Monero/multisig.
- `tools/nexum-cli` jest narzedziem manualnym/recovery, a nie runtime control plane.
- Komunikacja miedzy hostami ma isc przez Tor/onion.
- Runtime ma domyslnie dzialac fail-closed.

## Status

Stan repo:

- aktywny branch: `main`
- projekt jest workspace Rust plus narzedzia C/ops
- kod jest eksperymentalny i nadal wymaga audytu
- testy e2e istnieja, ale nie sa rownowazne formalnej weryfikacji bezpieczenstwa
- `privAI/privai-chain` jest jeszcze lokalna zaleznoscia czesci testow/orchestratora

Nie twierdzimy jeszcze:

- ze system jest production-ready,
- ze kryptografia i key management sa finalnie zaudytowane,
- ze transport ma formalny dowod constant-time,
- ze lokalne Docker/OpenRC smoke testy sa pelna symulacja docelowej produkcji.

## Repo Layout

```text
crates/
  nxms-transport/             # wire format, crypto helpers, framing, Tor/P2P primitives
  nxms-mailbox/               # relay store-and-forward dla zaszyfrowanych envelope
  nxms-mailbox-client/        # klient HTTP/Tor SOCKS dla mailboxa
  nxms-monero-core/           # logika domenowa Monero/multisig
  nxms-escrow-orchestrator/   # workflow, action tokens, state machine, SLO/integrity checks
  nxms-signer/                # signer node, policy, snapshot validation, wallet-rpc boundary
  nxms-host-bootstrap/        # generowanie materialu host identity/bootstrap

tools/
  nexum-cli/                  # manual auth/crypto/recovery tooling

docs/
  reference/                  # runbooki, modele, threat model, test matrices

deploy/
  openrc/                     # Alpine/OpenRC service files
  systemd/                    # systemd service examples
  tor/                        # hidden-service examples
  monero/                     # stagenet/wallet-rpc examples
  audit/                      # baseline audit profiles

tests/                        # integracyjne i e2e testy workspace
ios/NexumVault/               # lokalna kopia iOS vault, docelowo osobne repo
legacy-archive/               # material historyczny, nie runtime source of truth
```

## Komponenty

| Komponent | Rola |
| --- | --- |
| `nxms-transport` | Kanoniczny format `NxmsEnvelope`, podpisy, szyfrowanie, framing i podstawy transportu. |
| `nxms-mailbox` | Minimalny relay ciphertext envelope. Nie zna plaintextu i nie decyduje o escrow. |
| `nxms-mailbox-client` | Klient do mailboxa, w tym przez SOCKS/Tor. |
| `nxms-monero-core` | Warstwa domenowa Monero/multisig. Nie jest samodzielnym web runtime. |
| `nxms-escrow-orchestrator` | Control-plane workflow: stan, retry, timeouty, action tokens, SLO. |
| `nxms-signer` | Capability node z lokalnymi kluczami, policy gate i wallet-rpc boundary. |
| `nxms-host-bootstrap` | Narzedzie do przygotowania publicznych bundle hostow. |
| `nexum-node` | Prosty mesh/secure-ping harness na poziomie workspace. |
| `tools/nexum-cli` | Manualne narzedzia auth/crypto/recovery, nie glowne UI runtime. |

## Szybki Start

Wymagania minimalne:

- Rust zgodny z `rust-toolchain.toml`
- Cargo
- lokalny checkout zaleznosci `../privAI/privai-chain`, dopoki ta zaleznosc nie zostanie wydzielona albo zastapiona

Podstawowe komendy:

```sh
cargo fmt --check
cargo test
cargo test --test secure_ping -- --nocapture
cargo run --bin nexum-node -- --help
```

Generowanie lokalnej tozsamosci dla `nexum-node`:

```sh
cargo run --bin nexum-node -- gen-identity --id node-a --out-dir /tmp/nxms-node-a
```

Uruchomienie node'a lokalnie:

```sh
NODE_ID=node-a \
LISTEN_HOST=127.0.0.1 \
LISTEN_PORT=9000 \
VAULT_DIR=/tmp/nxms-node-a \
PEERS_JSON=peers.json \
cargo run --bin nexum-node -- run
```

## Testy

Najwazniejsze testy workspace sa w `tests/`:

- `secure_ping.rs`
- `e2e_transport_mailbox.rs`
- `e2e_escrow_admission.rs`
- `e2e_operator_escrow.rs`
- `e2e_orchestrated_flow.rs`
- `e2e_runtime_trust_bundle.rs`
- `e2e_sign_submit.rs`
- `workspace_smoke.rs`

Uruchomienie pelnego zestawu:

```sh
cargo test
```

Uruchomienie pojedynczego testu:

```sh
cargo test --test e2e_transport_mailbox -- --nocapture
```

## Deployment I Runtime

Materialy deploymentowe sa w `deploy/`.

Aktualnie repo zawiera:

- OpenRC service files dla Alpine,
- przyklady systemd,
- konfiguracje hidden service Tor,
- konfiguracje Monero stagenet/wallet-rpc,
- baseline audytu dla WSL i VM.

Docelowy runtime nie powinien polegac na publicznych bindach. Lokalne API procesow jest traktowane jako adapter boundary, a nie samodzielna warstwa zaufania. Ruch miedzy rolami ma isc przez Tor/onion i `nxms-transport`.

## Bezpieczenstwo

To repo dotyka obszarow wysokiego ryzyka: kryptografia, podpisy, multisig, wallet-rpc, autoryzacja workflow i key material.

Zasady pracy:

- nie przepisywac crypto bez osobnego audytu,
- nie mieszac legacy flow z aktualnym runtime,
- nie dodawac publicznych bind runtime bez uzasadnienia,
- nie wprowadzac break-glass jako glownej sciezki systemu,
- nie traktowac mailboxa, CLI ani operatora jako trust root,
- dokumentowac kazda zmiane w modelu zaufania.

Powiazane dokumenty:

- `docs/reference/SECURITY_PROOF.md`
- `docs/reference/NXMS_AUTH_GUARD_SECURITY_MODEL.md`
- `docs/reference/NXMS_RUNTIME_HARDENING_RUNBOOK.md`
- `docs/reference/NXMS_SANDBOX_NETWORK_POLICY.md`
- `docs/reference/NXMS_AUDIT_BASELINE.md`

## Granice Repo

To repo jest core/runtime workspace.

Powiazane, ale osobne kierunki:

- `nexum-network` - pakiety protokolow, fixtures, skills i dokumentacja sieciowa
- `nexum-vault-ios` - docelowe repo iOS vault
- przyszle `nexum-falcon-wasm` - reproducible WASM verifier
- przyszle service wrappery dla publicznych API

## Zasada Dokumentacji

README ma byc brama do repo, nie miejscem trzymania calej architektury. Decyzje systemowe zapisuj w `docs/NXMS_STACK_SOURCE_OF_TRUTH.md` albo odpowiednim dokumencie w `docs/reference/`.
