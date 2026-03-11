# NXMS Core

NXMS Core to eksperymentalny system **auto-multisig escrow** zbudowany wokół własnego transportu wiadomości, separacji ról, silnej izolacji usług i komunikacji **Tor-only**.

Projekt jest rozwijany jako **spójny rdzeń nowej architektury**, bez mieszania starych flow, szybkich obejść i historycznych wersji repo.

## Założenia

Docelowy system ma działać jako automat od:

- otwarcia escrow,
- przez kolejne rundy multisig,
- do podpisania, submitu, potwierdzenia i zamknięcia procesu,

z możliwością ręcznej interwencji operatora tylko poza ścieżką krytyczną runtime.

## Główne zasady architektury

- `nxms-transport` jest **jedynym kanonicznym wire formatem**
- `nxms-mailbox` jest **jedynym relayem / store-and-forward**
- `nxms-signer` jest node’em wykonawczym z lokalnymi kluczami
- `nxms-escrow-orchestrator` prowadzi workflow end-to-end
- `nxms-monero-core` zawiera logikę domenową Monero / multisig
- `tools/nexum-cli` jest narzędziem **manualnym user-auth / crypto**, a nie operatorskim UI/runtime surface
- komunikacja między hostami ma iść **wyłącznie przez Tor**
- system docelowo działa na **Alpine Linux**
- legacy pathy, shadow mode i break-glass nie są częścią głównego flow

## Status projektu

To repo jest w trakcie składania z wcześniejszych eksperymentów w **jedną, czystą architekturę**.

Aktualny cel to osiągnąć wersję:

- spójną,
- staging-ready,
- testowalną end-to-end,
- ale jeszcze nie traktowaną jako finalna produkcja.

## Co tu jest

### CORE

To są komponenty krytyczne dla automatu:

- `crates/nxms-transport`
- `crates/nxms-mailbox`
- `crates/nxms-mailbox-client`
- `crates/nxms-monero-core`
- `crates/nxms-escrow-orchestrator`
- `crates/nxms-signer`

### MANUAL

To są narzędzia ręczne, operatorskie i recovery:

- `tools/nexum-cli`

### OPS

To są rzeczy deploymentowe, runtime i dokumentacja operacyjna:

- `deploy/`
- `docs/`

## Docelowy model systemu

System jest projektowany jako rozdzielony zestaw usług uruchamianych na osobnych hostach / sandboxach.

Przykładowa topologia:

- orchestrator
- auth gateway A
- auth gateway B
- signer arbiter
- signer seller
- signer buyer

Wszystkie wiadomości między rolami są pakowane do `NxmsEnvelope`, szyfrowane i podpisywane przez `nxms-transport`, a następnie przekazywane przez mailbox relay dostępny przez Tor.

## Repo layout

```text
crates/
  nxms-transport/
  nxms-mailbox/
  nxms-mailbox-client/
  nxms-monero-core/
  nxms-escrow-orchestrator/
  nxms-signer/

tools/
  nexum-cli/

docs/
deploy/
tests/
