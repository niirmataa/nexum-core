# NXMS Stack Source of Truth

To jest główny dokument określający, **co jest prawdziwą architekturą systemu**.

Jeśli kod, dokumentacja albo stare notatki są z tym dokumentem sprzeczne, wygrywa ten plik.

---

## 1. Cel systemu

NXMS to auto-multisig escrow system z:
- własnym transportem wiadomości,
- rozdzielonymi rolami,
- lokalnymi signerami,
- automatem workflow,
- komunikacją Tor-only.

---

## 2. Kanoniczne komponenty runtime

### CORE

- `nxms-transport`
- `nxms-mailbox`
- `nxms-mailbox-client`
- `nxms-monero-core`
- `nxms-escrow-orchestrator`
- `nxms-signer`

### MANUAL

- `tools/nexum-cli`

### OPS

- `deploy/`
- `docs/`

---

## 3. Jedyny kanoniczny wire format

Jedynym kanonicznym wire formatem jest:

- `NxmsEnvelope`

Wszystkie wiadomości między hostami mają być przekazywane jako `NxmsEnvelope`.

Nie ma drugiego, równoległego formatu transportowego.

---

## 4. Jedyny kanoniczny relay

Jedynym relayem / store-and-forward jest:

- `nxms-mailbox`

Mailbox:
- nie zna logiki escrow,
- nie zna plaintextu wiadomości,
- nie jest źródłem prawdy workflow,
- nie podejmuje decyzji biznesowych.

---

## 5. Rola signera

`nxms-signer`:
- trzyma lokalne klucze,
- weryfikuje policy / snapshot / tokeny,
- wykonuje sign i submit,
- prowadzi lokalny audit i replay protection,
- działa jako capability node.

Signer nie jest zastępowany przez CLI ani przez mailbox.

---

## 6. Rola orchestratora

`nxms-escrow-orchestrator`:
- prowadzi automat workflow,
- trzyma stan procesu,
- pilnuje timeoutów, retry i quorum,
- przeprowadza ścieżkę od open escrow do close / fail.

Orchestrator jest control-plane systemu.

---

## 7. Rola `nxms-monero-core`

`nxms-monero-core`:
- zawiera logikę domenową Monero / multisig,
- nie zawiera starej warstwy `escrow_http`,
- nie jest aplikacją webową,
- nie jest runtime service samą w sobie.

---

## 8. Rola `nexum-cli`

`tools/nexum-cli`:
- jest narzędziem ręcznym,
- służy operatorowi,
- służy do recovery, auth, registration, prekeys, DM i diagnostyki,
- nie należy do krytycznej ścieżki runtime automatu.

System ma działać bez wymogu użycia `nexum-cli`.

---

## 9. Networking

Docelowy model:
- Tor only
- lokalne API tylko na loopback
- brak publicznych bindów bez powodu
- komunikacja między hostami przez onion / Tor

---

## 10. Czego nie robimy

Nie utrzymujemy:
- wielu równoległych flow jako równorzędnych,
- HTTP-first orchestration jako głównej ścieżki,
- direct legacy sign/submit jako normalnego runtime,
- shadow mode jako domyślnej drogi,
- break-glass jako zwykłego mechanizmu pracy.

---

## 11. Zasada zmian

Każda zmiana musi odpowiedzieć:
1. Czy to jest CORE, OPS czy MANUAL?
2. Czy to otwiera drugi flow?
3. Czy to ma test?
4. Czy zgadza się z tym dokumentem?

Jeśli nie, zmiana nie powinna wejść.