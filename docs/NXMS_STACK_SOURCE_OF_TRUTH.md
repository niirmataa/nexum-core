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
- `nxms-auth-guard` (rola docelowa; quorum gate systemu)

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
Orchestrator nie jest ostatecznym źródłem autoryzacji wejścia/wyjścia flow.

---

## 6a. Rola auth guardów

`auth guards`:
- są osobną rolą sieciową systemu,
- są warunkiem wejścia i wyjścia krytycznego flow,
- utrzymują quorum autoryzacyjne `2 z 5`,
- są sercem autentykacji, rotacji kluczy i trust root warstwy `nxms-transport`,
- trzymają główne klucze autoryzacyjne systemu oparte o `Falcon-1024-CT` i `FrodoKEM`,
- wystawiają proofy/quorum decision artifacts weryfikowane przez inne role,
- są jedyną warstwą zdolną do legalnej reaktywacji i odtworzenia systemu w nowej lokalizacji,
- działają fail-closed: brak quorum guardów oznacza brak systemu.

Konsekwencje:
- bez ważnego quorum guardów `2 z 5` system nie ma prawa dopuścić krytycznej akcji,
- bez `2` ważnych podpisów `Falcon-1024-CT` i poprawnego `KEM package` system nie ma prawa legalnie się aktywować ani przejść przez punkt krytyczny,
- signer i orchestrator nie zastępują guardów lokalną decyzją,
- orchestrator może prowadzić workflow i agregować stan/proofy, ale nie może samodzielnie zastąpić quorum guardów,
- guardy są częścią rdzenia systemu, a nie dodatkową warstwą auth,
- guardy są najbardziej chronioną rolą hostową w całym NXMS.

Dodatkowe zasady:
- operator nie ma bezpośredniej ścieżki logicznej do runtime core poza warstwą guardów,
- host runtime ma działać jak hermetyczny executor, nie miejsce ręcznego zarządzania trustem,
- guard runtime jest tamper-reactive i ma przechodzić w `quarantine` przy próbie nieautoryzowanej manipulacji,
- offline recovery material istnieje poza runtime i nie może być pojedynczym master key.
- operacje krytyczne i maintenance są mapowane na warianty `GDA` zgodnie z `docs/NXMS_GUARD_DECISION_ARTIFACT_MODEL.md`.
- abstrakcyjny model offline recovery quorum jest jawny architektonicznie, ale tajne szczegóły depozytu pozostają poza repo.
- wspólny język triady `nxms-guard / nxms-boss / nxms-integrity` jest opisany w `docs/NXMS_TRUST_TRIAD.md`.
- model pojęciowy `nxms-integrity` jest opisany w `docs/NXMS_INTEGRITY_MODEL.md`.
- host-role matrix jest utrzymywany w `docs/NXMS_HOST_ROLE_MATRIX.md` i jest domykany po pierwszych realnych uruchomieniach.

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

Doprecyzowanie granic:
- `Tor hidden service` jest jedyną docelową ścieżką sieciową między hostami.
- `nxms-transport` jest jedyną warstwą end-to-end dla szyfrowania, podpisów, integralności i message binding.
- lokalne HTTP/API procesów, np. `nxms-mailbox` na `127.0.0.1`, jest wyłącznie local process adapter boundary.
- lokalne HTTP/API nie jest samodzielną warstwą bezpieczeństwa runtime i nie zastępuje `nxms-transport` ani Tora.
- role hostowe (`auth guard`, `mailbox`, `signer`, `orchestrator`, `monerod`) są docelowo rozdzielone na oddzielnych maszynach spiętych tylko przez Tor/onion.
- `wallet-rpc` nie jest komunikacją między hostami; ma pozostać tylko local loopback boundary.

---

## 10. Czego nie robimy

Nie utrzymujemy:
- wielu równoległych flow jako równorzędnych,
- HTTP-first orchestration jako głównej ścieżki,
- direct legacy sign/submit jako normalnego runtime,
- shadow mode jako domyślnej drogi,
- break-glass jako zwykłego mechanizmu pracy,
- krytycznych decyzji bez quorum guardów `2 z 5`,
- aktywacji, recovery albo trust-changing operations bez `2x Falcon + KEM package`,
- clearnet exposure dla `monerod`, `wallet-rpc`, `signer`, `mailbox` albo guardów.

---

## 11. Zasada zmian

Każda zmiana musi odpowiedzieć:
1. Czy to jest CORE, OPS czy MANUAL?
2. Czy to otwiera drugi flow?
3. Czy to ma test?
4. Czy zgadza się z tym dokumentem?

Jeśli nie, zmiana nie powinna wejść.
