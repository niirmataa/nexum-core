# NXMS Stack Source of Truth

To jest główny dokument określający, **co jest prawdziwą architekturą systemu**.

Jeśli kod, dokumentacja albo stare notatki są z tym dokumentem sprzeczne, wygrywa ten plik.

Ten plik ma pozostac krotki i nadrzedny.
Nie sluzy do burzy mozgow.
Nie sluzy do trzymania wariantow.
Ma opisywac tylko aktualnie przyjety model.

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
- `deploy/audit/` (repo-managed audit baseline profiles for WSL and VM)

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
- utrzymują konstytucyjne quorum autoryzacyjne `2 z 2`,
- są sercem autentykacji, rotacji kluczy i trust root warstwy `nxms-transport`,
- trzymają główne klucze autoryzacyjne systemu oparte o `Falcon-1024-CT` i `FrodoKEM`,
- wystawiają proofy/quorum decision artifacts weryfikowane przez inne role,
- działają fail-closed: brak quorum guardów oznacza brak systemu.

Konsekwencje:
- bez ważnego quorum guardów `2 z 2` system nie ma prawa dopuścić krytycznej akcji,
- bez `2` ważnych podpisów `Falcon-1024-CT` i poprawnego `KEM package` system nie ma prawa legalnie się aktywować ani przejść przez punkt krytyczny,
- signer i orchestrator nie zastępują guardów lokalną decyzją,
- orchestrator może prowadzić workflow i agregować stan/proofy, ale nie może samodzielnie zastąpić quorum guardów,
- guardy są częścią rdzenia systemu, a nie dodatkową warstwą auth,
- guardy są najbardziej chronioną rolą hostową w całym NXMS.
- pojedynczy guard po utracie drugiej strony nie ma prawa reaktywować ani dalej prowadzić systemu; może co najwyżej publikować komunikat informacyjny o awarii.
- operator nie jest częścią quorum konstytucyjnego; może dawać tylko witness operacyjny i sygnał dostępności.
- dopuszczalny jest tylko bardzo wąski tryb awaryjnego domknięcia escrow już będących w toku, po którym system przechodzi do `END SYSTEM`.

Dodatkowe zasady:
- operator nie ma bezpośredniej ścieżki logicznej do runtime core poza warstwą guardów,
- host runtime ma działać jak hermetyczny executor, nie miejsce ręcznego zarządzania trustem,
- guard runtime jest tamper-reactive i ma przechodzić w `quarantine` przy próbie nieautoryzowanej manipulacji,
- offline recovery material istnieje poza runtime i nie może być pojedynczym master key.
- operacje krytyczne i maintenance są mapowane na warianty `GDA` zgodnie z `docs/reference/NXMS_GUARD_DECISION_ARTIFACT_MODEL.md`.
- abstrakcyjny model offline recovery quorum jest jawny architektonicznie, ale tajne szczegóły depozytu pozostają poza repo.
- wspólny język triady `nxms-guard / nxms-boss / nxms-integrity` jest opisany w `docs/reference/NXMS_TRUST_TRIAD.md`.
- model pojęciowy `nxms-integrity` jest opisany w `docs/reference/NXMS_INTEGRITY_MODEL.md`.
- host-role matrix jest utrzymywany w `docs/reference/NXMS_HOST_ROLE_MATRIX.md` i jest domykany po pierwszych realnych uruchomieniach.
- audyt środowiska developerskiego i runtime jest rozdzielony zgodnie z `docs/reference/NXMS_AUDIT_BASELINE.md`.

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
- docelowo służy tylko do auth / registration / challenge-response / sign / verify / key generation primitives,
- nie jest legalną ścieżką user escrow,
- nie jest legalną ścieżką operator runtime control,
- nie jest narzędziem administrowania `auth guard`,
- nie należy do krytycznej ścieżki runtime automatu.

Status docelowy:
- user escrow flow idzie wyłącznie przez dedykowaną warstwę `.onion hidden service`,
- operator manual console istnieje osobno i tylko jako ścieżka awaryjna,
- guard/admin tooling istnieje osobno i nie miesza się z user CLI.

Status bieżący repo:
- obecny kod `tools/nexum-cli` nadal zawiera legacy/manual surface wykraczający poza target scope,
- dopóki ten drift nie zostanie usunięty z implementacji, obowiązującym kontraktem pozostaje ten dokument, a nie historyczny zakres komend.

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

Docelowy stały runtime core:
- `1x AG-01`
- `1x AG-02`
- `1x orchestrator`
- `1x mailbox`
- `1x signer-a + monero-a`
- `1x signer-b + monero-b`

`operator-console` pozostaje oddzielnym, kontrolowanym środowiskiem użycia
systemu i nie jest liczony jako część stałego konstytucyjnego runtime core.

---

## 10. Czego nie robimy

Nie utrzymujemy:
- wielu równoległych flow jako równorzędnych,
- HTTP-first orchestration jako głównej ścieżki,
- direct legacy sign/submit jako normalnego runtime,
- shadow mode jako domyślnej drogi,
- break-glass jako zwykłego mechanizmu pracy,
- krytycznych decyzji bez quorum guardów `2 z 2`,
- aktywacji, recovery albo trust-changing operations bez `2x Falcon + KEM package`,
- clearnet exposure dla `monerod`, `wallet-rpc`, `signer`, `mailbox` albo guardów.

---

## 10a. Krótka Checklista

- [ ] Konstytucyjne quorum opisane jako `2 z 2` i nigdzie indziej nie ma starego `2 z 5`
- [ ] Operator nie jest częścią quorum
- [ ] Operator ma tylko witness / dostępność / bounded scope
- [ ] `mailbox` pozostaje jedynym relayem
- [ ] `signer-a + monero-a` i `signer-b + monero-b` są traktowane jako dwa oddzielne execution hosty
- [ ] Międzyhostowa komunikacja docelowo idzie tylko przez Tor/onion
- [ ] Brak legalnej reaktywacji starego systemu po utracie pełnego quorum

---

## 11. Zasada zmian

Każda zmiana musi odpowiedzieć:
1. Czy to jest CORE, OPS czy MANUAL?
2. Czy to otwiera drugi flow?
3. Czy to ma test?
4. Czy zgadza się z tym dokumentem?

Jeśli nie, zmiana nie powinna wejść.
