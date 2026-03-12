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
- nie podejmuje decyzji biznesowych,
- nie jest trust rootem ani źródłem legalności runtime,
- kończy swoją rolę na relay / store-and-forward ciphertext envelope.

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
- przeprowadza ścieżkę od open escrow do close / fail,
- po legalnym admission escrow prowadzi docelowy `AUTO multisig` runtime.

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
- `AG-01` i `AG-02` nie prowadzą ręcznie zwykłego escrow step-by-step; ich normalna obecność w escrow flow ma być skupiona w pojedynczym quorum admission artifact dopuszczającym konkretne escrow do legalnego auto-runtime,
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

## 8a. Rola customer service `.onion`

`customer service .onion`:
- jest jedyną legalną ścieżką klienta do systemu,
- obsługuje `register`, `challenge-response`, `open escrow`, `status` i bounded customer events typu `delivered`,
- nie jest runtime core i nie prowadzi execution path escrow,
- nie jest trust rootem i nie zastępuje guard quorum,
- przekazuje do core nie tylko nicki, ale zamrożony `customer identity snapshot` przypięty do escrow.

Docelowy flow klienta:
- `buyer` otwiera escrow przez `customer service .onion`,
- system zwraca adres multisig do wpłaty,
- `buyer` wpłaca,
- system informuje `seller`, że escrow jest ufundowane,
- `buyer` po otrzymaniu towaru zgłasza `delivered`,
- dalsze `sign/submit/close` wykonuje już automatycznie runtime core.

---

## 8b. Artefakty klienta

`nexum-cli` pozostaje źródłem materiału kryptograficznego klienta, ale nie jest runtime core.

Docelowy kontrakt:
- klient lokalnie generuje swoje klucze i sekrety wyłącznie po swojej stronie,
- do `customer service .onion` trafia tylko publiczny bundle rejestracyjny i proof z challenge-response,
- wynikiem rejestracji jest trwały `customer_identity_record`,
- przy `open escrow` `customer service .onion` zamraża `customer_identity_snapshot` dla `buyer` i `seller`,
- aktywne escrow nigdy nie przepina się cicho na późniejszą rotację kluczy klienta; nowe klucze działają dopiero dla nowych escrow.

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

Dopuszczalny etap wykonawczy przed pełnym rozdzieleniem ról:
- szybka lokalna weryfikacja runtime przez `OpenRC + Tor`,
- uruchomienie i smoke-test `mailbox` / `signer` / `orchestrator`,
- bez zmiany docelowego modelu hostowego i bez uznawania tego za finalną architekturę.

Bootstrap runtime:
- każdy host runtime generuje lokalnie własny zaszyfrowany sekret hostowy, tj. `host vault`,
- aktywny peer set runtime i aktywny issuer runtime auth mają pochodzić z guard-approved trust bundle dla danej epoki,
- lokalne pliki runtime takie jak `peers.json` i `action_token_pub.pem` są tylko materializacją aktywnego trust bundle, a nie samodzielnym source of truth,
- passphrase do `host vault` nie ma być trwałym sekretem na dysku; docelowy baseline to runtime secret w `/run/...` na `tmpfs`, a brak unseal ma kończyć się fail-closed,
- zwykłe escrow ma działać jako `AUTO multisig` po jednorazowym legalnym admission danego escrow do auto-runtime.

---

## 9a. Bootstrap runtime i source of truth

Kolejność bootstrapu przed pierwszym escrow:
1. Każdy host core generuje lokalnie własny zaszyfrowany `host vault` i lokalny publiczny `HostIdentityBundle`.
2. Do guardów trafiają tylko publiczne bundle hostów, nigdy prywatne sekrety hosta.
3. `AG-01 + AG-02` zatwierdzają aktywną epokę runtime i podpisują `runtime_trust_bundle`.
4. Każdy host materializuje lokalnie z aktywnego `runtime_trust_bundle` pliki runtime potrzebne do startu.
5. Host startuje tylko wtedy, gdy jego lokalny `host vault`, runtime unseal secret i aktywny trust bundle są zgodne; inaczej fail-closed.

Jedynym source of truth dla aktywnego trustu runtime jest:
- `runtime_trust_bundle` podpisany przez `AG-01 + AG-02`.

Lokalne pliki runtime są tylko projekcją tego bundle:
- `host vault` jest lokalnym sekretem hosta i nie pochodzi z zewnątrz,
- `peers.json` jest lokalną projekcją aktywnego peer setu z `runtime_trust_bundle`,
- `action_token_pub.pem` jest lokalną projekcją aktywnego publicznego klucza issuera runtime auth z `runtime_trust_bundle`.

`mailbox` tokeny są tylko scoped sekretami operacyjnymi transportu.
Nie są trust rootem, nie legalizują runtime i nie zastępują quorum guardów.

---

## 9b. Jednorazowe quorum AG dla escrow

Zwykłe escrow ma otrzymywać od `AG-01 + AG-02` dokładnie jeden konstytucyjny artefakt wejścia do auto-runtime:
- `escrow_admission_artifact`.

Ten artefakt ma wiązać co najmniej:
- `escrow_id`,
- `customer_identity_snapshot` dla `buyer` i `seller`,
- `runtime_trust_epoch`,
- policy dla zwykłego auto-flow danego escrow,
- hash intentu escrow przekazanego przez orchestrator.

Po wydaniu `escrow_admission_artifact`:
- `orchestrator` prowadzi zwykły `AUTO multisig`,
- `buyer` i `seller` nie sterują signerami,
- `AG-01` i `AG-02` nie uczestniczą już w każdym kroku codziennego runtime.

`action token` jest artefaktem wykonawczym, nie konstytucyjnym:
- wystawia go aktywny issuer runtime zatwierdzony w `runtime_trust_bundle`,
- signer weryfikuje go względem `action_token_pub.pem`,
- signer uznaje go tylko wtedy, gdy token mieści się w zakresie aktywnego `escrow_admission_artifact` i aktywnej epoki trustu.

---

## 9c. Kanoniczna mapa artefaktów

- `customer_identity_record`: powstaje w `customer service .onion` po poprawnym `register + challenge-response`; jest źródłem tożsamości klienta dla nowych escrow.
- `customer_identity_snapshot`: powstaje przy `open escrow`; jest zamrożonym przypięciem identity `buyer` i `seller` do konkretnego escrow.
- `host vault`: powstaje lokalnie na hoście runtime; zawiera prywatne klucze hosta i nie jest dostarczany przez guardy ani orchestrator.
- `HostIdentityBundle`: powstaje lokalnie z publicznej połowy `host vault`; jest jedynym artefaktem hosta przekazywanym do guardów przy bootstrapie.
- `runtime_trust_bundle`: powstaje z publicznych bundli hostów i jest podpisywany przez `AG-01 + AG-02`; jest jedynym source of truth dla aktywnego trustu runtime.
- `peers.json`: powstaje lokalnie jako projekcja `runtime_trust_bundle`; jest używany przez `nxms-transport`, ale nie jest samodzielnym trust rootem.
- `action_token_pub.pem`: powstaje lokalnie jako projekcja `runtime_trust_bundle`; wskazuje aktywny publiczny klucz issuera runtime auth.
- `escrow_admission_artifact`: powstaje dla konkretnego escrow z intentu orchestratora i snapshotu klienta; jest podpisywany przez `AG-01 + AG-02` raz, na wejściu escrow do auto-runtime.

---

## 9d. Współbieżność i execution lanes

Docelowy model ma rozdzielać:
- współbieżność stanową escrow,
- od bounded współbieżności wykonawczej.

To oznacza:
- wiele escrow może być aktywnych równolegle w stanach takich jak `multisig_setup_pending`, `funding_wait` albo `delivery_wait`,
- jedno długie escrow nie może monopolizować signer pair przez cały swój lifetime,
- każde escrow ma własny workflow state, własny wallet/workspace context i własne odniesienia do snapshot/admission/trust epoch,
- krytyczne sekcje wykonawcze, tj. `multisig ceremony step`, `sign` i `submit`, zużywają tylko krótki bounded execution slot.

Kontrakt skalowania:
- system ma być równoległy stanowo,
- execution ma być sekwencyjny albo o bardzo małej, kontrolowanej równoległości,
- klient nr 2 nie czeka na pełne zamknięcie escrow klienta nr 1; czeka co najwyżej na następny bounded slot wykonawczy dla swojej operacji,
- przy wzroście ruchu skaluje się przez kolejkowanie, bounded lanes i późniejszy sharding signer pair, a nie przez luzowanie guard/legality modelu.

To jest wymaganie architektoniczne, nie detal implementacyjny.
Model `AUTO multisig` ma pozostać:
- fail-closed,
- anti-capture first,
- bez pełnej równoległości w krytycznych operacjach wallet/sign/submit.

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
