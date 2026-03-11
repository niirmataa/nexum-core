# NXMS Auth Guard Quorum Model

To jest kontrakt architektoniczny dla warstwy `auth guard`.

Jeśli implementacja, deploy albo testy są z nim sprzeczne, wygrywa ten dokument.

Dokument uzupełniający:
- `docs/NXMS_AUTH_GUARD_SECURITY_MODEL.md` określa model zagrożeń, klasy operacji, klasy sekretów, rotację, kompromitację i resurrection guardów.

## 1. Teza główna

`auth guard` nie jest dodatkiem do systemu.

`auth guard quorum` jest warunkiem istnienia systemu.
`auth guards` są sercem autentykacji, rotacji kluczy i trust root warstwy `nxms-transport`.

Bez ważnego quorum `2 z 5`:
- nie ma wejścia do krytycznego flow,
- nie ma wyjścia z krytycznego flow,
- nie ma legalnej decyzji autoryzacyjnej,
- orchestrator, signer ani mailbox nie mogą samodzielnie zastąpić tej warstwy.

## 2. Docelowe role

Docelowa sieć ról:
- `nxms-auth-guard`
- `nxms-mailbox`
- `nxms-signer`
- `nxms-escrow-orchestrator`
- `nxms-transport`
- `monerod`
- `monero-wallet-rpc` jako wyłącznie lokalna granica procesu, nie rola cross-host

Każda rola ma:
- osobny host albo osobny blast radius,
- osobne klucze i sekrety,
- osobny kontrakt bind/egress,
- osobny audit trail.

## 3. Quorum

Minimalny runtime quorum model:
- `5` guardów w zestawie,
- `2` ważne guard proofy wymagane do krytycznej decyzji,
- brak `2 z 5` oznacza `fail-closed`.

To jest minimum egzystencjalne systemu, nie tryb opcjonalny.

## 4. Za co odpowiada guard quorum

Guard quorum musi warunkować:
- wejście do flow,
- autoryzację `sign`,
- autoryzację `submit`,
- autoryzację finalnego wyjścia `release/refund/close/fail`,
- krytyczne przejścia stanu, które zmieniają nieodwracalny rezultat.

Jeżeli akcja jest nieodwracalna albo krytyczna, nie może przejść bez proofów guardów.

## 5. Rola orchestratora wobec guardów

Orchestrator:
- prowadzi workflow,
- agreguje stan,
- przechowuje proofy i ich spójność,
- wystawia tokeny tylko na podstawie prawdziwego stanu i prawdziwych proofów.

Orchestrator nie może:
- zastąpić quorum guardów własną lokalną decyzją,
- emitować ważnej decyzji bez guard proof,
- obchodzić fail-closed przy braku guardów.

## 6. Klucze i kryptografia

Warstwa guardów trzyma główne klucze autoryzacyjne systemu:
- podpisy `Falcon-1024-CT`,
- KEM/admission trust material oparte o `FrodoKEM`.

Bez `2` ważnych podpisów `Falcon-1024-CT` i poprawnego `KEM package`:
- system nie uruchamia się legalnie,
- system nie przechodzi legalnie przez żaden krytyczny punkt,
- restart po utracie sealed state, recovery albo relokacja nie są legalne.

Warstwa guardów odpowiada też za:
- kontrolę trust setu używanego przez `nxms-transport`,
- rotację głównych kluczy autoryzacyjnych i admission keys,
- publikację nowego aktywnego zestawu kluczy i okresów overlap/cutover,
- unieważnianie starych trust setów.

Doprecyzowanie:
- inne role nadal mają własne lokalne klucze transportowe i operacyjne,
- ale to guardy trzymają główny materiał zaufania, który warunkuje dopuszczenie do krytycznego flow.

Brak guard key material albo niespójność trust setu:
- ma blokować system,
- nie może być automatycznie obchodzona przez local override.

## 7. Sieć i izolacja

Docelowy model sieciowy:
- wszystkie role cross-host komunikują się tylko przez Tor hidden services,
- brak legalnej ścieżki clearnet między hostami,
- `wallet-rpc` tylko loopback,
- `monerod` docelowo tylko Tor-only,
- `mailbox` tylko onion relay/store-and-forward,
- `signer` tylko do `.onion` mailboxa i lokalnego `wallet-rpc`.

Guardy:
- mają własne onion endpointy,
- nie wystawiają się do clearnetu,
- nie powinny współdzielić hosta z rolami o innym blast radius, jeśli da się tego uniknąć.

## 8. Sekrety i rotacja

Klasy sekretów:
- guard root/admission keys,
- `nxms-transport` identity keys,
- action-token signing keys,
- mailbox scoped tokens,
- signer worker/service auth,
- Monero wallet i multisig material.

Każda klasa musi mieć jawny model:
- generacji,
- przechowywania,
- rolloutu,
- overlapu stary/nowy,
- cutover,
- revoke,
- audytu.

Bez tego system nie jest produkcyjnie gotowy.

## 9. Fail-closed invariants

To są twarde zasady:
- brak guard quorum `2 z 5` => brak systemu,
- brak ważnego guard proof => brak krytycznej akcji,
- brak `2x Falcon + KEM package` dla aktywacji albo krytycznego przejścia => brak legalnej aktywacji/przejścia,
- guard unreachable => fail-closed,
- `monerod` z clearnet exposure => błąd,
- `wallet-rpc` poza loopback => błąd,
- signer bez `.onion` mailboxa => błąd,
- sekrety o złym ownership/mode => błąd startu,
- rotacja bez jawnego overlap/cutover modelu => niedopuszczalna w produkcji.

## 10. Otwarte problemy P0

To nie są opcjonalne ulepszenia, tylko rzeczy do domknięcia:
- guardy nie są jeszcze osobnym komponentem runtime w repo,
- quorum `2 z 5` nie jest jeszcze pełnym invariantem kodu end-to-end,
- format guard proof i lifecycle guard keys nie są jeszcze finalnie zapisane,
- model operacji klasy `A/B/C` i resurrection contract nie są jeszcze spięte z runtime,
- rotacja sekretów i kluczy nie ma jeszcze jednej wspólnej polityki source-of-truth,
- host role model dla rozproszonej sieci nie jest jeszcze w pełni spięty z deploy artifacts,
- Monero runtime isolation (`monerod Tor-only`, `wallet-rpc loopback-only`) musi być udowodniona na natywnym Alpine runtime.

## 11. Definicja done dla tego modelu

Model jest naprawdę domknięty dopiero wtedy, gdy:
- guardy są jawnie modelowane jako osobna rola,
- krytyczne flow nie przechodzi bez `2 z 5`,
- signer i orchestrator weryfikują proofy fail-closed,
- deploy role są rozdzielone na hostach Tor-only,
- sekrety i rotacja mają wspólny, testowalny kontrakt,
- testy runtime i deploy potwierdzają ten model, nie tylko docs.
