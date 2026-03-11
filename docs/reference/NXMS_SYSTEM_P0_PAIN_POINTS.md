# NXMS System P0 Pain Points

To jest jawna lista bolączek systemu, których nie wolno zamiatać pod dywan.

Każdy punkt na tej liście ma być:
- rozwiązany w kodzie albo deployu,
- zapisany w docs,
- pokryty prawdziwym testem albo runtime gate.

## 1. Auth guard quorum nie jest jeszcze pełnym invariantem systemu

Stan:
- repo mówi o quorum proof,
- ale nie modeluje jeszcze pełnego `auth guard quorum 2 z 5` jako warunku istnienia systemu.

Ryzyko:
- control-plane albo signer mogą pozostać zbyt „samodzielne”.

Wymagany rezultat:
- bez `2 z 5` krytyczny flow nie istnieje.

## 2. Monero musi być całkowicie odcięte od clearnetu

Stan:
- kierunek jest już zapisany,
- ale runtime proof na natywnym Alpine dopiero jest budowany.

Ryzyko:
- przypadkowy clearnet exposure `monerod`,
- błędny bind albo fallback,
- fałszywe poczucie izolacji.

Wymagany rezultat:
- `monerod` Tor-only,
- `wallet-rpc` loopback-only,
- fail-closed przy złej konfiguracji.

## 3. Rotacja kluczy i sekretów nie ma jeszcze jednego kontraktu

Stan:
- są pojedyncze twarde wymagania dla tokenów i sekretów,
- ale brak jednego spójnego modelu lifecycle.

Ryzyko:
- improwizowana rotacja,
- brak overlap/cutover,
- zbyt duży blast radius.

Wymagany rezultat:
- wspólny model rotacji dla każdej klasy sekretu.

## 4. Host role model nie jest jeszcze finalnie spięty

Stan:
- wiadomo, że system docelowo jest rozproszoną siecią ról,
- ale deploy artifacts i docs nie pokrywają jeszcze pełnego modelu guard/signer/mailbox/orchestrator/Monero.

Ryzyko:
- mieszanie ról na hostach,
- złe ownership/perms,
- niejasne granice zaufania.

Wymagany rezultat:
- jedna tabela ról hostowych, dozwolonych bindów, egressu, sekretów i preflight checks.

## 5. Prawdziwe deploy/runtime gate'y nadal są niepełne

Stan:
- component truth i workspace E2E są mocno domknięte,
- mailbox over Tor jest udowodniony,
- Monero i signer runtime gate są jeszcze w budowie.

Ryzyko:
- repo wygląda na gotowsze niż jest,
- kolejne etapy opierają się na niepełnym runtime proof.

Wymagany rezultat:
- pełne P0 gates dla `Monero runtime`, `signer startup`, `sign/submit/orchestrated over Tor`.
