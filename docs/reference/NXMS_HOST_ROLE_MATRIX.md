# NXMS Host Role Matrix

To jest docelowy dokument `host-role matrix` dla NXMS.

Na tym etapie:
- zamraża minimalne, już pewne granice ról hostowych,
- nie udaje jeszcze finalnego deploy spec,
- ma być uzupełniany po pierwszych realnych uruchomieniach i testach runtime.

Jeśli późniejszy runtime pokaże, że jakaś rola potrzebuje doprecyzowania:
- dopisujemy to tutaj,
- nie rozpraszamy tej wiedzy po przypadkowych notatkach.

## 1. Cel dokumentu

Ten dokument ma docelowo opisywać dla każdej roli:
- funkcję roli,
- dozwolone bindy,
- dozwolony egress,
- klasy sekretów,
- relacje z innymi rolami,
- operator access model,
- maintenance model,
- preflight checks,
- fail-closed conditions.

## 2. Status

Status na dziś:
- kontrakt logiczny: częściowo zamrożony,
- finalne szczegóły host/runtime: do uzupełnienia po pierwszych realnych uruchomieniach.

Nie wpisujemy tutaj na siłę szczegółów, których jeszcze nie potwierdził runtime.

## 3. Role

### `auth-guard`

Pewne już dziś:
- jest trust root systemu,
- jest jedyną legalną warstwą operatorskiego wejścia do systemu,
- działa fail-closed,
- jest tamper-reactive,
- nie powinien współdzielić hosta z `signer`, `mailbox`, `orchestrator`, `monerod`,
- nie powinien mieć legalnej ścieżki clearnet cross-host.

Do dopięcia później:
- finalne bindy,
- finalny egress contract,
- finalny maintenance path,
- finalny runtime preflight.

### `signer`

Pewne już dziś:
- jest execution node,
- wykonuje `sign` i `submit`,
- trzyma lokalne sekrety operacyjne,
- komunikuje się z lokalnym `wallet-rpc`,
- nie jest legalnym bezpośrednim endpointem operatorskim,
- nie może zastąpić guard layer.

Do dopięcia później:
- finalne bindy i service auth path,
- dokładny operator maintenance model,
- finalne restart/rejoin rules.

### `mailbox`

Pewne już dziś:
- jest relay/store-and-forward,
- nie podejmuje decyzji biznesowych,
- nie jest źródłem prawdy workflow,
- nie powinien znać plaintextu payloadów,
- nie jest legalnym operatorem trust decisions.

Do dopięcia później:
- finalny auth surface,
- finalny inbox/principal scoping,
- finalne maintenance rules.

### `orchestrator`

Pewne już dziś:
- jest control-plane workflow,
- trzyma stan i proof aggregation,
- nie jest ostatecznym źródłem autoryzacji,
- nie może zastąpić guard quorum,
- nie powinien utrzymywać drugiego execution path.

Do dopięcia później:
- finalny runtime shape,
- finalny bind/egress contract,
- finalne maintenance/recovery granice.

### `monerod`

Pewne już dziś:
- jest warstwą Monero daemon,
- ma działać Tor-only,
- local RPC pozostaje local boundary,
- nie jest elementem trust root NXMS,
- nie jest legalnym operatorskim entrypointem do logiki systemu.

Do dopięcia później:
- finalny runtime contract po pierwszych stabilnych syncach,
- finalny OpenRC/deploy contract,
- finalne preflight checks.

## 4. Zasady wspólne

Wspólne zasady dla wszystkich ról:
- brak bezpośredniej ścieżki operatorskiej do runtime core poza guard layer,
- role hostowe są hermetyczne i wąskie,
- każda rola ma własny blast radius,
- każda rola ma osobny lifecycle maintenance i recovery,
- rzeczywisty host-role contract dopinamy po uruchomieniach, a nie na wyobrażeniu.

## 5. Definicja done

Ten dokument będzie naprawdę domknięty dopiero wtedy, gdy dla każdej roli będą zapisane:
- finalne bindy,
- finalny egress,
- finalne sekrety,
- finalny maintenance model,
- finalne fail-closed triggers,
- realne preflight checks potwierdzone na uruchomionym systemie.
