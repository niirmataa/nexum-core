# NXMS All-in-One Logical Layout

Klasa:
- `REFERENCE`

Status:
- pomocniczy szkic wdrożeniowy etapu `all-in-one`
- nie jest source of truth
- w razie konfliktu wygrywa `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`

To jest szybki dokument kierunkowy dla etapu, w ktorym caly system NXMS dziala
jeszcze na jednym hostcie.

Nie opisuje on docelowej izolacji fizycznej.
Opisuje tylko:
- jak logicznie rozdzielic role juz teraz,
- jak testowac realna siec przez Tor,
- czego nie wolno mieszac nawet na jednym systemie,
- jak przygotowac system do pozniejszego rozbicia na VM i hosty fizyczne.

Powiazane dokumenty:
- [NXMS_STACK_SOURCE_OF_TRUTH](../NXMS_STACK_SOURCE_OF_TRUTH.md)
- [NXMS_AUTH_GUARD_WORKING_NOTES](../NXMS_AUTH_GUARD_WORKING_NOTES.md)
- [NXMS_AUTH_GUARD_BRAINSTORM_QUESTIONS](./NXMS_AUTH_GUARD_BRAINSTORM_QUESTIONS.md)

## 1. Cel etapu all-in-one

Etap all-in-one nie ma udawac finalnego bezpieczenstwa infrastrukturalnego.

Ma sluzyc do:
- budowy poprawnego modelu logicznego,
- rozdzielenia rol,
- sprawdzenia realnych polaczen przez Tor,
- testowania admission, challenge, checkpointow i flow,
- przygotowania systemu do pozniejszego rozdzielenia na VM i hosty fizyczne.

Zasada:
- implementujemy tak, jakby role byly juz osobnymi hostami,
- uruchamiamy tymczasowo na jednym systemie.

## 2. Role logiczne

Na etapie all-in-one zakladamy nastepujace role logiczne:

- `ag-01`
- `ag-02`
- `orchestrator`
- `mailbox`
- `signer-a + monero-a`
- `signer-b + monero-b`
- opcjonalnie `operator-console` jako osobne srodowisko logiczne

To nie oznacza jeszcze 7 fizycznych maszyn.
To oznacza odrebne odpowiedzialnosci, ktore juz teraz nie powinny byc
projektowane jak jedna wspolna rola.

### 2a. Rola kazdej maszyny logicznej

- `ag-01`
  - konstytucyjny podmiot podpisujacy,
  - jeden z dwoch jedynych podpisow decyzyjnych,
  - brak prawa do jednostronnego dzialania,
  - przy utracie `ag-02` moze tylko informowac o stanie awarii.

- `ag-02`
  - konstytucyjny podmiot podpisujacy,
  - drugi z dwoch jedynych podpisow decyzyjnych,
  - brak prawa do jednostronnego dzialania,
  - przy utracie `ag-01` moze tylko informowac o stanie awarii.

- `orchestrator`
  - control-plane flow,
  - prowadzi automat escrow,
  - pilnuje timeoutow i stanów procesu,
  - nie jest samodzielnym zrodlem legalnosci ani trust root.

- `mailbox`
  - jedyny relay/store-and-forward,
  - nie zna logiki biznesowej escrow,
  - nie podejmuje decyzji workflow,
  - nie moze byc traktowany jako zastępnik orchestratora ani guardów.

- `signer-a + monero-a`
  - lokalny capability node z kluczami i lokalna logika wykonawcza,
  - posiada lokalny boundary `monerod` / `wallet-rpc`,
  - konsumuje / produkuje transport przez mailbox,
  - nie jest control-plane i nie jest operator surface.

- `signer-b + monero-b`
  - drugi capability node,
  - symetryczny do `signer-a + monero-a`,
  - posiada lokalny boundary `monerod` / `wallet-rpc`,
  - brak samodzielnej roli konstytucyjnej.

- `operator-console`
  - ograniczone srodowisko operatorskie,
  - daje witness operacyjny i dostep do bounded operator scope,
  - nie jest host adminem runtime ani czescia quorum konstytucyjnego.

## 3. Konta systemowe

Kazda rola powinna dzialac pod osobnym kontem systemowym.

Minimalny podzial:
- `nxms-ag01`
- `nxms-ag02`
- `nxms-orch`
- `nxms-mailbox`
- `nxms-signer-a`
- `nxms-signer-b`
- `monero-a`
- `monero-b`
- opcjonalnie `nxms-operator`

Cel:
- ograniczenie blast radius,
- brak dostepu jednej roli do plikow drugiej,
- latwiejszy audit,
- latwiejsze pozniejsze rozdzielenie na VM.

## 4. Katalogi i dane

Kazda rola powinna miec:
- osobny katalog stanu,
- osobny katalog logow,
- osobny plik konfiguracyjny,
- osobne sekrety,
- osobne uprawnienia do plikow.

Nie wolno:
- wspoldzielic sekretow miedzy rolami,
- trzymac wszystkich configow w jednym katalogu z szerokimi uprawnieniami,
- dawac jednej roli dostepu do wrazliwych plikow drugiej "dla wygody".

## 5. Networking w etapie all-in-one

### 5.1. Co testujemy przez Tor juz teraz

Przez Tor powinny isc te relacje, ktore docelowo i tak beda miedzyhostowe:

- `user -> user-facing onion surface`
- `operator -> operator/admission surface`
- `orchestrator -> mailbox`
- `signer-a -> mailbox`
- `signer-b -> mailbox`
- docelowo takze sciezki sieciowe do `ag-01` / `ag-02`, jesli beda realizowane
  jako relacje miedzy osobnymi hostami

Powod:
- to daje realny test sciezki sieciowej,
- test onion ingress/egress,
- test opoznien, timeoutow i zachowania warstw komunikacyjnych,
- test modelu "Tor-only" juz przed rozbiciem na osobne hosty.

### 5.1a. Podstawowy model polaczen logicznych

- `operator-console -> auth/admission surface`
  - przez Tor / `.onion`
  - tylko bounded operator scope

- `user-facing surface -> orchestrator`
  - przez Tor / `.onion`
  - user nie ma direct dostepu do runtime core

- `orchestrator -> mailbox`
  - przez Tor / `.onion`

- `signer-a -> mailbox`
  - przez Tor / `.onion`

- `signer-b -> mailbox`
  - przez Tor / `.onion`

- `ag-01 <-> ag-02`
  - systemowa, szyfrowana warstwa dostepnosci i challenge
  - nie jest zwyklym "admin kanałem"

- `operator-console <-> ag-01`
  - szyfrowana warstwa dostepnosci / witness
  - nie tworzy quorum konstytucyjnego

- `operator-console <-> ag-02`
  - szyfrowana warstwa dostepnosci / witness
  - nie tworzy quorum konstytucyjnego

- `orchestrator -> ag-01/ag-02`
  - tylko dla admission / decision artifacts / checkpoint flow
  - nie jako dowolny operator admin channel

- `signer-a -> monero-a`
  - tylko lokalny boundary wykonawczy
  - nie jest międzyhostowym kanałem operatorskim

- `signer-b -> monero-b`
  - tylko lokalny boundary wykonawczy
  - nie jest międzyhostowym kanałem operatorskim

### 5.2. Co zostaje lokalne na loopback

Na loopback powinny zostac rzeczy, ktore docelowo i tak beda lokalnym boundary:

- `monerod`
- `wallet-rpc`
- lokalne health checks
- lokalne adaptery techniczne procesu

Powod:
- nie wszystko musi isc przez Tor,
- nie nalezy komplikowac na sile warstw, ktore i tak nie sa komunikacja
  miedzyhostowa.

## 6. Co jest zabronione nawet na jednym hoście

Nawet na etapie all-in-one nie wolno:

- traktowac jednego hosta jako jednej roli "admin/system",
- dawac operatorowi bezposredniego dostepu do runtime core,
- dawac operatorowi direct API do `signer`, `mailbox`, `monerod`, `wallet-rpc`,
- mieszac `mailbox` z `orchestrator` logicznie jako jednego procesu odpowiedzialnosci,
- mieszac `AG` z operator scope,
- projektowac systemu "pod jeden host", jesli docelowo ma byc wielohostowy,
- dodawac wygodnych bypassow tylko dlatego, ze wszystko stoi lokalnie.

## 7. Minimalna logika izolacji na jednym hoście

Na jednym systemie izolujemy tyle, ile sie realnie da:

- osobne konta,
- osobne procesy,
- osobne katalogi stanu,
- osobne bindy,
- osobne sekrety,
- osobne logi,
- brak szerokich uprawnien miedzy rolami,
- maksymalnie waski lokalny dostep.

To nie zastepuje izolacji hostowej.
To jest logiczna separacja przygotowujaca system do nastepnych etapow.

## 8. Operator w etapie all-in-one

Operator nie powinien miec "normalnego konta administracyjnego" na hostach runtime.

Na tym etapie mozna przyjac:
- operator ma oddzielne srodowisko logiczne,
- operator ma ograniczony admission path,
- operator nie jest host adminem runtime,
- operator nie zarzadza swobodnie procesami,
- operator pilnuje flow i eskaluje zgodnie z modelem.
- operator daje podpis obecnosci / witness operacyjny,
- operator nie tworzy legalnosci systemu i nie wchodzi do quorum `2 z 2`.

Jesli tymczasowo nie ma osobnej maszyny operatorskiej:
- nalezy i tak trzymac logike operatora jako oddzielna role,
- nie wolno utozsamiac operatora z rootem hosta runtime.

## 9. Kolejnosc dojrzewania systemu

Etap 1:
- jeden host,
- rozdzielone role logiczne,
- Tor dla relacji miedzyhostowych,
- lokalna izolacja procesowa i systemowa

Etap 2:
- rozbicie na VM zgodnie z rolami logicznymi

Etap 3:
- rozbicie na hosty fizyczne

Etap 4:
- rozdzial geograficzny / rozne lokalizacje

Najwazniejsza zasada:
- architektura ma byc poprawna logicznie juz od etapu 1,
- fizyczna separacja jest pozniejszym wzmocnieniem, a nie poprawka zlego modelu.

## 10. Docelowy kierunek

Docelowo system ma byc rozdzielony na osobne byty infrastrukturalne.

Ale juz na etapie all-in-one:
- `AG` nie sa operatorem,
- `mailbox` nie jest orchestratoriem,
- `signer` nie jest hostem operatorskim,
- `monero` boundary jest lokalnie przypiete do signera, a nie do control-plane,
- operator nie ma swobody dowolnego ruchu po systemie.

### 10a. Twardy werdykt obecnego modelu

- Konstytucyjne quorum: `2 z 2`
- Podpisy decyzyjne: tylko `AG-01` i `AG-02`
- Podpis operatora: witness operacyjny / obecnosc
- Dodatkowa warstwa: szyfrowana komunikacja dostepnosci miedzy `AG-01`,
  `AG-02` i operatorem
- Pojedynczy `AG` po utracie drugiego:
  - nie moze reaktywowac systemu,
  - nie moze legalnie zmieniac systemu,
  - moze tylko informowac o stanie awarii
- Dopuszczalny jest tylko bardzo waski tryb awaryjnego domkniecia escrow i
  przejscia do `END SYSTEM`.

## 10b. Krótka Checklista Etapu All-in-One

- [ ] `ag-01`, `ag-02`, `orchestrator`, `mailbox`, `signer-a + monero-a`, `signer-b + monero-b` są rozdzielone logicznie
- [ ] Każda rola działa pod osobnym kontem systemowym
- [ ] Sekrety i katalogi stanu nie są współdzielone między rolami
- [ ] Relacje docelowo międzyhostowe są testowane przez Tor
- [ ] `monerod` i `wallet-rpc` pozostają lokalnym boundary signera
- [ ] Operator nie ma direct API do runtime core

To jest podstawowy kierunek.
Szczegoly polaczen, checkpointow, challenge, admission i stanów systemu beda
rozwijane dalej na bazie tego szkicu.
