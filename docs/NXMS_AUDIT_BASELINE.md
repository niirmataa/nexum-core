# NXMS Audit Baseline

Last update: 2026-03-11

Ten dokument zamraża minimalny, użyteczny model audytu dla dwóch środowisk:

- `WSL`: audyt repo-centric
- `VM`: audyt host-centric

Cel nie jest "logować wszystko", tylko uzyskać wiarygodny sygnał:

- kto dotyka repo i archiwum,
- kto uruchamia procesy na hoście runtime,
- kto czyta albo modyfikuje krytyczne pliki,
- kto próbuje wejść w obszary operatorskie, kluczowe lub konfiguracyjne.

## 1. Zasada ogólna

NXMS nie używa śmieciowych warningów jako głównego modelu obserwacji.

Wymagany jest:

- stabilny `auditd` na hostach, które mają realną wartość operacyjną,
- precyzyjne watch rules na ścieżki i zdarzenia o wysokim sygnale,
- osobny profil dla środowiska developerskiego i osobny dla runtime,
- możliwość szybkiego odczytu ostatnich zdarzeń bez ręcznego przekopywania całego journala.

## 2. Podział odpowiedzialności

### WSL

`WSL` nie jest traktowany jako docelowy host runtime NXMS.

`WSL` ma być audytowany głównie pod:

- `.git`
- `.git-archive`
- bundle
- reflogi
- pliki shell hygiene / operator traces

To jest audyt środowiska pracy nad repo, nie pełny audit runtime core.

### VM

`VM` jest traktowana jako realny host runtime i musi mieć silniejszy audyt.

`VM` ma śledzić:

- krytyczne katalogi configu,
- binarki runtime,
- skrypty init / service files,
- logowania i uruchamianie procesów,
- odczyt i modyfikację plików operatorskich,
- próby dotykania sekretów, transportu, Tora i Monero boundary.

Logi audytu na hoście runtime:

- mają być zapisywane do katalogu obsługiwanego wyłącznie przez `root`,
- nie mają być czytelne dla operatora runtime,
- ich przegląd ma być jawnie ograniczony do roota,
- próby dotykania konfiguracji audytu albo samych logów mają być objęte osobnym kluczem audytu.

## 3. Wymagane profile

Repo utrzymuje dwa profile reguł:

- `deploy/audit/wsl-repo.rules`
- `deploy/audit/alpine-vm.rules`

Te profile są minimalne, celowe i mają być rozwijane tylko wtedy, gdy runtime pokaże realną lukę obserwacyjną.

## 4. Kryterium jakości

Dobry audyt NXMS:

- daje mało zdarzeń o wysokim znaczeniu,
- pokazuje realny dotyk pliku albo uruchomienie procesu,
- pozwala szybko odpowiedzieć "czy ktoś tu zaglądał",
- nie jest oparty na verbose telemetry bez wartości operacyjnej.

Zły audyt NXMS:

- zalewa operatora tysiącami technicznych eventów,
- nie odróżnia repo od runtime,
- nie pokazuje, które zdarzenia są egzystencjalne dla systemu.

## 5. Klucze zdarzeń

Reguły powinny używać stabilnych kluczy `auditd`, tak aby raporty można było czytać po kategoriach:

- `nxms-repo`
- `nxms-archive`
- `nxms-bundle`
- `nxms-shell-trace`
- `nxms-runtime-config`
- `nxms-runtime-bin`
- `nxms-runtime-init`
- `nxms-identity`
- `nxms-audit-config`
- `nxms-audit-log`
- `nxms-tor`
- `nxms-monero`
- `nxms-exec`

## 6. Odczyt zdarzeń

Podstawowy odczyt ma być robiony przez:

- `ausearch -k <key>`
- `aureport`
- `tools/nxms-audit-report.sh`

## 7. Granice

Ta warstwa:

- nie zastępuje guardów,
- nie zastępuje tamper response,
- nie zastępuje integralności repo,
- nie ma zgadywać intencji przeciwnika.

Ma dawać wiarygodny ślad:

- że ktoś dotknął ważnego miejsca,
- kiedy to zrobił,
- jako jaki użytkownik,
- jakim procesem.
