# NXMS Offline Recovery Quorum Model

To jest abstrakcyjny model `offline recovery quorum` dla NXMS.

Ten dokument:
- opisuje tylko logikę i granice modelu,
- nie zawiera tajnych szczegółów operacyjnych,
- nie wskazuje osób,
- nie wskazuje lokalizacji,
- nie opisuje realnego układu depozytu.

## 1. Cel

`offline recovery quorum` istnieje wyłącznie po to, aby:
- umożliwić legalne odtworzenie systemu po katastrofie,
- umożliwić resurrection w nowej lokalizacji,
- utrzymać ciągłość trust root poza aktywnym runtime,
- nie dopuścić do pojedynczego punktu przejęcia systemu.

To nie jest zwykły mechanizm operatorski.
To nie jest zwykły mechanizm maintenance.
To nie jest ścieżka codziennego runtime.

## 2. Zasada podstawowa

Recovery offline:
- jest poza runtime,
- jest poza aktywną infrastrukturą hostów,
- jest aktywowane tylko w scenariuszach klasy `A`,
- działa tylko jako część legalnego quorum,
- nie istnieje jako pojedynczy master key.

## 3. Minimalny model logiczny

Abstrakcyjny model na dziś:
- istnieje offline `Falcon` recovery material,
- materiał jest podzielony na `4` części,
- części są fizycznie i organizacyjnie rozdzielone,
- sam podział nie daje jeszcze samodzielnego resurrection,
- użycie recovery wymaga nadal zgodności z modelem `2x Falcon + KEM package`.

Ten dokument nie określa:
- kto posiada części,
- gdzie są przechowywane,
- jak wyglądają realne nośniki,
- jaki jest dokładny proces fizycznego dostępu.

To jest informacja ściśle tajna i pozostaje poza repo.

## 4. Co offline quorum ma umożliwiać

Offline quorum ma umożliwiać:
- odtworzenie legalnego trust root,
- bootstrap nowego środowiska guardów,
- publikację nowego aktywnego trust setu,
- przywrócenie zdolności do aktywacji systemu,
- odtworzenie systemu w ciągu kilku godzin od uruchomienia procedury disaster recovery.

## 5. Czego offline quorum nie może umożliwiać

Offline quorum nie może być używane do:
- codziennej pracy operatorskiej,
- zwykłego maintenance hostów,
- zwykłego restartu usług,
- bezpośredniego `sign`,
- bezpośredniego `submit`,
- zwykłej zmiany konfiguracji runtime,
- obchodzenia guard runtime policy.

## 6. Relacja do guard runtime

Guard runtime:
- obsługuje normalne operacje systemu,
- może wejść w `quarantine`,
- może zostać zastąpiony,
- może zostać utracony.

Offline recovery quorum:
- nie zależy od bieżącego stanu utraconego runtime,
- nie ufa skażonemu hostowi tylko dlatego, że host nadal istnieje,
- służy do odtworzenia legalnej podstawy systemu po incydencie.

## 7. Relacja do `2x Falcon + KEM package`

Offline recovery quorum nie zastępuje modelu:
- `2x Falcon`,
- `KEM package`,
- epoch,
- revoke/cutover,
- fail-closed.

Offline recovery quorum jest jedną z warstw, która ma umożliwić legalne odtworzenie tych warunków.

Znaczy to:
- sama część offline material nie wystarcza,
- sam papierowy recovery share nie wystarcza,
- samo posiadanie dostępu do hosta runtime nie wystarcza,
- recovery musi odtworzyć system z powrotem do modelu guard quorum, nie obok niego.

## 8. Wymagania bezpieczeństwa

Model offline quorum musi spełniać:
- brak pojedynczego podmiotu zdolnego do samodzielnego resurrection,
- brak pojedynczej lokalizacji zdolnej do samodzielnego resurrection,
- brak zależności od jednego hosta runtime,
- brak zależności od jednego operatora,
- możliwość użycia po utracie części infrastruktury,
- możliwość użycia po kompromitacji części infrastruktury.

## 9. Wymagania operacyjne

Model offline quorum musi być:
- rzadko używany,
- regularnie przeglądany,
- testowany scenariuszowo,
- zgodny z guard epoch / revoke / cutover policy,
- spięty z procedurą resurrection, a nie z codzienną administracją.

Testowanie nie musi oznaczać realnego użycia tajnego materiału produkcyjnego.
Może oznaczać ćwiczenie procedury, kontroli i kolejności kroków.

## 10. Poziomy tajności

W repo można trzymać:
- model logiczny,
- invarianty,
- wymagania bezpieczeństwa,
- wymagania operacyjne.

Poza repo muszą pozostać:
- realni depozytariusze części,
- realne lokalizacje,
- realne nośniki,
- realny sposób fizycznego odtworzenia,
- realne procedury dostępu do materiału tajnego.

## 11. Definicja done

Model offline recovery quorum jest domknięty dopiero wtedy, gdy:
- istnieje jawny abstrakcyjny kontrakt architektoniczny,
- nie ma pojedynczego master key,
- wiadomo, że recovery jest częścią quorum, nie obejściem quorum,
- model jest spięty z resurrection flow,
- tajne szczegóły są trzymane poza repo,
- istnieje możliwość ćwiczenia procedury bez ujawniania materiału tajnego.
