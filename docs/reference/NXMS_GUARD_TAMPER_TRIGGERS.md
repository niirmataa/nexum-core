# NXMS Guard Tamper Triggers

To jest lista zdarzeń, które zawsze kończą się `quarantine` albo `shutdown` guard runtime.

To nie są ostrzeżenia operacyjne.
To są twarde `tamper triggers`.

## 1. Zasada

Jeśli guard wykrywa trigger z tej listy:
- nie próbuje działać dalej,
- nie przechodzi w degraded mode,
- nie zostawia decyzji operatorowi lokalnemu,
- przechodzi w `quarantine` albo zatrzymuje proces fail-closed.

## 2. Triggery binarki i konfiguracji

Zawsze `quarantine/shutdown`:
- binarka guard runtime nie zgadza się z zatwierdzonym hash albo artefaktem,
- wykryto nieautoryzowaną zmianę binarki,
- config nie zgadza się z zatwierdzonym hash albo artefaktem,
- wykryto nieautoryzowaną zmianę configu,
- uruchomienie następuje poza zatwierdzonym maintenance artifact,
- host próbuje wystartować z niezatwierdzoną ścieżką binarki albo configu.

## 3. Triggery sekretów i storage

Zawsze `quarantine/shutdown`:
- ownership sekretów jest nieprawidłowy,
- mode sekretów jest nieprawidłowy,
- brakuje wymaganego sekretu,
- secret store zwraca materiał niespójny z oczekiwanym epoch,
- wykryto rollback sealed state,
- wykryto niespójność lokalnego sealed state,
- wykryto nieautoryzowane odtworzenie starego key material.

## 4. Triggery epok, revoke i trust setu

Zawsze `quarantine/shutdown`:
- `system_epoch` lokalny nie zgadza się z oczekiwanym stanem guardów,
- `guard_set_epoch` jest niezgodny,
- używany artefakt został odwołany,
- używany artefakt jest poza cutover,
- lokalny trust set nie zgadza się z legalnym aktywnym trust setem,
- wykryto próbę użycia starego trust setu po revoke/cutover.

## 5. Triggery artefaktów i operacji

Zawsze `quarantine/shutdown`:
- operacja klasy `A` przychodzi bez wymaganego artefaktu,
- artefakt ma zły scope,
- artefakt ma zły host,
- artefakt ma złą rolę,
- artefakt wygasł,
- artefakt jest używany drugi raz, jeśli model zakłada single-use,
- `state_precondition` nie zgadza się z rzeczywistym stanem,
- maintenance artifact próbuje wykonać trust-changing operation,
- `GDA-5` jest używany poza maintenance scope.

## 6. Triggery operator access

Zawsze `quarantine/shutdown`:
- wykryto próbę bezpośredniego operator path poza guard layer,
- wykryto ręczne uruchomienie operacji klasy `A` poza legalnym flow,
- wykryto próbę obejścia maintenance artifact,
- wykryto lokalny override, który miałby zastąpić guard decision flow.

## 7. Triggery środowiska runtime

Zawsze `quarantine/shutdown`:
- guard wystawia się na niedozwolony bind albo niedozwoloną sieć,
- guard traci wymagany lokalny kontrakt izolacji,
- host uruchamia guard w niezatwierdzonym profilu runtime,
- wykryto niespójność krytycznych ścieżek plików albo mountów, jeśli są częścią trusted baseline.

## 8. Dopuszczalne reakcje

Dozwolone reakcje:
- natychmiastowy `shutdown`,
- wejście w stan `quarantine`,
- zapis audytu incydentu,
- oznaczenie guard key material do revoke,
- wymuszenie replace/re-issue flow.

Niedozwolone reakcje:
- `warning only`,
- automatyczne obejście problemu,
- lokalny fallback omijający guard policy,
- zwykły restart bez nowego legalnego flow.

## 9. Uwagi implementacyjne

Nie każdy trigger musi wyglądać identycznie na poziomie kodu.
Ale każdy trigger z tej listy musi dawać ten sam efekt semantyczny:
- guard przestaje być legalnym źródłem decyzji,
- system traktuje go jako nieufny,
- powrót wymaga jawnego flow `quarantine/revoke/replace`.
