# NXMS Auth Guard Security Model

To jest kontrakt bezpieczeństwa dla `nxms-auth-guard` jako trust root całego systemu.

Jeśli runtime, deploy, rotacja kluczy albo recovery są z nim sprzeczne, wygrywa ten dokument.

Dokument uzupełniający:
- `docs/NXMS_GUARD_DECISION_ARTIFACT_MODEL.md` zamraża wybór wariantów `GDA` dla klas operacji i ról systemowych.
- `docs/NXMS_MAINTENANCE_ARTIFACT_MODEL.md` opisuje kontrakt logiczny maintenance artifact dla `GDA-5`.
- `docs/NXMS_GUARD_TAMPER_TRIGGERS.md` zamraża listę zdarzeń kończących się `quarantine/shutdown`.
- `docs/NXMS_OFFLINE_RECOVERY_QUORUM_MODEL.md` opisuje abstrakcyjny model offline recovery quorum bez tajnych szczegółów operacyjnych.

## 1. Teza główna

`auth guard` jest najbardziej chronioną rolą w NXMS.

Guardy nie są zwykłą warstwą auth.
Guardy:
- utrzymują warunek istnienia systemu,
- utrzymują warunek reaktywacji systemu,
- utrzymują warunek przejścia przez wszystkie punkty krytyczne,
- są jedyną warstwą, która może legalnie odtworzyć system w nowym miejscu.

## 2. Główny model zagrożeń

Bazowy przeciwnik:
- może być cierpliwy i długotrwały,
- może przejmować hosty pojedynczo,
- może działać jak służby wywiadowcze albo dobrze zorganizowany insider,
- może powoli wiercić kanały, zbierać metadane i materiały operacyjne,
- może próbować podszywać się pod restart, update, migrację albo recovery.

Zakładamy:
- kompromitacja pojedynczego hosta jest realna,
- kompromitacja jednego komponentu runtime jest realna,
- długotrwała obserwacja części systemu jest realna,
- przeciwnik może znać architekturę systemu.

Nie zakładamy bezpieczeństwa przez nieznajomość projektu.
Bronimy się przez quorum, izolację, rotację, wygaszanie artefaktów i fail-closed.

## 3. Cele bezpieczeństwa guardów

Guardy mają zapewnić, że:
- przejęcie `mailbox`, `signer`, `orchestrator` albo `monerod` nie daje kontroli nad całym systemem,
- przejęcie jednego guarda nie daje prawa do aktywacji ani krytycznej decyzji,
- nawet dobrze poinformowany przeciwnik nie przejdzie przez trust-changing operations bez quorum,
- system da się odtworzyć w ciągu kilku godzin na nowych hostach i w nowej lokalizacji,
- kompromitacja jednego miejsca nie niszczy zdolności do resurrection.

## 4. Topologia guardów

Minimalny model:
- `5` guard hostów,
- `2 z 5` jako minimalne quorum aktywacyjne i krytyczne,
- każdy guard ma osobny blast radius,
- każdy guard ma własny onion endpoint,
- każdy guard ma własne sekrety lokalne i własny audit trail.

Wymagania hostowe:
- guard nie współdzieli hosta z `mailbox`, `signer`, `orchestrator`, `monerod`,
- guard ma najmniejszy możliwy surface runtime,
- guard ma najtwardszą politykę sekretów, logów i lokalnego dostępu,
- guard ma osobny lifecycle rotate/revoke/quarantine/replace.

Operator:
- nie ma bezpośredniej logicznej ścieżki do `signer`, `mailbox`, `orchestrator` ani `monerod`,
- legalna ścieżka operatorska do systemu prowadzi tylko przez `auth guard`,
- nawet operacje serwisowe na hostach runtime wymagają guard-approved maintenance artifact,
- dostęp hostowy nie może oznaczać prawa do zmiany trust state systemu.

## 5. Klasy operacji

### A. Egzystencjalne / trust-changing

Te operacje zawsze wymagają `2` ważnych podpisów `Falcon-1024-CT` i poprawnego `KEM package`:
- bootstrap systemu od zera,
- reaktywacja po utracie infrastruktury,
- odtworzenie w nowej lokalizacji,
- aktywacja nowego trust setu,
- rotacja guard root keys,
- odblokowanie systemu po fail-closed,
- wejście do krytycznego flow,
- `sign`,
- `submit`,
- finalne `release/refund/close/fail`.

### B. Wrażliwe operacyjnie

Te operacje nie zawsze wymagają pełnego recovery package, ale nie mogą samodzielnie zmienić trust root:
- aktualizacja binarki,
- restart procesu na tym samym hoście i z tym samym sealed stanem,
- wymiana hosta bez zmiany trust setu,
- rebind endpointów i rollout konfiguracji,
- restart po awarii bez utraty materiału zaufania.

Jeżeli operacja z klasy B zmienia tożsamość, trust set, klucze, lokalizację albo sealed state, wpada do klasy A.

### C. Zwykła eksploatacja

Te operacje nie dostają dodatkowego gate ponad normalny model runtime:
- healthcheck,
- housekeeping,
- retry,
- zwykła transmisja pakietów,
- lokalna diagnostyka niezmieniająca trust.

## 6. Invariant aktywacji i krytycznych przejść

System jako całość:
- nie uruchamia się legalnie bez `2` podpisów `Falcon`,
- nie przechodzi legalnie żadnego punktu krytycznego bez `2` podpisów `Falcon`,
- nie uruchamia się ani nie przechodzi legalnie przez punkt krytyczny bez poprawnego `KEM package`.

To oznacza:
- sam `orchestrator` nie może reaktywować systemu,
- sam `signer` nie może reaktywować systemu,
- sam `mailbox` nie może reaktywować systemu,
- pojedynczy guard nie może reaktywować systemu,
- dwa ważne podpisy bez poprawnego `KEM package` nie wystarczają,
- sam `KEM package` bez dwóch ważnych podpisów nie wystarcza.

## 7. Guard Decision Artifact

Każda operacja klasy A musi być opisana artefaktem guardów.

Minimalna zawartość artefaktu:
- typ operacji,
- `system_epoch`,
- `guard_set_epoch`,
- scope operacji,
- czas ważności,
- wymagany stan wejściowy,
- identyfikator pakietu `KEM`,
- `2` podpisy `Falcon` guardów.

Artefakt:
- jest weryfikowany fail-closed,
- nie może być użyty poza swoim epoch/scope/TTL,
- nie może być akceptowany po revoke albo cutover,
- nie może być odtwarzany z lokalnego override.

## 8. Klasy sekretów guardów

Sekrety guardów nie mogą być jednym wspólnym „super-sekretem”.

Minimalne klasy:
- quorum signing keys dla `Falcon`,
- package encryption / admission / activation keys dla `KEM`,
- recovery / resurrection package material,
- guard transport identity keys,
- lokalne host bootstrap secrets,
- lokalne atestation / audit secrets, jeśli są potrzebne.

Każda klasa ma osobny lifecycle:
- generacja,
- storage,
- aktywacja,
- rotacja,
- overlap,
- cutover,
- revoke,
- wymiana po kompromitacji,
- audyt użycia.

## 9. Rotacja kluczy

Rotacja guardów ma być agresywna, ale kontrolowana.

To znaczy:
- krótkie epoki kluczy,
- jawny overlap `old/new`,
- podpisany cutover artifact,
- możliwość natychmiastowego revoke,
- brak długotrwałego współistnienia nieoznaczonych trust setów,
- brak lokalnych override omijających cutover.

Rotacja nie może:
- zatrzymywać systemu bez planu recovery,
- tworzyć chaosu operacyjnego przez niejawne stany pośrednie,
- dopuszczać do „wiecznych” kluczy guard root.

## 10. Kompromitacja i kwarantanna

Model musi zakładać kompromitację pojedynczego guarda.

Po wykryciu albo podejrzeniu kompromitacji:
- guard przechodzi do `quarantine`,
- jego klucze i artefakty są oznaczane do revoke,
- system nie używa go jako legalnego źródła nowych decyzji,
- uruchamiany jest flow replace/reissue,
- cutover do nowego guard setu musi być podpisany przez legalne quorum.

Przejęcie jednego guarda:
- jest poważnym incydentem,
- nie może dawać aktywacji systemu,
- nie może dawać legalnej zmiany trust setu,
- nie może dawać legalnego recovery całego systemu.

## 10a. Tamper Response Policy

Guard runtime ma być tamper-reactive.

To znaczy:
- guard nie może próbować „pracować dalej” po wykryciu naruszenia,
- guard przechodzi do `quarantine` albo zatrzymuje proces,
- lokalny operator nie może tego obejść zwykłym restartem,
- powrót do legalnego stanu wymaga nowego zatwierdzonego flow guardów.

Minimalne zdarzenia wyzwalające tamper shutdown albo quarantine:
- niezatwierdzona zmiana binarki,
- niezatwierdzona zmiana konfiguracji,
- naruszenie ownership/mode sekretów,
- rollback stanu albo epoch,
- lokalny drift trust setu,
- użycie nieważnego albo odwołanego artefaktu,
- wykrycie niespójności sealed state,
- próba uruchomienia poza zatwierdzonym maintenance window/artifact.

Lista source-of-truth:
- pełna lista triggerów jest utrzymywana w `docs/NXMS_GUARD_TAMPER_TRIGGERS.md`.

Wymagany efekt:
- guard przestaje być legalnym źródłem nowych decyzji,
- system traktuje go jako nieufny do czasu replace/re-issue,
- nie istnieje tryb „warning only” dla naruszeń tej klasy.

Maintenance i operator access:
- nie mogą omijać guard layer,
- muszą używać `GDA-5`,
- nie mogą dawać efektu trust-changing.

Kontrakt maintenance:
- maintenance artifact jest opisany w `docs/NXMS_MAINTENANCE_ARTIFACT_MODEL.md`.

## 11. Resurrection i odtworzenie systemu

Guardy muszą umożliwiać odtworzenie systemu od podstaw w dowolnym miejscu na świecie w ciągu kilku godzin.

To oznacza:
- guardy utrzymują recovery contract dla całego systemu,
- recovery może wystartować na nowych hostach i nowej infrastrukturze,
- stary `mailbox`, `signer`, `orchestrator` i stare hosty nie są wymagane do odtworzenia,
- wymagane jest legalne quorum i poprawny `KEM package`,
- odtworzenie publikuje nowy aktywny trust set i nowe bootstrap artifacts.

Minimalny rezultat resurrection:
- aktywny guard trust root,
- aktywny `nxms-transport` trust set,
- bootstrap nowych hostów `mailbox`, `signer`, `orchestrator`,
- legalna aktywacja nowego środowiska bez zależności od starej lokalizacji.

## 11a. Offline Paper Recovery Quorum

System musi mieć offline recovery material poza runtime.

Wymagania:
- offline material nie jest zwykłym runtime secretem,
- offline material nie daje samodzielnej kontroli pojedynczej osobie,
- offline material służy tylko do resurrection / disaster recovery,
- offline material jest częścią quorum, nie pojedynczym master key.

Dopuszczalny model:
- papierowe albo offline `Falcon` recovery shares / recovery signers,
- fizycznie rozdzielone nośniki,
- przechowywanie poza aktywną infrastrukturą runtime,
- użycie tylko razem z innymi legalnymi składnikami quorum i `KEM package`.

Niedopuszczalny model:
- jeden papierowy klucz dający samodzielne odtworzenie systemu,
- jeden operator jako jedyne źródło resurrection,
- recovery oparte wyłącznie o lokalny dostęp do hosta runtime.

`nxms-boss` albo inny strażnik systemu może być depozytariuszem jednego offline składnika recovery, ale:
- nie może samodzielnie aktywować systemu,
- nie może samodzielnie zmienić trust setu,
- nie może samodzielnie obejść quorum resurrection.

Model source-of-truth:
- abstrakcyjny kontrakt offline quorum jest utrzymywany w `docs/NXMS_OFFLINE_RECOVERY_QUORUM_MODEL.md`,
- realny układ depozytu i realni depozytariusze nie trafiają do repo.

## 12. Czego nie wolno robić

Nie wolno:
- traktować guardów jak zwykłego pomocniczego auth service,
- przenosić guard root secrets do `orchestrator` albo `signer`,
- utrzymywać jednej klasy „master key” dla wszystkiego,
- dawać operatorowi bezpośredniej ścieżki logicznej do runtime core poza guardami,
- dopuszczać restartu po utracie sealed state jako zwykłego restartu,
- dopuszczać recovery bez prawdziwego quorum,
- utrzymywać pojedynczego papierowego klucza zdolnego do samodzielnego resurrection,
- opierać bezpieczeństwa na ukrywaniu architektury zamiast na kryptografii i invariantach.

## 13. Definicja done

Ten model jest domknięty dopiero wtedy, gdy:
- istnieje jawny runtime/deploy contract dla `5` guard hostów,
- operacje klasy A są wymuszane jako `2x Falcon + KEM package`,
- operacje klasy B i C są jawnie rozdzielone,
- guard secret classes mają jeden wspólny lifecycle contract,
- istnieje policy `tamper shutdown / quarantine / replace`,
- istnieje offline paper recovery quorum bez pojedynczego master key,
- istnieje flow `quarantine/revoke/replace/resurrection`,
- testy i deploy gates potwierdzają te zasady, a nie tylko docs.
