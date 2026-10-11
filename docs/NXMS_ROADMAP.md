# NXMS ROADMAP

Ten plik jest jedyną aktywną roadmapą i checklistą wykonawczą.

Ma pozostać krótki.
Nie trzyma historii.
Nie trzyma wariantów, które już odrzuciliśmy.
Nie dubluje `NXMS_STACK_SOURCE_OF_TRUTH.md`.

## Aktywna checklista

To jest jedyna lista, po ktorej idziemy krok po kroku.
Nie otwieramy nowych watkow, dopoki poprzedni krok nie jest domkniety albo
swiadomie odlozony.

### A. Porzadek docs
- [ ] Utrzymac tylko dwie klasy docs: `PRIMARY` i `REFERENCE`.
- [ ] Utrzymac jako PRIMARY tylko:
  - `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`
  - `docs/NXMS_ROADMAP.md`
  - `docs/NXMS_AUTH_GUARD_WORKING_NOTES.md`
- [ ] Trzymac reszte tylko w `docs/reference/`.
- [ ] Poprawic martwe linki po przenosinach do `docs/reference/`.
- [ ] Wyciac z aktywnych docs wszelkie resztki starego `2 z 5`.

### B. Model konstytucyjny
- [ ] Utrzymac quorum konstytucyjne `2 z 2`.
- [ ] Utrzymac operatora poza quorum jako witness operacyjny.
- [ ] Utrzymac warstwe komunikacji dostepnosci `AG <-> AG` i `operator <-> AG` jako niedecyzyjna.
- [ ] Zamrozic waski tryb awaryjnego domkniecia escrow i `END SYSTEM`.
- [x] Domknac model jednorazowego `escrow admission artifact` od `AG-01 + AG-02` dla zwyklego `AUTO multisig`.

### B1. Bootstrap trustu i artefaktow runtime
- [ ] Dostosowac lifecycle publicznej tozsamosci i snapshotu klienta do modelu bez kont, rejestracji i logowania; zamkniecie poprzedniego modelu `register/login` nie pokrywa nowego kontraktu.
- [x] Domknac source of truth dla aktywnego `runtime trust bundle`.
- [x] Domknac pochodzenie `host vault`, `peers.json` i `action_token_pub.pem`.
- [x] Domknac zasade, ze `mailbox` tylko przesyla, a nie legalizuje runtime.

### C. All-in-one logical split
- [ ] Uruchomic na jednym hoście jako oddzielne role logiczne:
  - `ag-01`
  - `ag-02`
  - `orchestrator`
  - `mailbox`
  - `signer-a + monero-a`
  - `signer-b + monero-b`
- [ ] Rozdzielic role na osobne konta systemowe.
- [ ] Rozdzielic katalogi stanu, logi i sekrety.
- [ ] Testowac relacje miedzyhostowe przez Tor juz na jednym hoście.

### D. Monero / Alpine / OpenRC
- [ ] Dokonczyc source build Monero na Alpine/musl.
- [ ] Potwierdzic `monerod-stagenet` over Tor-only.
- [ ] Potwierdzic `wallet-rpc` loopback-only.
- [ ] Domknac OpenRC dla aktywnego runtime:
  - `nxms-mailbox`
  - `nxms-signer`
  - `nxms-escrow-orchestrator` jesli stanie sie realnym daemonem runtime

### E. Runtime cleanup
- [ ] Domknac wydzielenie `nxms-monero-core` jako rzeczywistego rdzenia domenowego Monero / multisig.
- [ ] Domknac migracje `nxms-signer` do docelowego execution node bez legacy driftu.
- [ ] Domknac migracje `nxms-escrow-orchestrator` do czystego workflow control-plane bez starego HTTP-first modelu.
- [ ] Usunac stare HTTP pathy z runtime core.
- [ ] Usunac direct legacy sign/submit z glownego flow.
- [ ] Utrzymac `tools/nexum-cli` jako manual auth/crypto only.
- [ ] Zwęzic `tools/nexum-cli` implementacyjnie do:
  - auth
  - lokalny vault
  - challenge-response
  - sign / verify
  - key generation

### F. Lokalny dashboard w Dockerze

Zakres: haslo lokalnego vaulta, jawne zatwierdzenie challenge i podglad
istniejacego escrow. Bez kont, rejestracji, logowania i WASM. Kontrakt:
`NXMS_STACK_SOURCE_OF_TRUTH.md` sekcje 8a-8c. Plan wykonawczy:
`reference/NXMS_LOCAL_DASHBOARD_PLAN.md`.

- [ ] Zamrozic kontrakt bezkontowego challenge, powiazanie klucza z escrow, uprawnienie odczytu i lifecycle kluczy kanalu transportowego; nie uzywac legacy `register/login`.
- [ ] Przygotowac graficzny przebieg na danych syntetycznych: Tor, vault, challenge, haslo, podglad i bledy; jawnie oznaczyc dane demonstracyjne.
- [ ] Wydzielic natywny adapter vault/podpis i przejrzec tylko uzywana sciezke; pelny review starego CLI pozostaje odlozony.
- [ ] Dodac lokalny backend i adapter customer service przez Tor z kanonicznym `NxmsEnvelope`.
- [ ] Przygotowac obrazy runtime i Compose: hostowy loopback, trwaly zaszyfrowany vault, limity i brak dostepu do socketu Dockera.
- [ ] Potwierdzic caly przebieg oraz odmowy dostepu, replay, restart i utrate Tora; testy i kompilacje wykonywac kolejno z jednym zadaniem.

## Zasady ogólne

- Nie dodawaj drugiego równoległego flow.
- `tools/nexum-cli` nie może być dependency ścieżki krytycznej runtime.
- Break-glass i shadow mode nie mogą być domyślną drogą działania.
- Każda większa zmiana ma mieć test albo jawny powód braku testu.
