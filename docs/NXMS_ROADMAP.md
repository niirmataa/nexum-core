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
  - registration
  - challenge-response
  - sign / verify
  - key generation

## Zasady ogólne

- Nie dodawaj drugiego równoległego flow.
- `tools/nexum-cli` nie może być dependency ścieżki krytycznej runtime.
- Break-glass i shadow mode nie mogą być domyślną drogą działania.
- Każda większa zmiana ma mieć test albo jawny powód braku testu.
