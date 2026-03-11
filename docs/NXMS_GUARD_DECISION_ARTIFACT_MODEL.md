# NXMS Guard Decision Artifact Model

To jest kontrakt wyboru wariantów `GDA` dla NXMS.

Nie opisuje jeszcze finalnego wire/payload formatu.
Zamraża:
- które warianty `GDA` są używane,
- do jakich operacji,
- przez które role są weryfikowane,
- jaki mają sens operacyjny.

## 1. Warianty przyjęte do NXMS

### GDA-2: State-Bound

To jest bazowy standard dla NXMS.

Cechy:
- artefakt jest związany z konkretnym stanem wejściowym,
- działa tylko przy zgodnym `state_precondition`,
- jest fail-closed przy epoch mismatch, revoke, TTL expiry albo state drift.

Przeznaczenie:
- operacje krytyczne klasy `A`,
- codzienne krytyczne checkpointy runtime.

### GDA-3: Intent + Commit

To jest wariant dla cięższych operacji trust-changing.

Cechy:
- operacja ma fazę `intent`,
- operacja ma fazę `commit`,
- pozwala rozdzielić przygotowanie od finalnej aktywacji.

Przeznaczenie:
- recovery,
- relokacja,
- zmiana trust setu,
- ciężkie maintenance z efektem systemowym.

### GDA-5: Capability / Maintenance

To jest wariant dla wąskich operacji serwisowych.

Cechy:
- bardzo wąski scope,
- bardzo krótki TTL,
- przypisanie do konkretnego hosta/roli/akcji,
- nie daje prawa do zmiany trust root.

Przeznaczenie:
- restart,
- podmiana binarki,
- rollout configu,
- serwis hosta,
- ograniczony dostęp operatorski do runtime.

### GDA-6: Chained Epoch

To jest wariant docelowy, finalny, najwyższego poziomu.

Cechy:
- artefakty tworzą łańcuch decyzji między epokami,
- bardzo silny audit i downgrade resistance,
- najlepszy dla najbardziej krytycznych ścieżek końcowych.

Przeznaczenie:
- docelowa warstwa finalna dla najbardziej krytycznych flow,
- nie jest wymagany jako pierwszy etap wdrożenia.

## 2. Warianty odrzucone na teraz

Nie przyjmujemy jako bazowego modelu:
- GDA-1 `Minimal Ticket`,
- GDA-4 `Manifest + External Package` jako osobnego głównego standardu.

Powód:
- GDA-1 jest zbyt słaby semantycznie dla modelu NXMS,
- GDA-4 na tym etapie zbyt wcześnie rozrzuca ciężar w dodatkowe elementy.

Nie wyklucza to, że przyszłe recovery package będą miały osobne manifesty.
Na dziś nie zamrażamy tego jako głównego wariantu.

## 3. Wspólny rdzeń każdego GDA

Każdy wariant `GDA` musi mieć co najmniej:
- `artifact_type`,
- `operation_class`,
- `operation_kind`,
- `system_epoch`,
- `guard_set_epoch`,
- `artifact_id`,
- `scope`,
- `not_before`,
- `not_after`,
- referencję do `KEM package` albo jego hash/ID, jeśli operacja tego wymaga,
- `2` podpisy `Falcon-1024-CT`,
- referencję revoke/cutover.

Operacje klasy `A` muszą dodatkowo wiązać artefakt ze stanem wejściowym.

## 4. Matryca operacji

| Operacja | Klasa | Wariant GDA | Kto weryfikuje | Uwagi |
|---|---|---|---|---|
| bootstrap systemu od zera | A | GDA-3 | guard bootstrap runtime + orchestrator bootstrap path | `intent` + `commit`, zawsze z `KEM package` |
| resurrection po utracie infrastruktury | A | GDA-3 | guard recovery path + bootstrap roles | dwufazowość obowiązkowa |
| relokacja do nowej lokalizacji | A | GDA-3 | guard recovery path + nowe hosty | relokacja nie jest zwykłym maintenance |
| aktywacja nowego trust setu | A | GDA-3 | guard runtime + orchestrator + signer | trust-changing, nie runtime convenience |
| rotacja guard root keys | A | GDA-3 | guard runtime | wymaga jawnego cutover |
| odblokowanie po fail-closed | A | GDA-3 | guard runtime + rola docelowa | nie może być zwykłym restartem |
| wejście do krytycznego flow | A | GDA-2 | orchestrator + signer | bazowy krytyczny standard |
| `sign` | A | GDA-2 | signer | state-bound, fail-closed |
| `submit` | A | GDA-2 | signer + orchestrator proof path | state-bound, fail-closed |
| finalne `release/refund/close/fail` | A | GDA-2 | orchestrator + signer | state-bound, fail-closed |
| restart hosta runtime ze spójnym sealed state | B | GDA-5 | host runtime preflight | tylko maintenance scope |
| restart po incydencie bez zmiany trust root | B | GDA-5 | host runtime preflight + guard check | jeśli zmienia trust/state, wpada do GDA-3 |
| podmiana binarki | B | GDA-5 | host runtime preflight | musi być host/role scoped |
| rollout configu | B | GDA-5 | host runtime preflight | musi być host/role scoped |
| wymiana hosta bez zmiany trust setu | B | GDA-5 albo GDA-3 | zależnie od stanu | jeśli nowa tożsamość/sealed state, wtedy GDA-3 |
| zwykły healthcheck / housekeeping | C | brak GDA | lokalny runtime | poza guard decision layer |

## 5. Rola ról systemowych

### `nxms-auth-guard`

Guardy:
- wystawiają `GDA`,
- weryfikują `epoch`, `revoke`, `cutover`,
- są jedyną legalną warstwą emisji artefaktów dla operacji `A` i `B`.

### `nxms-escrow-orchestrator`

Orchestrator:
- nie wystawia własnego zastępczego `GDA`,
- weryfikuje `GDA-2` i `GDA-3` tam, gdzie prowadzi workflow,
- agreguje proofy i stan, ale nie zastępuje guardów.

### `nxms-signer`

Signer:
- weryfikuje `GDA-2` dla `sign` i `submit`,
- weryfikuje state binding i proof consistency,
- odrzuca operację bez prawidłowego artefaktu.

### Runtime host roles

Hosty runtime:
- akceptują `GDA-5` tylko dla wąskiego maintenance scope,
- nie mogą przez `GDA-5` zmieniać trust root,
- mają przejść fail-closed przy próbie użycia złego albo wygasłego maintenance artifact,
- mają odwoływać się do `docs/NXMS_MAINTENANCE_ARTIFACT_MODEL.md` jako source-of-truth dla maintenance contract.

## 6. Fail-closed wymagania

Każdy wariant `GDA` musi być odrzucany przy:
- `system_epoch` mismatch,
- `guard_set_epoch` mismatch,
- revoke,
- cutover mismatch,
- TTL expiry,
- scope mismatch,
- host mismatch,
- role mismatch,
- state drift, jeśli operacja jest state-bound.

`GDA-5` nie może:
- aktywować systemu,
- zrobić resurrection,
- zmienić trust setu,
- zastąpić `GDA-2` albo `GDA-3`.

## 7. Kierunek docelowy

Stan docelowy NXMS:
- `GDA-2` jako codzienny krytyczny standard,
- `GDA-3` jako ciężki trust-changing standard,
- `GDA-5` jako maintenance/operator access standard,
- `GDA-6` jako finalna, najwyższa warstwa dojrzałości i audytu.

To jest zamrożony kierunek.
Jeśli później dojdzie nowy wariant, musi mieć osobną decyzję architektoniczną.
