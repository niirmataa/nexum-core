# NXMS Trust Triad

To jest skrót pojęciowy opisujący trzy współzależne warstwy zaufania systemu NXMS.

Ten dokument nie zastępuje szczegółowych modeli `guard`, `recovery` i `integrity`.
Ma tylko zamrozić wspólny język i zależności między tymi warstwami.

## 1. Trzy warstwy

NXMS można opisać jako triadę:
- `nxms-guard`
- `nxms-boss`
- `nxms-integrity`

## 2. `nxms-guard`

`nxms-guard`:
- jest aktywną warstwą runtime trust,
- utrzymuje quorum,
- wystawia decyzje, gate'y i maintenance artifacts,
- pilnuje bieżącego legalnego wejścia w krytyczne operacje,
- działa fail-closed.

Bez `nxms-guard` nie ma żywego, legalnie działającego systemu.

## 3. `nxms-boss`

`nxms-boss`:
- jest nazwą logicznej warstwy offline / resurrection / strategic trust,
- nie oznacza jednej osoby,
- nie oznacza pojedynczego klucza,
- nie oznacza pojedynczego centrum władzy nad systemem.

`nxms-boss` opisuje warstwę zdolną do współtworzenia recovery i resurrection, ale tylko jako część większego modelu quorum.

Bez `nxms-boss` nie ma pełnej ciągłości systemu po katastrofie, utracie lokalizacji albo utracie aktywnego runtime.

## 4. `nxms-integrity`

`nxms-integrity`:
- jest niepodważalną mapą bezpieczeństwa systemu,
- spina legalne przejścia,
- spina epoki,
- spina revoke,
- spina cutover,
- spina state binding,
- spina dowody i zasady legalności decyzji.

Bez `nxms-integrity` ani `nxms-guard`, ani `nxms-boss` nie mają wspólnej, weryfikowalnej prawdy systemowej.

Dokument uzupełniający:
- `docs/NXMS_INTEGRITY_MODEL.md` opisuje `nxms-integrity` jako widoczną warstwę ram i spójności, ale bez rozpisywania pełnej mapy wewnętrznej.

## 5. Zależności

Zależności są współzależne:
- bez `nxms-guard` nie ma sensownego `nxms-boss`,
- bez `nxms-boss` nie ma pełnego modelu ciągłości `nxms-guard`,
- bez `nxms-integrity` nie ma systemu, tylko luźne elementy bez wspólnego trust contract.

To oznacza:
- `guard` i `boss` nie są od siebie niezależnymi światami,
- `integrity` jest warstwą, która nadaje obu formalny sens,
- żadna z tych warstw sama nie powinna wystarczać do przejęcia systemu.

## 6. Zasada semantyczna

Nazwy:
- `nxms-guard`
- `nxms-boss`
- `nxms-integrity`

opisują role logiczne systemu.

Nie należy ich czytać jako:
- nazw jednej osoby,
- nazwy pojedynczego hosta,
- nazwy pojedynczego klucza,
- nazwy jednego scentralizowanego podmiotu sterującego całością.

## 7. Konsekwencja architektoniczna

Jeśli przyszła implementacja, deploy albo docs:
- redukują `nxms-boss` do jednego człowieka,
- redukują `nxms-guard` do zwykłego auth service,
- albo redukują `nxms-integrity` do luźnych notatek,

to są sprzeczne z tym modelem.
