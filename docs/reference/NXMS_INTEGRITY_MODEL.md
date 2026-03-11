# NXMS Integrity Model

To jest model pojęciowy `nxms-integrity`.

Ten dokument nie opisuje pełnej wewnętrznej mapy mechanizmów integrity.
Ma zamrozić:
- czym jest `nxms-integrity`,
- jaką pełni rolę,
- czego nie należy z niego robić,
- jak rozumieć jego miejsce wobec `nxms-guard` i `nxms-boss`.

## 1. Czym jest `nxms-integrity`

`nxms-integrity` jest wewnętrzną warstwą spójności i legalności systemu.

To nie jest zwykły komponent runtime.
To nie jest osobny publiczny interfejs.
To nie jest też pojedynczy sekret, klucz albo dokument.

`nxms-integrity` to warstwa, która porządkuje:
- legalne przejścia,
- legalne decyzje,
- epoki,
- revoke,
- cutover,
- state binding,
- granice między rolami,
- semantyczną spójność całego systemu.

## 2. Rola w systemie

Bez `nxms-integrity`:
- `nxms-guard` byłby tylko zbiorem hostów i podpisów,
- `nxms-boss` byłby tylko warstwą recovery bez wspólnej prawdy,
- system nie miałby jednej mapy, co jest legalne, a co nie.

`nxms-integrity` nadaje wspólny sens:
- runtime trust,
- recovery trust,
- maintenance trust,
- fail-closed reactions.

## 3. Co może być widoczne

Widoczne może być:
- samo pojęcie `nxms-integrity`,
- to, że system ma wewnętrzną warstwę spójności,
- to, że istnieją legalne i nielegalne przejścia,
- to, że system opiera się o ramy i invarianty.

To nie jest problem.

## 4. Czego nie odsłaniamy wprost

Nie opisujemy wprost pełnej mapy:
- wszystkich korelacji,
- wszystkich progów reakcji,
- wszystkich zależności wewnętrznych,
- pełnej logiki wykrywania manipulacji,
- pełnej logiki tego, jak system wewnętrznie składa wszystkie warunki legalności.

Ten dokument nie ma być instrukcją rozbierania systemu na części.
Ma być ramą pojęciową dla twórców i architektury.

## 5. Czym `nxms-integrity` nie jest

`nxms-integrity` nie jest:
- tajnym master dokumentem, od którego magicznie zależy wszystko,
- pojedynczym zasobem do przejęcia,
- jednym interfejsem, który można „zdobyć”,
- warstwą, która ma być bezpośrednio obsługiwana przez operatora.

## 6. Relacja do `nxms-guard`

`nxms-guard`:
- wykonuje aktywną warstwę trust,
- wystawia decyzje,
- działa fail-closed.

`nxms-integrity`:
- nadaje sens temu, kiedy decyzja guardów jest legalna,
- określa, jak rozumieć epoch, revoke, cutover i state binding,
- nie zastępuje guardów, ale spina ich znaczenie.

## 7. Relacja do `nxms-boss`

`nxms-boss`:
- opisuje warstwę offline / resurrection / strategic trust.

`nxms-integrity`:
- sprawia, że resurrection nie jest improwizacją,
- utrzymuje wspólną prawdę między runtime i recovery,
- nie pozwala, aby `boss` był luźnym obejściem guardów.

## 8. Zasada architektoniczna

`nxms-integrity` ma być:
- obecne,
- spójne,
- wewnętrznie silne,
- ale nie rozpisane publicznie jako pełna mapa wrażliwych zależności.

Inaczej mówiąc:
- warstwa jest realna,
- rola warstwy jest zrozumiała,
- ale pełna zawartość tej warstwy nie jest eksponowana jako publiczny opis działania systemu.

## 9. Definicja semantyczna

Najkrócej:

`nxms-integrity` to konstytucyjna warstwa systemu, która definiuje, co oznacza legalne istnienie, legalna decyzja i legalne przejście systemu.

## 10. Definicja done

Model `nxms-integrity` jest wystarczająco domknięty wtedy, gdy:
- wiadomo, że to warstwa spójności, nie pojedynczy komponent,
- wiadomo, że nie jest publicznym interfejsem,
- wiadomo, że nie jest pojedynczym sekretem,
- wiadomo, że spina `guard`, `boss` i resztę systemu,
- szczegółowe mechanizmy pozostają domeną implementacji i wewnętrznej architektury, a nie jawnego opisu wysokopoziomowego.
