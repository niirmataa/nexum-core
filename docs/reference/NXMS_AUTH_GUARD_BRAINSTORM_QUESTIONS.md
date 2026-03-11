# NXMS Auth Guard Brainstorm Questions

To jest jeden roboczy dokument do otwartej burzy mozgow.

Cel:
- zebrac pytania, na ktore system musi miec jednoznaczna odpowiedz,
- rozwinac ryzyka i kompromisy,
- zapisac robocze propozycje,
- umozliwic odniesienie sie punkt po punkcie w jednym miejscu.

To nie jest finalna specyfikacja.
To nie jest source of truth.
To jest material do wspolnego doprecyzowania.

Powiazane notatki:
- [docs/NXMS_AUTH_GUARD_WORKING_NOTES.md](./NXMS_AUTH_GUARD_WORKING_NOTES.md)

## 1. Co dokladnie liczy sie jako znaczaca zmiana

### Pytanie

Ktore operacje musza byc z definicji traktowane jako znaczace zmiany i zawsze
wymagac drugiej strony?

### Dlaczego to jest wazne

Bez tej listy system zacznie dryfowac:
- czesc zmian bedzie traktowana jako "zwykla administracja",
- czesc jako "jeszcze niegrozna technikalia",
- a pozniej okaze sie, ze wlasnie przez takie "male" zmiany da sie przejac
  runtime, trust albo hosty.

### Propozycja robocza

Znaczaca zmiana to kazda operacja, ktora:
- zmienia wykonywalny kod,
- zmienia konfiguracje majaca wplyw na trust, admission albo granice dostepu,
- zmienia klucze, root material albo sklad podmiotow zaufania,
- zmienia to, kto i jak moze wejsc do systemu,
- zmienia to, jak system reaguje na awarie i recovery,
- moze zostac wykorzystana do pozniejszego przejecia systemu.

### Kandydaci do listy "zawsze znaczace"

- aktualizacja binarek,
- rollout nowej wersji guard/orchestrator/signer,
- zmiana plikow konfiguracyjnych guard,
- zmiana endpointow, bind address, warstw sieciowych,
- zmiana polityki admission,
- zmiana kluczy guard,
- zmiana root package / bootstrap package,
- zmiana operator capabilities,
- zmiana modelu audytu,
- zmiana procedury recovery,
- wlaczenie czegokolwiek testowego w produkcji.

### Pytania do Ciebie

- Czy restart uslugi bez zmiany binarki tez ma byc znaczaca zmiana?
- Czy zwykle ponowne uruchomienie hosta ma wymagac obu stron?
- Czy zmiana logowania / observability / audit retention ma byc znaczaca?
- Czy zmiana samego opisu procedury operatorskiej bez zmiany binarek ma byc
  znaczaca, jesli w praktyce zmienia zachowanie?

### Robocza odpowiedz uzytkownika

- Lepsze od listy rzeczy wymagajacych obu podpisow jest zrobienie listy rzeczy,
  ktore takich dwoch podpisow nie wymagaja.
- Domyslna logika ma byc zachowawcza: jesli operacja nie jest jawnie wpisana
  jako bezpieczna i niewymagajaca obu stron, to wpada do wyzszego rezimu.

## 2. Jak ma dzialac swiezy artefakt czasu rzeczywistego

### Pytanie

Jak ma wygladac artefakt albo podpis drugiej strony wymagany dla operacji
wysokiego ryzyka?

### Dlaczego to jest wazne

Jesli artefakt:
- da sie przechwycic,
- ma zbyt dlugi TTL,
- nie jest zwiazany z konkretna operacja,
- da sie odtworzyc albo replayowac,

to sam staje sie narzedziem przejecia.

### Propozycja robocza

Kazda operacja wysokiego ryzyka powinna wymagac swiezego, jednorazowego
potwierdzenia zawierajacego co najmniej:
- typ operacji,
- identyfikator celu,
- kto inicjuje,
- kto zatwierdza,
- czas wystawienia,
- bardzo krotki termin waznosci,
- nonce/challenge,
- powiazanie z aktualnym stanem systemu,
- oznaczenie jednorazowego uzycia.

### Minimalne wymagania

- single-use,
- anti-replay,
- krotki TTL,
- zwiazanie z konkretna operacja,
- zwiazanie z konkretnym stanem systemu,
- niewaznosc po zmianie stanu,
- brak mozliwosci wykorzystania jako uniwersalnego tokena sesyjnego.

### Pytania do Ciebie

- Czy taki artefakt ma byc per operacja czy per bardzo krotka sesja?
- Jaki TTL uwazasz za dopuszczalny: sekundy, minuty, czy tylko jeden request?
- Czy artefakt ma byc generowany zawsze przez druga strone interaktywnie,
  czy dopuszczasz bardzo waski pre-approval window?
- Czy sam artefakt wystarczy, czy ma byc jeszcze dodatkowy warunek lokalny?

### Robocza odpowiedz uzytkownika

- Artefakt ma byc jednorazowego uzytku i stawac sie niewazny dokladnie w
  momencie wykorzystania w systemie.
- TTL moze byc bardzo krotki; roboczo 5 minut jest akceptowalne jako gorna
  granica dla operacji wymagajacych czasu reakcji.
- Artefakt powinien zawierac:
  - hash danego zadania albo pliku,
  - typ operacji,
  - identyfikator,
  - kto do kogo,
  - czas,
  - waznosc,
  - nonce,
  - powiazanie ze stanem systemu.
- Artefakt powinien miec tez wage/priorytet, a jego "objetosc" i sila zwiazania
  z kontekstem powinny byc dostosowane do ryzyka operacji.
- Nie ma wielokrotnego uzycia.
- Czas nie jest tu priorytetem; to system finansowy i bezpieczenstwo ma wyzszy
  priorytet niz szybkosc.
- Jesli ktos nie chce brac odpowiedzialnosci za taki rezim, poprawnym stanem jest
  fail-closed / END SYSTEM.

## 3. Jakie warunki musza obowiazywac przy full machine access dla AG-01 / AG-02

### Pytanie

W jakich dokladnie warunkach `AG-01` i `AG-02` moga wejsc glebiej na hosty i co
to znaczy "pelny dostep do maszyn"?

### Dlaczego to jest wazne

Jesli to nie bedzie opisane twardo, to z `AG-01` / `AG-02` zrobia sie po prostu
dwaj superadmini.

### Propozycja robocza

Full machine access:
- nie jest normalnym trybem pracy,
- nie jest wygodnym trybem serwisowym,
- jest tylko narzedziem konstytucyjnym / awaryjnym,
- wymaga obu stron dla wejscia w istotne operacje,
- zawsze zostawia maksymalny slad audytowy i proceduralny.

### Kandydaci do warunkow

- tylko dla scisle okreslonych klas awarii,
- tylko po stwierdzeniu, ze operator scope nie wystarcza,
- tylko z aktywnym audytem,
- tylko na okres ograniczony czasowo,
- tylko z minimalnym zakresem wymaganym do konkretnej naprawy,
- tylko z jawnie oznaczonym powodem wejscia,
- tylko z obowiazkiem zamkniecia sesji uprzywilejowanej.

### Pytania do Ciebie

- Czy samo wejscie na host ma wymagac obu stron, czy dopiero operacje po wejsciu?
- Czy AG moze tylko "otworzyc okno dostepu", czy tez wykonywac konkretne akcje?
- Czy dopuszczasz read-only host access w lzejszym trybie niz write/change access?
- Czy diagnostyka lokalna bez zmian stanu tez ma wymagac obu?

### Robocza odpowiedz uzytkownika

- Full machine access jest dopuszczalny tylko wtedy, gdy operator zglosi powazna
  awarie systemu i jego zwykle narzedzia nie zadzialaja.
- Musi byc quorum, bo przejecie trzech podmiotow naraz (`operator`, `AG-01`,
  `AG-02`) jest uznawane za skrajnie malo prawdopodobne.
- Powod wejscia musi byc powazny i z gory rozpoznawalny, np. system nie odpowiada.
- Jesli przypadek nie podpada pod z gory wypisany katalog, trzeba znalezc inne
  rozwiazanie zanim system ruszy dalej.
- Nie ma wymyslania powodow wejscia ad hoc; jesli powod nie pokrywa sie z lista,
  nie ma wejscia.
- Stale wejscia administracyjne:
  - serwis okresowy co z gory ustalony czas,
  - audyt okresowy,
  - oba takze wymagaja quorum.
- System powinien byc projektowany tak, aby przy znanych bledach, utracie
  lacznosci narzedzi i uslug przechodzil w automatyczny reset / automatyczne
  odzyskanie bez potrzeby recznego operator action.
- Kazde wejscie ma wymagac quorum dwoch AG i podpisu operatora.
- Tylko AG maja dostep ostateczny.
- Dopuszczalny jest tryb monitoringu z ograniczonymi uprawnieniami, ale takze z
  quorum, bo monitoring moze odsłaniac dane wrazliwe.

## 4. Czy operator key sluzy tylko do identyfikacji, czy tez do admission

### Pytanie

Czy publiczny klucz operatora ma sluzyc tylko do identyfikacji operatora, czy
takze byc czescia warunku wejscia do sciezki operatorskiej?

### Dlaczego to jest wazne

Jesli operator key bedzie zbyt silny, operator zacznie byc wspol-rootem systemu.
Jesli bedzie zbyt slaby, przechwycony artefakt admission moze byc uzywany bez
realnego zwiazania z konkretna osoba i zakresem.

### Propozycja robocza

Najbezpieczniejszy kierunek na ten moment:
- operator key nie daje authority,
- operator key sluzy do identyfikacji,
- admission jest wydawane przez warstwe wyzsza,
- admission jest zwiazane z tozsamoscia operatora i zakresem jego capability.

### Pytania do Ciebie

- Czy operator ma w ogole podpisywac wejscie do swojej sciezki?
- Czy operator identity ma byc stale przypisana do jednego zakresu dzialan?
- Czy chcesz rozne klasy operatora, czy tylko jedna role z jednym katalogiem?

### Robocza odpowiedz uzytkownika

- Klucz operatora sluzy do wejscia i podpisywania quorum, ale jest tylko jedna z
  warstw dostepu, nie daje automatycznej jednosci authority.
- Kazde wejscie operatora jest podpisane challenge.
- Dostep ma byc stageryzowany i kategoryzowany tak, aby ograniczac manipulacje
  i wymuszanie dostepu.
- Operator jest jedna rola, ale zadania sa kategoryzowane i maja rozne klasy
  bezpieczenstwa dostepu.

## 5. Jak ma wygladac bounded operator scope

### Pytanie

Jaki dokladnie katalog dzialan moze wykonywac operator, skoro ma reagowac, ale
nie moze miec swobody dowolnego ruchu?

### Dlaczego to jest wazne

Bez skonczenie zdefiniowanego katalogu operator stanie sie de facto adminem
runtime, tylko pod inna nazwa.

### Propozycja robocza

Operator powinien miec tylko capability do:
- obserwacji statusu,
- potwierdzania znanych stanow awaryjnych,
- uruchamiania z gory przewidzianych procedur,
- eskalacji do AG tam, gdzie system dochodzi do granicy operator scope.

Operator nie powinien miec capability do:
- arbitralnej zmiany konfiguracji runtime,
- arbitralnego deployu,
- bezposredniego sterowania signerem,
- bezposredniego sterowania trust state,
- wolnego poruszania sie po hostach.

### Pytania do Ciebie

- Czy operator moze sam restartowac niektore uslugi?
- Czy operator moze uruchomic procedury maintenance bez AG, jesli nie zmieniaja trust?
- Czy operator moze tylko wybierac z predefiniowanych playbookow?

### Robocza odpowiedz uzytkownika

- Zadaniem operatora jest obsluga flow i pilnowanie, by nie bylo przerw we flow.
- Operator moze:
  - obserwowac flow i status,
  - potwierdzac stany awaryjne,
  - awaryjnie puscic flow dalej, ale bez mozliwosci swobodnego "naprawiania"
    systemu w sposob otwierajacy wyciek danych lub logiki.
- Operator nie moze restartowac uslug.
- Uslugi przy utracie lacznosci albo braku odpowiedzi maja restartowac sie same.
- Operator nie moze uruchamiac maintenance bez quorum, jesli mogloby to wplynac
  na logike, obserwacje albo dane wrazliwe.
- Operator jest jak straznik flow: ma doprowadzic proces do konca bez ujawniania
  logiki i danych wrazliwych; jesli to niemozliwe, musi byc quorum.

## 6. Co znaczy "END SYSTEM" operacyjnie

### Pytanie

Skoro przy utracie warunku wspolnego dzialania `AG-01` i `AG-02` ma byc
`END SYSTEM`, to co dokladnie ma sie stac operacyjnie?

### Dlaczego to jest wazne

Bez tej odpowiedzi "END SYSTEM" pozostanie haslem, a nie zachowaniem systemu.

### Propozycja robocza

`END SYSTEM` moze znaczyc:
- brak mozliwosci legalnych zmian,
- zamrozenie admission dla operacji wrazliwych,
- zatrzymanie zdolnosci do aktualizacji i zmiany trust state,
- pozostawienie tylko bezpiecznego minimum odczytu / dowodow / audytu,
- brak mozliwosci przejscia do trybu jednoosobowego.

### Pytania do Ciebie

- Czy system ma sie zatrzymac twardo, czy przejsc w tryb read-only / no-change?
- Czy user-facing warstwa ma dalej dzialac, czy rowniez ma zostac wygaszona?
- Czy audit i dowody maja pozostac aktywne nawet po END SYSTEM?

### Robocza odpowiedz uzytkownika

- Jesli przez z gory okreslony czas np. `AG-01` traci kontakt, probuje wymuszać
  nieautoryzowany dostep albo omijac uzgodnione procedury, moze dojsc do
  `END SYSTEM`, bo `AG-02` nie podpisze wymaganego checkpointa.
- Poza przypadkiem AG, `END SYSTEM` moze wynikac z:
  - braku mozliwosci zmian,
  - krytycznego bledu systemu,
  - nieudanej aktualizacji,
  - ataku.
- Nie istnieje tryb jednoosobowy.
- W ostatecznosci, przy powaznym problemie systemowym, zakladany jest model:
  `end system in this location and recovery in new location`.
- System powinien przejsc w kwarantanne na 5 dni, a potem w autodestrukcje
  logiczna przez wygaszenie starego materialu.
- Brak podpisanego checkpointa ma uruchamiac stan blokady i rotacji kluczy.
- Bez nowych, zaakceptowanych kluczy stare klucze po 5 dniach maja przestac
  dzialac.
- Po END SYSTEM nic nie pozostaje aktywne i nie ma dostepu bez aktualnych kluczy.

## 7. Ktore rzeczy musza byc niemozliwe nawet dla AG

### Pytanie

Jakie operacje maja byc zabronione nie tylko operatorowi, ale takze `AG-01` i
`AG-02`, chyba ze system przechodzi przez osobny, ekstremalny tryb recovery?

### Dlaczego to jest wazne

Jesli AG moze "wszystko", to roznica miedzy warstwa konstytucyjna a superadminem
zacznie zanikac.

### Propozycja robocza

Nawet AG nie powinien moc:
- jednostronnie przepiac trust root,
- jednostronnie usunac drugiej strony,
- jednostronnie zmienic model wladzy,
- stworzyc legalnego trybu single authority,
- zalegalizowac testowych/scisle zakazanych bypassow w produkcji.

### Pytania do Ciebie

- Czy jest jakakolwiek operacja konstytucyjna, ktora dopuszczasz dla pojedynczego AG?
- Czy istnieje jakis odrebny, offline-only recovery path ponad AG-01/AG-02?

### Robocza odpowiedz uzytkownika

- AG nie moze:
  - zmieniac kodu,
  - manipulowac przy binarkach,
  - aktualizowac bez legalnego kanalu dostepu,
  - zmieniac plikow bez wlasciwej autoryzacji,
  - miec wgladu do szczegolowych danych wrazliwych bez z gory okreslonej,
    warunkowej podstawy,
  - nawet otwierac wrazliwych plikow bez podstaw i odpowiedniego logowania AG
    do systemu.
- Nie istnieje zadna mozliwosc samodzielnego podejmowania znaczacych decyzji
  przez pojedynczy AG bez quorum.
- Nie istnieje osobny tryb jednostronny ponad tym modelem.

## 8. Jak ma wygladac podzial operacyjny vs konstytucyjny

### Pytanie

Ktore klasy decyzji naleza do zwyklej eksploatacji, a ktore sa juz decyzjami
konstytucyjnymi?

### Dlaczego to jest wazne

Jesli te dwa poziomy sie wymieszaja, zwykle operacje zaczna miec zbyt wysoki
koszt albo zmiany konstytucyjne beda przechodzily za latwo.

### Propozycja robocza

Poziom operacyjny:
- reakcja na znane awarie,
- status,
- uruchamianie predefiniowanych procedur,
- ograniczone maintenance bez zmiany trust.

Poziom konstytucyjny:
- zmiana trust root,
- zmiana guard key material,
- zmiana modelu admission,
- zmiana skladu podmiotow zaufania,
- wszystko, co po przechwyceniu mogloby posluzyc do przejecia systemu.

### Pytania do Ciebie

- Gdzie dokladnie stawiasz granice miedzy maintenance a zmiana konstytucyjna?
- Czy update binarki zawsze jest konstytucyjny, czy tylko niektore?

### Robocza odpowiedz uzytkownika

- System ma nienegocjowalne zasady i reguly bezpieczenstwa.
- Zwykla eksploatacja to tylko taka codzienna warstwa dzialania, na ktorej nie
  ciazy jarzmo kompromitacji ani niebezpiecznych sytuacji zagrażających
  stabilnosci i poufnosci systemu.
- Poziomy operacyjne i konstytucyjne nie wymieszaja sie, jesli zostana jawnie i
  stanowczo opisane.
- Konkretne modele zagrozen maja same wyłonić poziomy bezpieczenstwa.
- Ostateczne zapisanie poziomow operacyjnych i konstytucyjnych ma nastapic przy
  uruchomieniu testow calosciowych systemu, modeli zagrozen i scenariuszy atakow.
- Twarda administracja, update, rotacje sekretow i audyty sa nienegocjowalne.
- W modelu `2 z 2` pojedynczy `AG` po utracie drugiej strony ma tylko role
  informacyjna.
- Taki pojedynczy `AG` nie moze wykonywac zadnych dzialan konstytucyjnych ani
  reaktywacyjnych; system ma byc projektowany jako auto-flow z fail-closed, a
  nie jako manual single-side recovery.

## 9. Zestaw decyzji, ktore musimy zamknac przed dalsza architektura

### Minimalny zestaw

- definicja "znaczacej zmiany",
- definicja operator scope,
- definicja fresh artifact,
- warunki full machine access dla AG,
- definicja END SYSTEM,
- granica operacyjne vs konstytucyjne,
- rola operator key.

### Propozycje definicji do konsensusu

#### 9.1 Definicja "znaczacej zmiany"

Znaczaca zmiana to kazda operacja, ktora:
- zmienia kod, binarki albo obraz wykonywalny systemu,
- zmienia klucze, sekrety, root material albo admission material,
- zmienia polityke dostepu, quorum, role albo zakres capability,
- zmienia warstwe audytu, recovery albo zasady reakcji na awarie,
- moze zostac wykorzystana do pozniejszego przejecia systemu lub ujawnienia
  wrazliwej logiki / danych.

Domyslna zasada:
- jesli operacja nie jest jawnie skwalifikowana jako bezpieczna codzienna
  eksploatacja, traktujemy ja jako znaczaca.

#### 9.2 Definicja "zwyklej eksploatacji"

Zwykla eksploatacja to warstwa codziennych, z gory przewidzianych dzialan,
ktore:
- nie zmieniaja trust state,
- nie zmieniaja root material,
- nie otwieraja dostepu do danych wrazliwych ponad przewidziany zakres,
- nie niosa wysokiego ryzyka kompromitacji systemu,
- nie wymagaja wyjscia poza z gory zdefiniowany operator scope.

#### 9.3 Definicja "poziomu konstytucyjnego"

Poziom konstytucyjny obejmuje wszystkie operacje, ktore:
- dotykaja legalnosci systemu,
- dotykaja trust root,
- dotykaja skladu i relacji miedzy podmiotami zaufania,
- dotykaja admission do warstw krytycznych,
- po przechwyceniu lub naduzyciu moglyby posluzyc do przejecia systemu.

#### 9.4 Definicja "fresh artifact"

Fresh artifact to jednorazowy, krotko wazny, kontekstowy artefakt autoryzacyjny,
ktory:
- jest generowany dla jednej konkretnej operacji,
- jest zwiazany z aktualnym stanem systemu,
- ma nonce i TTL,
- jest niewazny po wykorzystaniu,
- nie moze posluzyc jako ogolny token dostepu ani byc replayowany.

#### 9.5 Definicja "operator scope"

Operator scope to zamkniety katalog capability sluzacych do:
- obserwacji flow,
- potwierdzania znanych stanow awaryjnych,
- koordynacji procedur,
- utrzymania ciaglosci flow bez ujawniania logiki i danych wrazliwych.

Operator scope nie obejmuje:
- dowolnej administracji hostami,
- restartow uslug poza automatyka systemowa,
- zmian binarek, kluczy, sekretow i polityk,
- swobodnego maintenance,
- dostepu do wrazliwych plikow i szczegolowych danych bez wyzszego rezimu.

#### 9.6 Definicja "full machine access"

Full machine access to warunkowy, wyjatkowy i maksymalnie ograniczony dostep do
hosta, dostepny tylko dla `AG-01` i `AG-02`, uruchamiany:
- po zgloszeniu powaznej awarii przez operatora,
- gdy zwykle narzedzia operatorskie i automatyka systemu nie wystarczaja,
- przy quorum obu AG oraz podpisie operatora,
- tylko dla z gory przewidzianych klas przypadkow,
- z pelnym sladem audytowym.

#### 9.7 Definicja "END SYSTEM"

END SYSTEM to stan fail-closed, w ktorym:
- nie ma legalnej mozliwosci dalszych znaczacych zmian,
- nie ma mozliwosci przejscia do trybu jednoosobowego,
- brak nowych checkpointow i podpisow prowadzi do blokady i wygaszenia starego
  materialu,
- system przechodzi przez kwarantanne, a pozniej traci zdolnosc legalnego
  dzialania bez nowego, poprawnego stanu konstytucyjnego.

Doprecyzowanie robocze:
- END SYSTEM nie musi oznaczac natychmiastowego fizycznego zatrzymania kazdego
  procesu juz uruchomionego przed zamknieciem starego stanu,
- po wygaszeniu kluczy i zamknieciu starej legalnosci nie da sie juz legalnie
  zalogowac ani dalej sterowac systemem,
- ale jesli maszyny fizycznie nadal dzialaja, escrow albo multisig bedace juz w
  toku moze dojsc do naturalnego domkniecia,
- fizyczne odlaczenie lub zatrzymanie maszyn przerywa taki tok wykonania.

#### 9.8 Definicja "nienegocjowalnych operacji administracyjnych"

Operacje nienegocjowalne to takie, ktore musza istniec w modelu systemu i nie
moga zostac uznane za opcjonalne:
- update,
- rotacje sekretow,
- audyty,
- twarda administracja konstytucyjna.

Nie znaczy to, ze sa latwe lub czeste.
Znaczy to, ze system musi miec dla nich legalny i bezpieczny model wykonania.

### Roboczy konsensus uzytkownika dla 9.1-9.8

- `9.1` zaakceptowane.
- `9.2` zaakceptowane.
- `9.3` zaakceptowane.
- `9.4` zaakceptowane z zastrzezeniem, ze dokladny "zasob" artefaktu ma byc
  dopasowany do poziomu bezpieczenstwa samego artefaktu i klasy operacji.
- `9.5` zaakceptowane.
- `9.6` zaakceptowane.
- `9.7` do doprecyzowania:
  - przy braku odpowiedzi na zaplanowana rotacje system ma wygenerowac nowy
    material uniewazniajacy stary stan,
  - przejsc w automatyczna izolacje,
  - zamknac legalne dzialanie starego stanu systemu,
  - nie tworzyc "nowego zycia" dla tego samego systemu, tylko definitywnie
    zerwac ciaglosc starego stanu.
- `9.8` zaakceptowane.

## Jak odpowiadac na ten dokument

Najprostszy sposob:
- zostawic sekcje,
- pod kazda dopisac:
  - `Decyzja`
  - `Uzasadnienie`
  - `Odrzucone warianty`

Alternatywnie:
- dopisac pod punktami tylko krotkie:
  - `tak`
  - `nie`
  - `warunkowo`
  - `do dopracowania`
