# NXMS Auth Guard Working Notes

To jest jeden roboczy plik do ciągłego zapisywania ustaleń z dyskusji o modelu
`auth guard`.

To nie jest jeszcze finalny kontrakt.
To jest pamięć robocza:
- co zostało już ustalone,
- do jakich wniosków doszliśmy,
- co jest nadal otwarte.

## Stan roboczy

Data startu notatek: 2026-03-11

## Ustalenia

### 0. Werdykt konstytucyjny

- Konstytucyjne quorum systemu to `2 z 2`.
- Jedynymi podpisami decyzyjnymi sa podpisy `AG-01` i `AG-02`.
- Model `2 z 5` zostaje odrzucony jako zbyt podatny na manipulacje, uklady i
  polityczne/praktyczne przejecie przez zla koalicje.
- Operator nie wchodzi do quorum konstytucyjnego.
- Operator daje podpis obecnosci / witness operacyjny, ale nie tworzy legalnosci
  systemu.
- Dodatkowo istnieje systemowa, szyfrowana warstwa komunikacji dostepnosci:
  - `operator <-> AG-01`
  - `operator <-> AG-02`
  - `AG-01 <-> AG-02`
- Ta warstwa nie jest warstwa decyzyjna; sluzy tylko do wykrywania anomalii,
  braku kontaktu i podnoszenia alarmu proceduralnego.

### 1. Legalna ścieżka operatorska

- Jedyną legalną ścieżką operatorską do runtime ma być warstwa `nxms-auth-guard`.
- Operator nie może mieć bezpośredniego dostępu do runtime core w żadnej formie.
- Direct HTTP/API do `signer`, `orchestrator`, `mailbox` i innych runtime roles jest niedozwolone.
- Local loopback nie jest sam z siebie legalną ścieżką operatorską.
- Host access nie może sam z siebie oznaczać prawa sterowania systemem.

### 2. Legacy / break-glass / direct path

- `shadow mode` nie może istnieć jako element produkcyjnego modelu.
- `allow-remote-bind` nie może być dozwolony w normalnym runtime.
- Direct worker/orchestrator HTTP path nie może być zwykłą ścieżką operatorską.
- `wallet-rpc fallback` i podobne obejścia nie mogą być normalnym workflow.
- Break-glass w produkcji jest niedozwolony.
- Jeśli jakaś ścieżka istnieje wyłącznie do testów, nie jest częścią modelu produkcyjnego.

### 3. Rola operatora

- Operator nie jest trust rootem systemu.
- Operator jest koordynatorem operacyjnym.
- Operator ma ograniczony zakres działań z góry narzucony przez model systemu.
- Operator nie może wyjść poza swój zdefiniowany obszar działania.
- Operator nie ma pełnego dostępu do hostów.
- Operator nie ma prawa do dowolnych ruchów na maszynach i usługach.
- Operator może reagować na znane klasy błędów i stanów awaryjnych tylko w granicach z góry opisanych capability.

### 4. Rola AG-01 i AG-02

- `AG-01` i `AG-02` są jedynymi bytami, które mogą mieć pełny dostęp do maszyn.
- Ten dostęp nie jest stałym prawem, tylko dostępem warunkowym.
- `AG-01` i `AG-02` także podlegają zasadom użycia, zgodom i zabezpieczeniom.
- `AG-01` i `AG-02` nie mogą być traktowani jak zwykli superadmini.
- `AG-01` i `AG-02` nie są "bogiem", "wladca" ani arbitralnym centrum wladzy.
- `AG-01` i `AG-02` sa odpowiedzialnymi podmiotami konstytucyjnymi, dzialajacymi
  wyłącznie w granicach rygorystycznych zasad bezpieczenstwa.
- Full machine access jest zabroniony dla operatora i zwykłych runtime roles.

### 5. Znaczące zmiany i zasada dwóch stron

- `AG-01` sam nie może dokonać znaczącej zmiany.
- `AG-02` sam nie może dokonać znaczącej zmiany.
- Znaczące zmiany wymagają zgody i podpisu obu.
- Dotyczy to także aktualizacji.
- Pojedynczy guard nie może legalnie zmieniać trust state, root state ani modelu władzy.

### 6. Artefakty czasu rzeczywistego

- Dla operacji wysokiego ryzyka potrzebny jest świeży podpis drugiej strony albo świeży artefakt wygenerowany w czasie rzeczywistym.
- Sam stały sekret albo dawniej wygenerowany artefakt nie może wystarczać.
- Sam przechwytywalny artefakt nie może być podstawą autoryzacji.
- Mechanizm musi być odporny na replay i późniejsze wykorzystanie przechwyconego materiału.

### 6a. Pudełko „niebezpieczeństwo przejęcia wrażliwych danych”

- Istnieje klasa operacji i materiałów, które wpadają do pudełka:
  `niebezpieczeństwo przejęcia wrażliwych danych`.
- Jeśli dana operacja, zgoda, podpis, artefakt albo materiał może zostać przechwycony i później wykorzystany przeciw systemowi, to automatycznie należy do najwyższego reżimu ochrony.
- Taka operacja nie może być wykonywana jednostronnie.
- Taka operacja nie może opierać się na stałym, długożyjącym artefakcie.
- Taka operacja wymaga świeżej zgody drugiej strony albo świeżego artefaktu czasu rzeczywistego.
- Taka operacja musi być projektowana pod założenie, że przeciwnik zna system i będzie próbował wykorzystać każdy przechwycony materiał wtórnie.

### 6b. Podpis obecnosci operatora

- Podpis operatora nie jest podpisem konstytucyjnym.
- Podpis operatora jest podpisem obecnosci / witness warstwy operacyjnej.
- Brak podpisu operatora nie daje operatorowi prawa blokady quorum.
- Brak podpisu operatora oraz brak kontaktu po warstwie dostepnosci oznacza
  anomalię i uruchamia procedure bezpieczenstwa.
- Operator podpisuje challenge i potwierdza dostepnosc/obecnosc, ale nie tworzy
  legalnosci systemu samym swoim podpisem.

### 7. Model kompromitacji

- Kompromitacja jednego guarda nie może prowadzić do legalnego przejęcia systemu.
- Nie może istnieć model sukcesji, w którym po utracie jednego guarda drugi przejmuje pełnię władzy.
- Nie może istnieć legalna ścieżka przejścia z modelu dwu-stronnego do jednoosobowego.
- Jeśli system przestaje spełniać warunek wspólnego działania `AG-01` i `AG-02`, to nie następuje przejęcie władzy przez jedną stronę.
- W takim stanie system ma przejść w `fail-closed` / `END SYSTEM`.
- Pojedynczy `AG` po utracie drugiej strony moze dzialac wyłącznie informacyjnie.
- Taki `AG` moze oglosic przez ustalona sciezke `.onion`, ze system jest w awarii,
  stare escrow zostaly zamkniete dla nowych wejsc i nowy system powstanie od zera.
- Pojedynczy `AG` nie moze jednak wykonywac zadnych dzialan konstytucyjnych,
  reaktywacyjnych ani zmieniajacych legalnosc systemu.

### 7a. Tryb awaryjnego domkniecia escrow

- System moze miec bardzo waski tryb awaryjnego domkniecia escrow.
- Ten tryb nie sluzy do dalszego prowadzenia systemu ani do przywracania jego
  normalnego zycia.
- Ten tryb sluzy wyłącznie do:
  - zablokowania nowych wejsc i nowych escrow,
  - doprowadzenia do konca escrow juz bedacych w toku,
  - ograniczenia szkód i ochrony klientow przed trwałym zablokowaniem srodkow,
  - przejscia do `END SYSTEM`.
- Tryb awaryjny nie daje pojedynczemu `AG` nowej konstytucyjnej wladzy.
- Tryb awaryjny ma byc technicznie niezdolny do:
  - uruchamiania nowych flow,
  - zmian konfiguracji,
  - zmian binarek,
  - zmian sekretow,
  - zmian trust state,
  - reanimacji starego systemu.

### 8. Konflikt właścicielski

- System musi być odporny na konflikt między współwłaścicielami.
- Jeden właściciel nie może usunąć drugiego i przejąć systemu.
- Zwykłe quorum operacyjne nie może mieć prawa do zmiany samego składu władzy.
- Jeśli dochodzi do nierozwiązanego konfliktu właścicielskiego, system nie może zostać legalnie przepisany na jedną stronę.
- W razie takiego konfliktu poprawnym zachowaniem jest `fail-closed`, a nie „kontynuacja pod jednym zarządcą”.

### 9. Root / bootstrap / operator identity

- Operator nie wnosi trust root do systemu.
- Operator może dawać co najwyżej własny klucz publiczny do identyfikacji.
- Secret sharing nie jest podstawą normalnego mechanizmu operatorskiego.
- Warstwy bootstrap, operator access i recovery nie mogą być zlane w jeden „master access”.
- Główny materiał bootstrap/recovery i zwykła ścieżka operatorska to różne rzeczy.

### 9a. Customer service `.onion` i rola klienta

- `customer service .onion` jest jedyną legalną ścieżką klienta do systemu.
- Ta rola obsługuje:
  - rejestrację,
  - challenge-response,
  - `open escrow`,
  - `status`,
  - bounded customer event typu `delivered`.
- Nie należy opisywać tej warstwy jako "HTTP auth layer"; istotna jest rola logiczna customer service `.onion`, nie lokalny adapter transportowy.
- Dane z `nexum-cli register/challenge` nie mogą kończyć życia jako chwilowa sesja; muszą tworzyć trwały `customer identity record`.
- Przy `open escrow` system ma zamrażać `customer identity snapshot` dla `buyer` i `seller`.
- Po `open escrow` i funding klient nie steruje runtime core.
- Docelowy customer flow:
  - `buyer` otwiera escrow,
  - system zwraca adres multisig do wpłaty,
  - `buyer` wpłaca,
  - system informuje `seller`, że escrow jest ufundowane,
  - `seller` wysyła towar poza systemem,
  - `buyer` zgłasza `delivered`,
  - runtime core automatycznie kończy escrow do `seller`.

### 9b. Jednorazowe quorum AG dla escrow

- `AG-01` i `AG-02` muszą być obecne w zwykłym escrow flow raz, dając legalne quorum admission dla konkretnego escrow.
- Nie jest to model ręcznego udziału guardów w każdym późniejszym kroku runtime.
- Najczystszy kontrakt to pojedynczy `escrow admission artifact` podpisany przez `AG-01` i `AG-02`.
- Ten artefakt ma wiązać co najmniej:
  - `escrow_id`,
  - `customer identity snapshot`,
  - payout/refund policy,
  - aktywną epokę runtime trustu,
  - zakres legalnego auto-flow dla danego escrow.
- Po wydaniu tego artefaktu zwykłe escrow ma przejść do docelowego `AUTO multisig` runtime bez dalszego ręcznego udziału guardów.

### 9c. Runtime trust i artefakty hostowe

- `mailbox` tylko przesyła ciphertext envelope i na tym kończy swoją rolę.
- `mailbox` nie jest źródłem legalności, trust rootem ani źródłem prawdy workflow.
- `host vault` jest lokalnym sekretem hosta runtime i ma powstawać lokalnie na danym hoście.
- `peers.json` nie może być ręcznie klejonym źródłem prawdy; ma być lokalną materializacją aktywnego guard-approved trust bundle.
- `action_token_pub.pem` także ma być tylko lokalną materializacją aktywnego trust bundle, a nie luźnym plikiem z niejasnego pochodzenia.
- `orchestrator` prowadzi zwykły `AUTO multisig` runtime.
- `operator` nadzoruje `orchestrator` boundedly, ale nie tworzy legalności systemu.
- `AG-01` i `AG-02` mają podpisywać warunki legalnego działania automatu, a nie każdy codzienny runtime packet.

### 9d. Domkniety lifecycle bootstrapu i escrow

- Bootstrap runtime przed pierwszym escrow:
  - każdy host core generuje lokalnie własny sekret hostowy,
  - host publikuje tylko publiczny bundle hosta,
  - `AG-01` i `AG-02` podpisują aktywny `runtime_trust_bundle`,
  - każdy host materializuje lokalnie `peers.json` i `action_token_pub.pem`,
  - host startuje tylko przy zgodności lokalnego sekretu z aktywnym trust bundle.
- Lifecycle klienta:
  - `nexum-cli` generuje lokalne klucze klienta,
  - `customer service .onion` tworzy `customer_identity_record`,
  - `open escrow` zamraża `customer_identity_snapshot`,
  - późniejsza rotacja kluczy klienta nie zmienia już aktywnego escrow.
- Lifecycle escrow:
  - orchestrator buduje escrow intent,
  - `AG-01 + AG-02` podpisują jednorazowy `escrow_admission_artifact`,
  - od tego momentu zwykłe escrow przechodzi do `AUTO multisig`,
  - `buyer` po funding ma już tylko `status` i bounded event `delivered`,
  - `orchestrator` wystawia krótkie runtime `action tokeny` tylko w granicach admission scope,
  - `signer` wykonuje `sign/submit` tylko przy zgodności: trust epoch, admission scope, escrow hash i token claims.

## Wnioski

### Wniosek 1

Model docelowy jest silnie anti-capture, nie availability-first.

Znaczy to:
- lepiej zatrzymać system,
- niż dopuścić możliwość przejęcia go przez kompromitację jednej strony.

### Wniosek 1a

Najwyższy reżim bezpieczeństwa nie jest wyznaczany tylko przez nazwę operacji,
ale przez pytanie:

- czy przechwycenie tego materiału może później posłużyć do kompromitacji systemu?

Jeśli odpowiedź brzmi `tak`, to taka rzecz automatycznie wpada do klasy
`niebezpieczeństwo przejęcia wrażliwych danych`.

### Wniosek 2

Operator nie jest podmiotem decydującym o legalności systemu.

Znaczy to:
- operator koordynuje,
- ale nie stanowi root authority,
- nie ma swobody dowolnego zarządzania runtime.

### Wniosek 3

`AG-01` i `AG-02` są warstwą konstytucyjną, a nie zwykłą administracją.

Znaczy to:
- mają wyższy poziom kompetencji niż operator,
- ale także są mocno ograniczeni zasadami,
- nie mogą działać jednostronnie przy zmianach znaczących.

### Wniosek 4

System nie przewiduje legalnego trybu „jednego guarda”.

Znaczy to:
- brak mechanizmu sukcesji jednoosobowej,
- brak legalnej ścieżki przejścia do single authority,
- kompromitacja albo utrata jednej strony ma prowadzić do zatrzymania zdolności zmian, a nie do koncentracji władzy.

### Wniosek 5

Taki system nie jest oparty na pojedynczej osobie ani na zaufaniu do jednego
„superadmina”.

Znaczy to:
- odpowiedzialnosc jest rozlozona warstwowo,
- kazda warstwa ma swoj scisle ograniczony zakres odpowiedzi na znane klasy problemow,
- mechanizmy musza byc instalowane zachowawczo i z mysleniem o przeciwniku,
- bezpieczenstwo wynika z architektury i wzajemnych ograniczen podmiotow, a nie z tego, ze jedna osoba „wie wszystko”.

### Wniosek 6

System nie jest przeznaczony dla ludzi nieodpowiedzialnych ani dla osob
nieprzygotowanych do pracy z zaawansowanym bezpieczenstwem.

Znaczy to:
- model zaklada swiadomosc manipulacji, dezinformacji, presji i przejecia,
- role o wysokim poziomie odpowiedzialnosci musza rozumiec znane techniki ataku
  i znane modele myslenia przeciwnika,
- szczelnosc systemu ma wynikac z rygorystycznego przestrzegania zasad
  bezpieczenstwa, a nie z improwizacji,
- system jest projektowany z zalozeniem, ze klasy atakow, sposob myslenia
  pentesterow i hakerow oraz wektory manipulacji sa znane i musza byc aktywnie
  uwzgledniane w architekturze i procedurach.

### Wniosek 7

Prostota jest jednym z glownych mechanizmow obrony systemu.

Znaczy to:
- atakujacy moze byc hakerem, cyberprzestepca albo wykwalifikowanym agentem i
  bedzie probowal zlamac system cierpliwie, a nie tylko "sila",
- im prostszy i bardziej ograniczony model systemu, tym mniejszy i bardziej
  znany jest jego wektor ataku,
- "udziwnienia", skroty i dodatkowe wygodne sciezki tworza pulapki, ktorych
  czesto nie przewiduje nawet tworca,
- przeciwnik nie musi byc geniuszem; wystarczy, ze bedzie cierpliwy i poczeka
  na moment ludzkiego rozluznienia, przyzwyczajenia albo wykonania skrotu,
- historia uczy, ze czlowiek predzej czy pozniej popelnia blad, dlatego system
  ma byc projektowany tak, by ograniczac mozliwosc takich bledow i ich skutkow,
- szczelnosc wynika z prostoty, jawnych granic i braku niepotrzebnych
  mozliwosci, a nie z "sprytu" architektury.

### Wniosek 8

Multisig i caly model systemu nie musza byc pozornie skomplikowane, ale musza
stac na twardych fundamentach i byc rygorystycznie wykonane od poczatku do
konca.

Znaczy to:
- prosty model nie oznacza slabego modelu,
- kazdy detal implementacji, procedur i dostepu musi utrzymywac wysoki poziom
  dyscypliny,
- system ma byc sztywny, przewidywalny i odporny na odchylenia proceduralne,
- wymagany poziom rygoru ma odpowiadac systemowi projektowanemu przeciw
  przeciwnikowi wysoce wykwalifikowanemu i cierpliwemu,
- bezpieczenstwo ma byc utrzymywane konsekwentnie na kazdym poziomie, a nie
  tylko w "najwazniejszych" fragmentach.

### Wniosek 9

Krotkie okno kwarantanny jest dodatkiem operacyjnym, ale dodatkiem krytycznym.

Znaczy to:
- nie jest ono jedynym fundamentem bezpieczenstwa,
- ale w sytuacji, gdy pozostale warstwy zawioda, moze byc ostatnia realna bariera
  przed domknieciem przejecia,
- model moze zakladac wysoka dostepnosc odpowiedzialnych wlascicieli, bo chodzi
  o system o bardzo wysokiej wartosci i stalej uwadze operacyjnej,
- z tego powodu okno kwarantanny moze byc celowo krotkie,
- krotkie okno ogranicza przeciwnikowi czas na jednoczesne zlamanie,
  manipulacje i wykorzystanie obu stron przed przejsciem systemu w stan
  definitywnego zamkniecia.

### Wniosek 10

END SYSTEM zamyka legalny dostep i zdolnosc dalszego zarzadzania systemem, ale
nie musi oznaczac natychmiastowego fizycznego zatrzymania kazdego procesu juz
bedacego w toku.

Znaczy to:
- po wygaszeniu kluczy nie da sie juz legalnie zalogowac ani dalej sterowac
  systemem,
- stary stan konstytucyjny jest zamkniety,
- jednak flow escrow rozpoczetego wczesniej nie nalezy mylic z nowym dostepem
  operatorskim ani z dalsza legalna eksploatacja,
- jesli maszyny fizycznie pozostaja uruchomione, multisig i proces juz bedacy w
  toku moze dojsc do naturalnego domkniecia,
- dopiero fizyczne odlaczenie lub zatrzymanie maszyn przerywa taki tok
  wykonania,
- END SYSTEM oznacza wiec przede wszystkim koniec legalnego sterowania i
  odtwarzania starego stanu, a nie koniecznie natychmiastowe "zgaszenie
  wszystkiego" na poziomie fizycznym.
- Jesli niedostepnosc AG wynika z przyczyn zyciowych, a nie z kompromitacji,
  stary system i tak nie odzyskuje legalnej ciaglosci.
- W takim przypadku poprawnym modelem jest postawienie nowego systemu od zera,
  a nie reaktywacja starego stanu.
- Taki restart od zera powinien nastapic dopiero wtedy, gdy nie ma juz
  niedokonczonych escrow albo gdy procesy bedace w toku zostaly naturalnie
  domkniete.

### Wniosek 11

Mozna rozwazac bardzo waski tryb awaryjnego domkniecia escrow, aktywowany przy
braku kontaktu i uzasadnionym niepokoju jednej strony konstytucyjnej.

Znaczy to:
- tryb nie sluzy do ratowania ani dalszego prowadzenia systemu,
- tryb nie daje nowej wladzy ani nowej legalnosci pojedynczemu `AG`,
- tryb sluzy wyłącznie do:
  - zablokowania nowych wejsc,
  - domkniecia escrow juz bedacych w toku,
  - ochrony klientow przed trwałym zablokowaniem srodkow,
  - szybszego przejscia do `END SYSTEM`,
- taki tryb moze byc dodatkowym zabezpieczeniem, bo ogranicza okno manipulacji i
  domyka zobowiazania escrow zanim przeciwnik zdazy wykorzystac chaos operacyjny,
- jego wartosc nie moze opierac sie na "zaskoczeniu" przeciwnika, tylko na tym,
  ze technicznie nie daje nic poza finalizacja i zamknieciem systemu.

## Otwarte

### A. Co dokładnie liczy się jako „znacząca zmiana”

Do dalszego doprecyzowania:
- aktualizacja binarki,
- restart,
- zmiana konfiguracji,
- zmiana endpointów,
- zmiana kluczy,
- zmiana ról,
- zmiana trust state,
- zmiana root package,
- zmiana polityki operatorskiej.

### B. Jak dokładnie ma działać świeży artefakt czasu rzeczywistego

Do dalszego doprecyzowania:
- jakie pola musi zawierać,
- jaki ma TTL,
- jak powiązać go z konkretną operacją,
- jak wymusić single-use,
- jak chronić przed replay,
- jak związać go z aktualnym stanem systemu.

### C. Jakie są dokładne warunki full machine access dla AG-01 / AG-02

Do dalszego doprecyzowania:
- kiedy wolno wejść na host,
- przy jakiej klasie awarii,
- jaki próg zgody jest potrzebny,
- jak kończy się sesja uprzywilejowana,
- jaki ślad po niej zostaje.

### D. Czy operator używa własnego klucza publicznego tylko do identyfikacji, czy także do dodatkowego warunku admission

Obecny kierunek:
- operator nie jest trust rootem,
- operator może dawać publiczny klucz do identyfikacji,
- ale rola tego klucza w admission flow wymaga dalszego dopracowania.
