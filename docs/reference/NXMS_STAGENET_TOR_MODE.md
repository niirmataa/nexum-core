# NXMS stagenet: tryb Tor-only — weryfikacja i przełączanie

Klasa: **REFERENCE** (OPS). Nie redefiniuje architektury.
Status modelu: `docs/NXMS_STACK_SOURCE_OF_TRUTH.md` sekcja 9 (wyjście OPS
synchronizacji direct wygasa wraz z potwierdzeniem trybu Tor).

## Tryb sieciowy jest ustalony na stałe przy tworzeniu kontenera

`tools/alpine-stagenet.sh` przyjmuje `NXMS_STAGENET_NETWORK=direct|tor`
(domyślnie `direct`) i wbudowuje wartość w kontener przy `docker create`.
`start` odmówi obsługi istniejącego kontenera z innym trybem.

Przełączenie wymaga rekreatywacji kontenera **z tym samym wolumenem**
`nexum-alpine-stagenet-data` (dane łańcucha przetrwają, sync wznawia się
z dysku):

1. `stop` kontenera (łagodnie; wolumen nietknięty),
2. usunięcie samego kontenera (nigdy wolumenu),
3. `NXMS_STAGENET_NETWORK=tor sh tools/alpine-stagenet.sh start`
   (składnia `sudo env VAR=... sh ...` jest celowa),
4. weryfikacja poniżej.

Warstwa kontenera (pakiety `apk`) jest reinstalowana przy każdym odtworzeniu;
bootstrap `apk` korzysta z sieci hosta. Gwarancja Tor-only dotyczy ruchu
moneroda P2P.

## Dowody weryfikacji Tor-only (2026-10-15)

- log startowy kontenera: `alpine-stagenet: network=tor`,
- Tor: `Bootstrapped 100%`,
- cmdline moneroda (`docker top`) kończy się `--proxy socks5://127.0.0.1:9050`
  — proxy obejmuje cały P2P; skrypt nie ma clearnet fallbacku, śmierć Tora
  zatrzymuje moneroda,
- RPC tylko na loopback wewnątrz kontenera (`--restricted-rpc`), brak
  publikowanych portów, `in-peers 0`,
- synchronizacja przez Tora działa: węzeł dwukrotnie nadrobił zaległości do
  bieżącej wysokości sieci po przełączeniu.

Stan przed: kontener legacy bez zmiennej `NXMS_STAGENET_NETWORK`, czyli
domyślny tryb `direct` (zgodnie z komunikatem skryptu).

## Otwarte obserwacje (do domknięcia przed podłączeniem portfeli)

1. **Łączność przez exity Tora jest niestabilna.** Wiele prób łączenia na
   port 38080 kończy się timeoutem 15 s i `Giving up`; węzeł bywa godzinami
   bez pary, mimo poprawnego tunelowania. Wymaga wzmocnienia: znane peery
   (`--add-peer`), docelowo peery `.onion`.
2. **Rozstrzyganie nazw seedów idzie poza Torem.** Tor ostrzega w logu, że
   aplikacja podaje mu gotowe IP (socks5 zamiast socks4a/socks5h) — same
   lookupy DNS nie są tunelowane. Do domknięcia przed realnym runtime.
3. Ostrzeżenia `0 blocks in the last 90 minutes` występowały przy błędzie
   zegara hosta +2 h i są artefaktem czasu, nie partycji sieciowej.

## Zasada dostępu do Dockera

Właściciel wybrał root-owned broker (`tools/nexum-docker-agent`) zamiast
członkostwa w grupie `docker`. Żaden skrypt, instalator ani asystent nie
dodaje użytkownika do grupy `docker` — także „przy okazji" bloków
instalacyjnych. Grupa może istnieć pusta.
