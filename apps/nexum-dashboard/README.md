# Lokalny dashboard Nexum

Pierwszy działający prototyp graficznego przebiegu: połączenie, wybór
escrow, challenge, hasło i podgląd. Wszystkie dane są syntetyczne.
Nie ma prawdziwych kluczy, podpisów, połączenia z Torem ani Monero.
Nie podawaj prawdziwego hasła lub danych portfela. Hasło demonstracyjne:
`nexum-demo-2026`.

Klasyfikacja: **MANUAL** dla GUI, **OPS** dla opakowania Docker.
Prototyp nie implementuje nowego kontraktu kryptograficznego ani zmian CORE.
[Architektura](../../docs/NXMS_STACK_SOURCE_OF_TRUTH.md) i
[plan dashboardu](../../docs/reference/NXMS_LOCAL_DASHBOARD_PLAN.md)
określają kolejne etapy.

## Uruchomienie bez kompilacji

Z katalogu repo:

```sh
python3 -B apps/nexum-dashboard/server.py
```

Otwórz `http://127.0.0.1:8787`. Proces pozostaje uruchomiony w terminalu;
`Ctrl+C` go zatrzymuje. Restart usuwa cały stan demonstracji. Program
nie zapisuje haseł ani sesji na dysku i nie wykonuje połączeń zewnętrznych.

## Uruchomienie w Dockerze

Po przygotowaniu Dockera i jego danych na wybranej partycji:

```sh
sudo docker compose -f apps/nexum-dashboard/compose.demo.yml up --build -d
sudo docker compose -f apps/nexum-dashboard/compose.demo.yml down
```

To osobny kontener z limitem 0,5 CPU i 128 MiB RAM, bez dodatkowego swapu.
Nie ma dostępu do socketu Dockera, vaultów, workspace ani wolumenów Monero.
Panel jest publikowany tylko na hostowym `127.0.0.1:8787`; sieć demo jest
wewnętrzna. Na etapie budowy obrazu pobierany jest Python z repozytorium
Alpine. Tag bazowy `alpine:3.23` jest odpowiedni dla tego prototypu;
pakiet wydaniowy wymaga przypięcia obrazu i zależności przed publikacją.

Istniejący `nexum-docker-agent` zarządza tylko kontenerami dev i stagenet.
Nie rozszerzamy jego uprawnień dla tego prototypu. Uruchomienie nowego
kontenera jest odrębną czynnością administratora.

Konfigurację sieci i limitów opisują
[Docker Compose networks](https://docs.docker.com/reference/compose-file/networks/)
i [Docker Compose services](https://docs.docker.com/reference/compose-file/services/).

## Sprawdzenie przebiegu

1. Rozpocznij demonstrację, wybierz jedno escrow i przejdź do challenge.
2. Sprawdź błędne hasło, anulowanie i wygaśnięcie wyzwania.
3. Użyj jawnego hasła demo i zatwierdź symulację podpisu.
4. Sprawdź stan, historię oraz utratę i przywrócenie połączenia.
5. Wygaś dostęp lub zamknij podgląd; nowe wejście wymaga nowego challenge.

Testy HTTP uruchamiaj kolejno:

```sh
cd apps/nexum-dashboard
python3 -B -m unittest -v test_server.py
```

Testy sprawdzają przepływ demonstracji, odmowy dostępu i ochronę lokalnego
API. Nie są testami Falcona, multisig ani rzeczywistego Tor/stagenet.

## Granica prototypu

Endpointy mają prefiks `/api/demo`. Cookie identyfikuje wyłącznie chwilowy
stan lokalnej demonstracji, a nie konto użytkownika. Hasło jest publiczną
wartością testową; jego porównanie nie jest odblokowaniem prawdziwego vaulta.
Podpis jest jawnie symulowany. Nie ma routingu do CLI, wykonania shell,
rejestracji, logowania ani operacji na środkach.

Prawdziwy backend vaulta, powiązanie klucza z escrow, klucze kanału odczytu
i customer service przez Tor wymagają osobnego wdrożenia zgodnie z planem.
WASM pozostaje odłożony.
