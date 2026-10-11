# Nexum CLI

`tools/nexum-cli` jest lokalnym CLI w C dla wąskiego user auth/crypto path.

Nie jest to operator UI.
Nie jest to user escrow client.
Nie jest to runtime control plane.
Nie jest to guard-admin tooling.

## Docelowa rola

Docelowy kontrakt architektoniczny:
- `nexum-cli` służy tylko do lokalnego vaulta / challenge-response / sign / verify / key generation primitives
- user escrow flow idzie wyłącznie przez dedykowaną warstwę `.onion hidden service`
- operator manual console ma być osobnym narzędziem awaryjnym
- guard/admin tooling ma być osobnym narzędziem o wyższym poziomie uprzywilejowania

Source of truth:
- [docs/NXMS_STACK_SOURCE_OF_TRUTH.md](../../docs/NXMS_STACK_SOURCE_OF_TRUTH.md)
- [docs/reference/DECISIONS.md](../../docs/reference/DECISIONS.md)

## Status Rewrite

Ten katalog nadal wymaga przepisania do docelowego kontraktu.

Aktualny kod:
- nadal zawiera legacy/manual surface wykraczający poza target scope
- nadal zawiera komendy i ścieżki, które nie powinny zostać w finalnym `nexum-cli`
- powinien zostać docięty do małego `v1-style` auth/crypto client

Lokalny dashboard ma działać bez kont, rejestracji i logowania, zgodnie z
sekcją 8c `docs/NXMS_STACK_SOURCE_OF_TRUTH.md`. Obecne komendy `register`
i `login` są legacy, nie ukrytym mechanizmem nowego GUI. Pełny review CLI
pozostaje odłożony; przed użyciem vaulta lub podpisu w dashboardzie trzeba
przejrzeć i wydzielić konkretną używaną ścieżkę.

Ten plik opisuje docelowy nurt architektoniczny, a nie pełny historyczny zakres obecnej implementacji.

## Minimalny Target Zakres

Docelowo w `nexum-cli` mają zostać tylko komendy z tej klasy:
- `init`
- `keygen`
- `show-keys`
- `list-kem`
- `pow-solve`
- `respond`

Jeśli później dojdą nowe komendy, muszą nadal należeć do user auth/crypto boundary i nie mogą otwierać drugiego flow.

## Crypto

Obecny kod używa:
- FREE Falcon (ternary N=1536) do podpisów
- KEM przez liboqs

Vault przechowuje lokalny materiał kluczowy CLI i jest chroniony hasłem użytkownika.

## Build

Aktualny lokalny build target dla tego katalogu jest:

```sh
cd tools/nexum-cli
make
```

Typowe zależności dla Alpine:

```sh
apk add --no-cache build-base libsodium-dev curl-dev oqs-dev jansson-dev sqlite-dev
```

## Tor

Komunikacja klienta ma działać tylko przez Tor/onion. Historyczne
`register/login` nie definiują bezkontowego kontraktu dashboardu.
Obecny `respond` wymaga dostosowania do powiązania challenge z usługą,
escrow i zakresem odczytu; nie jest jeszcze gotowym adapterem GUI.

## Czego Ten README Nie Obiecuje

Ten README celowo nie opisuje:
- escrow commands jako docelowego scope
- operator runtime commands jako docelowego scope
- worker-route / preflight / maintenance jako docelowego scope
- żadnego operator UI

Jeśli taki kod nadal istnieje w implementacji, należy go traktować jako stan przejściowy do usunięcia lub wydzielenia.
