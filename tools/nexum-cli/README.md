# Nexum CLI (C) — Falcon-1024 (CT) + NTRU KEM

CLI do testów Nexum (passwordless / key-based). Projekt zakłada **brak JS** w przeglądarce — kryptografia dzieje się w CLI.

## Status

Docelowy kontrakt architektoniczny dla `tools/nexum-cli` został już zawężony do
`v1` auth / registration / challenge-response / sign / verify / keygen.

Obecny kod nie jest jeszcze do tego w pełni przepisany:
- nadal zawiera legacy/manual surface wykraczający poza target scope,
- komendy escrow/operator zostaną usunięte w późniejszym etapie,
- ten plik opisuje stan przejściowy implementacji, nie finalny zakres narzędzia.

## Co potrafi v1
- `init` — tworzy katalog i pusty zaszyfrowany vault
- `keygen` — generuje **Falcon-1024 (CT)** + **NTRU KEM**, zapisuje w vault
- `register` — rejestruje konto (PoW + challenge, JSON API)
- `login` — pobiera challenge, podpisuje Falconem i zapisuje `session_id + csrf`
- `prekeys-*` — generowanie, upload i rotacja prekeys (podpis Falconem batcha)
- `dm-send` / `dm-inbox` — E2E DM (KEM + Falcon)

## Vault ("szyfrowany folder")
W v1 vault to **jeden plik** `~/.nexum/vault.bin` zaszyfrowany:
- AEAD: `XChaCha20-Poly1305`
- KDF: `Argon2id`

W środku trzymamy klucze i manifest. Manifest jest dodatkowo podpisany Falconem (integrity / wykrywanie korupcji).

## Wymagania (Alpine)
Pakiety:
```sh
apk add --no-cache build-base libsodium-dev curl-dev
```

### liboqs (dla NTRU KEM)
Ten CLI używa **liboqs** dla KEM.
Zainstaluj:
- albo z paczki (jeśli masz w repozytorium/portach)
- albo zbuduj ze źródeł (skrypt):

```sh
./scripts/build_liboqs_alpine.sh
```

## Build
```sh
make
```

Powstaje binarka: `./nexum`

## Tor (wymagany)
CLI **wymusza Tor** dla komend sieciowych.
Upewnij się, że masz Tor i SOCKS na `127.0.0.1:9050` (socks5h).

Szybki check:
```sh
./nexum tor-check --socks5 socks5h://127.0.0.1:9050
```
`tor-check` — kontrola warstwy transportowej. Zasada: fail‑closed. Brak SOCKS5 = brak ruchu. Minimalizuje ryzyko przypadkowego clearnetu i błędnej diagnozy na etapie rejestracji/DM.

## Captcha / gate (opcjonalnie)
Jeśli serwer wymusza captcha na `/api` (np. `GATE_API=1`), ustaw w CLI cookies:
- `FF_GATE_OK` — wartość cookie `gate_ok`
- `FF_SCAPTCHA_CID` — wartość cookie `scaptcha_cid` (opcjonalnie)

Przykład:
```sh
export FF_GATE_OK="...cookie..."
export FF_SCAPTCHA_CID="...cookie..."
```

## Konfiguracja endpointów
CLI czyta `~/.nexum/config.json` (tworzy się przy `init`).
Możesz też podać własny plik globalnie: `--config /ścieżka/do/config.json`.

Obsługiwane pola:
```json
{
  "dir": "/home/user/.nexum",
  "base": "http://xxxx.onion",
  "socks5": "socks5h://127.0.0.1:9050",
  "network": {
    "base": "http://xxxx.onion",
    "socks5": "socks5h://127.0.0.1:9050"
  }
}
```
`network.base` i `network.socks5` mają priorytet nad polami top-level.

## Użycie
```sh
./nexum init
./nexum keygen --kem ntru-hrss701
./nexum register --base http://XXXX.onion --nick alice --socks5 socks5h://127.0.0.1:9050
./nexum login --base http://XXXX.onion --nick alice --socks5 socks5h://127.0.0.1:9050

# prekeys + DM
./nexum prekeys-gen --count 20 --ttl-days 14
./nexum prekeys-upload --base http://XXXX.onion --count 20 --socks5 socks5h://127.0.0.1:9050
./nexum dm-send --base http://XXXX.onion --to bob --msg "hello" --socks5 socks5h://127.0.0.1:9050

# escrow (Tor-only)
./nexum escrow-proposal --base http://XXXX.onion --id 30 --nick arbiter --token <arbiter_token> --socks5 socks5h://127.0.0.1:9050
./nexum escrow-release --base http://XXXX.onion --id 30 --nick seller --token <seller_token> --tx-data-hex <multisig_txset_hex> --signer-sign-action-token-file /secure/sign.action.token --signer-submit-action-token-file /secure/submit.action.token --idempotency-key rel-30-01 --retry-max 3 --retry-backoff-ms 1500 --socks5 socks5h://127.0.0.1:9050
./nexum escrow-refund --base http://XXXX.onion --id 30 --nick buyer --token <buyer_token> --tx-data-hex <multisig_txset_hex> --signer-action-token-env NXMS_ACTION_TOKEN --idempotency-key ref-30-01 --retry-max 3 --retry-backoff-ms 1500 --socks5 socks5h://127.0.0.1:9050
./nexum escrow-release-pipeline --base http://XXXX.onion --id 30 --seller-nick seller --seller-token <seller_token> --arbiter-nick arbiter --arbiter-token <arbiter_token> --seller-signer-sign-action-token-file /secure/seller.sign.action.token --seller-signer-submit-action-token-file /secure/seller.submit.action.token --arbiter-signer-submit-action-token-file /secure/arbiter.submit.action.token --idempotency-prefix relpipe-30 --retry-max 2 --retry-backoff-ms 1500 --socks5 socks5h://127.0.0.1:9050

# worker routes (operator/local orchestrator wrapper)
./nexum worker-route-set --escrow-id-hex 0000000000000000000000000000002a --role seller --endpoint http://127.0.0.1:28090 --orch-db /var/lib/nxms/orch.db
./nexum worker-route-show --escrow-id-hex 0000000000000000000000000000002a --role seller --orch-db /var/lib/nxms/orch.db
./nexum worker-route-reconcile --stale-after-ms 86400000 --limit 500 --fail-on-findings --orch-db /var/lib/nxms/orch.db
```

## Uwagi
- Domyślny KEM to `ntru-hrss701`. Możesz ustawić `ntru-hps2048677`.
- Podpis używa Falcon-1024 i **formatu CT**.
