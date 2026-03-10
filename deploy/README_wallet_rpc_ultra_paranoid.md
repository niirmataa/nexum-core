# Ultra-Paranoid `wallet-rpc` (split buyer/seller)

Cel: uruchomic lokalne `monero-wallet-rpc` dla buyer/seller jako osobne uslugi, bez sekretow
w `argv`, z minimalnymi uprawnieniami i loopback-only.

## Zasady

- osobny user systemowy na role (`nxmr-buyer`, `nxmr-seller`, opcjonalnie `nxmr-arbiter`)
- `wallet-rpc` bind tylko `127.0.0.1`
- auth przez `rpc-login`
- sekrety tylko w `config-file` (`0600`), nie w `ps`
- katalogi walletow rola-specific (`0700`)
- logi serwisowe `0600`

## Pliki template w repo

- OpenRC service template:
  - `escrow/deploy/openrc/monero-wallet-rpc-split-role`
- OpenRC `conf.d` example:
  - `escrow/deploy/openrc/monero-wallet-rpc-split-role.confd.example`
- Monero `wallet-rpc` config example:
  - `escrow/deploy/monero/wallet-rpc-split-role.conf.example`

## Minimalny rollout (buyer/seller)

1. Utworz userow:

```sh
adduser -S -D -H -G monero nxmr-buyer
adduser -S -D -H -G monero nxmr-seller
```

2. Ustaw ownership/perms katalogow:

```sh
chown -R nxmr-buyer:monero /var/lib/monero/real3p_CURRENT/buyer
chown -R nxmr-seller:monero /var/lib/monero/real3p_CURRENT/seller
find /var/lib/monero/real3p_CURRENT/buyer -type d -exec chmod 700 {} +
find /var/lib/monero/real3p_CURRENT/seller -type d -exec chmod 700 {} +
find /var/lib/monero/real3p_CURRENT/buyer -type f -exec chmod 600 {} +
find /var/lib/monero/real3p_CURRENT/seller -type f -exec chmod 600 {} +
```

3. Utworz configi `wallet-rpc` per role (`/etc/monero/*.conf`, mode `0600`) na bazie
   `escrow/deploy/monero/wallet-rpc-split-role.conf.example`.

4. Utworz uslugi OpenRC:

```sh
cp escrow/deploy/openrc/monero-wallet-rpc-split-role /etc/init.d/monero-wallet-rpc-real3p-buyer
cp escrow/deploy/openrc/monero-wallet-rpc-split-role /etc/init.d/monero-wallet-rpc-real3p-seller
chmod 0755 /etc/init.d/monero-wallet-rpc-real3p-buyer /etc/init.d/monero-wallet-rpc-real3p-seller
```

5. Utworz `conf.d` per rola na bazie
   `escrow/deploy/openrc/monero-wallet-rpc-split-role.confd.example`:

- `/etc/conf.d/monero-wallet-rpc-real3p-buyer`
- `/etc/conf.d/monero-wallet-rpc-real3p-seller`

6. Start/restart:

```sh
rc-service monero-wallet-rpc-real3p-buyer restart
rc-service monero-wallet-rpc-real3p-seller restart
```

7. Weryfikacja:

```sh
ps aux | grep monero-wallet-rpc | grep real3p
# oczekiwane: tylko '--config-file ...', bez 'rpc-login user:pass' w argv
```

## Integracja z `nexum_cli` (bez sekretow w argv)

`escrow-gate3-ready` obsluguje teraz:

- `--buyer-wallet-rpc-user-env`
- `--buyer-wallet-rpc-pass-env`
- `--buyer-wallet-rpc-user-file`
- `--buyer-wallet-rpc-pass-file`
- analogicznie `seller-*`

Zalecenie: uzywaj `--*-env` albo `--*-file`; unikaj `--*-pass <...>` w produkcji.

## Znana anomalia (idempotency / create timeout)

Zaobserwowano przypadek, gdzie:

- pierwszy `escrow-create` timeoutuje po stronie klienta (`transport timeout`),
- backend mimo to zapisuje escrow,
- retry z tym samym `idempotency-key` moze zwrocic nowy `id`, zamiast deduplikacji.

Skutek: mozliwe osierocone escrow (`NEW`) po timeoutach klienta.

Mitigacja operacyjna (do czasu naprawy backendu):

- traktuj `run_dir/SOURCE_OF_TRUTH.txt` jako jedyne zrodlo prawdy dla aktywnego runu,
- po timeout `escrow-create` sprawdz DB/API po `memo`/czasie przed retry,
- oznacz niekanoniczne escrow jako orphan w artefaktach runu.

## Post-READY flow bez wrapperow (native `nexum_cli`)

Po `escrow-gate3-ready` nie trzeba uruchamiac `scripts/nxms_http_real_flow.sh`.
Docelowy/native sequence:

1. `escrow-fund` (funding transfer buyer -> `deposit_address`)
2. `escrow-wait-funded` (poll stanu escrow do `FUNDED`/`RELEASED`)
3. `escrow-funded-sync` (natywny command w `nexum_cli`, wywoluje backend orchestratora `http-flow funded-sync`)
4. `worker-route-set` dla `seller` i `arbiter`
5. `escrow-release-pipeline` (seller + arbiter release path) albo `escrow-refund`

Uwaga: `escrow-funded-sync` usuwa wrapper shellowy, ale backend orchestrator bin nadal ma
wlasny kontrakt CLI. To jest akceptowalne architektonicznie (backend binary), ale dalej warto
zrobic osobny hardening orchestratora pod sekrety (`env/file`) jesli chcesz pelne "ultra-paranoid"
takze na tym kroku.
