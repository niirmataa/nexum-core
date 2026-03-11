# Architecture: freeTUNNEL v0.1

Cel: opisać warstwę transportową jako opcję obok Tor. freeTUNNEL nie zastępuje DM – przenosi dowolny ruch aplikacyjny (DM, API, admin).

Status: koncepcyjny (do realizacji później).

## Zakres
- Transport punkt‑punkt (client ↔ server).
- Opcjonalny wybór w kliencie: `tor` lub `freetunnel`.
- Silna autentyczność serwera (Falcon).
- Odporność na store‑now/decrypt‑later (PQC).

## Wersja 0.1 – parametry (propozycja)
- KEM: **FrodoKEM‑640‑SHAKE** (default, tryb konserwatywny).
- KEM alternatywny: **Kyber‑768** (szybszy, bardziej praktyczny).
- ECDH: **X25519** (ephemeral).
- Podpis: **Falcon‑1024‑CT** (pinowany public key).
- KDF: **HKDF‑SHA256**.
- AEAD: **XChaCha20‑Poly1305**.
- Transcript context: `FREE_TUNNEL_V0`.

## Handshake (hybrydowy)
1. ClientHello:
   - `client_ecdh_pub`
   - `client_kem_pub`
   - `client_nonce`
2. ServerHello:
   - `server_ecdh_pub`
   - `kem_ct` (encapsulation do `client_kem_pub`)
   - `server_nonce`
   - `sig` = Falcon‑sign( transcript )
3. Client:
   - weryfikuje `sig` na pinowanym `server_falcon_pk`.
   - wylicza `ss_kem = KEM.decaps(kem_ct, client_kem_sk)`.
   - wylicza `ss_ecdh = X25519(client_eph_sk, server_ecdh_pub)`.
4. Master secret:
   - `master = HKDF(ss_kem || ss_ecdh, salt=client_nonce||server_nonce, info="FREE_TUNNEL_V0")`.
5. Klucze sesji:
   - `k_tx`, `k_rx` z HKDF‑expand.
6. Transport:
   - szyfrowanie XChaCha20‑Poly1305, nonces monotonic per direction.

## Autentyczność i tożsamość
- Serwer podpisuje transcript Falconem.
- Klucz publiczny serwera jest pinowany i dystrybuowany out‑of‑band.
- Opcja 0.2: client‑auth (podpis klienta) jako tryb „mutual auth”.

## Integracja z ekosystemem
- DM pozostaje E2E na poziomie aplikacji.
- freeTUNNEL to tylko transport (nie ingeruje w payload DM).
- ff‑cli może mieć flagę: `--transport tor|freetunnel`.

## Założenia bezpieczeństwa
- Klucze ephemeral (KEM + ECDH) dla forward secrecy.
- Brak trybu „plaintext”.
- Brak zależności od systemowego czasu w handshake.

## Ryzyka i uwagi
- Większa złożoność vs Tor.
- Wymaga stabilnego routingu (np. własne entry/relay).
- Konieczna zgodność wersji (transcript context).

## Następne kroki (gdy wrócimy)
- Zdefiniować formaty binarne wiadomości.
- Ustalić politykę rotacji kluczy serwera.
- Zbudować minimalny klient testowy.
