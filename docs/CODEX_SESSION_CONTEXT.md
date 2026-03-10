Podsumowanie

Po prześledzeniu flow z plików widać dwa równoległe runtime paths. Dobra ścieżka to NxmsEnvelope -> nxms-mailbox -> nxms-signer, gdzie signer ma sensowne lokalne zabezpieczenia seq, req_id i jti w transport.rs (line 51), db.rs (line 790), db.rs (line 1085), db.rs (line 1219) i action_token.rs (line 336). Zła ścieżka to równoległy direct HTTP path: orchestrator -> worker_routes/direct HTTP -> signer worker API oraz orchestrator -> wallet-rpc.

To jest statyczny review architektury i granic bezpieczeństwa. Nie uruchamiałem build/test, bo zadanie dotyczyło audytu plików.

Krytyczne

Runtime core nadal utrzymuje HTTP-first/direct-execution path obok kanonicznego transport/mailbox/signer.
Pliki: Cargo.toml (line 8), worker.rs (line 67), worker.rs (line 231), wallet.rs (line 81), db.rs (line 1590), db.rs (line 2055).
Dlaczego to ma znaczenie: control-plane nie jest już tylko control-plane. Orchestrator trzyma direct wallet-rpc i własny model worker_routes, więc w runtime istnieje drugi execution path, który omija nxms-transport i nxms-mailbox. To jest dokładnie konflikt z NXMS_STACK_SOURCE_OF_TRUTH.
Klasa: CORE.
Wysokie

Mailbox ma zbyt słabą granicę autoryzacji: auth jest opcjonalne i globalne, nie per-inbox ani per-peer.
Pliki: main.rs (line 61), api.rs (line 154), api.rs (line 216), api.rs (line 269), api.rs (line 320), db.rs (line 389).
Dlaczego to ma znaczenie: przy token=None mailbox jest otwartym relay/pull/ack API. Przy jednym wspólnym bearerze każdy posiadacz tokena może pullować dowolne to i ackować dowolny znany receipt, więc boundary relaya jest zbyt szerokie i łatwo zrobić DoS albo wyciek metadanych.
Klasa: CORE.

nxms-signer worker API nie ma osobnej warstwy service-auth, a break-glass pozwala na remote bind.
Pliki: worker_http.rs (line 102), worker_http.rs (line 152), worker_http.rs (line 208), worker_http.rs (line 256), worker_http.rs (line 336), main.rs (line 48).
Dlaczego to ma znaczenie: propose_multisig i auth_event nie wymagają auth w ogóle, a sign/submit traktują action token jako autoryzację biznesową, nie jako uwierzytelnienie wywołującego. Jeśli włączy się remote bind albo na hoście działa nieufny lokalny kod, signer wystawia wrażliwy HTTP control surface.
Klasa: CORE.

Shadow mode realnie wyłącza twarde enforce action tokenów dla sign/submit/approve_pending.
Pliki: config.rs (line 321), flow_ops.rs (line 349), flow_ops.rs (line 1126), pending.rs (line 290), NXMS_TOR_FALCON_SERVICE_MAP.md (line 135).
Dlaczego to ma znaczenie: jedna flaga env zamienia fail-closed w shadow_allow. To jest poprawny break-glass tylko jako wyjątek, ale repo nadal to normalizuje także operacyjnie w docs.
Klasa: CORE.

Spójność signer/orchestrator dla quorum proof przy submit_multisig jest warunkowa, nie bezwzględna.
Pliki: orchestrator_bridge.rs (line 112), orchestrator_bridge.rs (line 452), agent.rs (line 515), flow_ops.rs (line 1061).
Dlaczego to ma znaczenie: cross-check proof bundle z orchestratora jest wyłączalny poza production_hardening. To osłabia integralność proof_* jti/req_id dokładnie na granicy między signerem a orchestratorrem.
Klasa: CORE.

Tor-only nie jest fail-closed w runtime core; jest tylko policy mode zależnym od hardeningu.
Pliki: config.rs (line 398), config.rs (line 413), db.rs (line 2055).
Dlaczego to ma znaczenie: signer dopiero przy production_hardening=true wymusza .onion i socks5h://127.0.0.1. Orchestrator worker_routes akceptuje dowolne http|https hosty. To oznacza, że model “Tor-only communication” nie jest dziś invariantem kodu.
Klasa: CORE.

Średnie

OpenRC jest kanoniczne, ale dostarczone template’y nie są jeszcze bezpiecznym source of truth dla deployu.
Pliki: nxms-mailbox.confd (line 8), main.rs (line 31), nxms-signer.confd (line 8), nxms-escrow-orchestrator.confd (line 8).
Dlaczego to ma znaczenie: mailbox conf używa --listen, podczas gdy binarka ma serve --bind. Reszta też wygląda jak placeholdery bez jawnego, utwardzonego profilu uruchomieniowego. To zwiększa ryzyko ręcznego startu z pominięciem tokenów, bind policy albo hardeningu.
Klasa: OPS.

Legacy HTTP i break-glass nadal są mocno obecne w toolingu i docs operatorskich.
Pliki: cli_app.c (line 142), cli_app.c (line 445), cli_ext_cmds.c (line 7320), NXMS_TOR_FALCON_SERVICE_MAP.md (line 135), NXMS_MAILBOX_RUNBOOK.md (line 50).
Dlaczego to ma znaczenie: nawet jeśli nexum-cli jest tylko MANUAL, repo nadal utrzymuje nawyk escrow-http, allow-non-tor, wallet-rpc fallback i direct legacy flags. To nie łamie core samo przez się, ale silnie zwiększa ryzyko driftu operacyjnego.
Klasa: MANUAL.

Minimalny plan naprawy

Zamknąć CORE do jednego runtime path: usunąć z orchestratora direct wallet-rpc i cross-host worker_routes, zostawić tylko workflow/action-token/quorum-state.
Zrobić fail-closed granice sieciowe: mailbox auth obowiązkowy, rozdzielony co najmniej na push/pull/admin, a ack powiązać z leased inboxem lub auth principalem.
Dodać osobne uwierzytelnienie do wszystkich endpointów worker API signera i zostawić loopback-only bez runtime override w profilu produkcyjnym.
Uczynić shadow mode, allow_remote_bind, wallet-rpc fallback i podobne ścieżki wyłącznie dev/test albo jawnie legacy-break-glass, nie normalny runtime.
Wymusić Tor-only i quorum-proof verification jako invariant kodu, nie opcję production_hardening; potem dopiero uporządkować OpenRC templates i wyciąć legacy guidance z docs/CLI.

a co z podpisami falcon ? 


Worked for 1m 10s
Podpisy Falcon są tu realnie używane, nie tylko deklarowane.

Transport wymusza stały suite Falcon-1024-CT w wire.rs (line 8) i build.rs (line 15). Przy odbiorze signer odrzuca zły sig_id i bierze publiczny klucz Falcon nadawcy z peerbooka w transport.rs (line 13), transport.rs (line 31). Sama weryfikacja podpisu idzie przez crypto.rs (line 376) do nxms_ms_transport.c (line 528). Snapshoty też są podpisywane i weryfikowane Falconem w snapshot.rs (line 126) i snapshot.rs (line 137). Są też testy negatywne dla podmienionego podpisu i złego klucza nadawcy w crypto_negative.rs (line 65) i crypto_negative.rs (line 107).

Czyli: Falcon nie wygląda tu na główną dziurę. Słabsze miejsca są gdzie indziej:

Falcon uwierzytelnia pakiet i snapshot, ale nie naprawia problemów architektonicznych typu direct HTTP path, shadow mode i słabe boundary mailboxa.
Zaufanie opiera się na peerbooku sig_pk_b64 w peers.rs (line 13), więc kompromitacja provisioning/peer mapping kompromituje też Falcon trust.
Implementacja jest w natywnym C/FFI, nie w czystym Rust, więc dochodzi surface build-chain i vendor code w build.rs (line 23) i pqc_falcon.c (line 39).
Jeśli chcesz, mogę teraz zrobić osobny mini-audyt tylko dla Falcon layer: key lifecycle, peerbook trust, signed transcript, downgrade resistance, vendor provenance.


tym zajmiemy sie pozniej mam tutaj teraz konretna listye zadan i podsumowanie twoich spostrzezen 

Podsumowanie

Najmocniejsza część systemu jest dziś w nxms-signer: lokalny replay guard po seq, dedup req_id, single-use jti, walidacja action tokenów i lokalny audit wyglądają sensownie w transport.rs, db.rs, action_token.rs i flow_ops.rs. nxms-transport i nxms-mailbox też mają dobry kierunek: jeden wire format, envelope-only relay, podstawowe limity i dedup.

Największy problem nie jest kryptograficzny, tylko architektoniczny: runtime nadal ma drugi flow obok transport -> mailbox -> signer. nxms-escrow-orchestrator nadal utrzymuje direct wallet-rpc, własny HTTP worker path i routing do worker endpointów w worker.rs, wallet.rs i db.rs. Do tego mailbox ma zbyt szerokie boundary auth, signer worker API nie ma osobnego service-auth, a shadow mode i break-glass dalej są realną ścieżką runtime.

Konkretna lista zadań

[CORE][P0] Zamknąć drugi runtime flow w orchestratorze.
Zakres: usunąć z aktywnej ścieżki direct wallet-rpc i cross-host worker HTTP jako równorzędny mechanizm wykonania.
Pliki: worker.rs, wallet.rs, db.rs, Cargo.toml.
Cel: orchestrator ma być tylko control-plane, nie execution-plane.

[CORE][P0] Utwardzić granice autoryzacji mailboxa.
Zakres: zrobić auth obowiązkowy, rozdzielić auth user/admin, ograniczyć pull i ack do właściwego principal/inbox scope.
Pliki: api.rs, main.rs, db.rs.
Cel: mailbox ma być relayem, ale nie globalnym API z jednym wspólnym bearerem.

[CORE][P0] Dodać osobne service-auth do worker API signera.
Zakres: wszystkie endpointy worker HTTP muszą mieć warstwę uwierzytelnienia transportowego niezależną od action tokena.
Pliki: worker_http.rs.
Cel: action token ma autoryzować operację biznesową, a nie zastępować auth klienta HTTP.

[CORE][P0] Wyłączyć shadow mode jako realny runtime path.
Zakres: zostawić tylko jawny tryb awaryjny poza normalnym runtime, bez akceptowania sign/submit bez tokena.
Pliki: config.rs, flow_ops.rs, pending.rs.
Cel: fail-closed, nie shadow_allow.

[CORE][P0] Zrobić Tor-only i loopback-only jako invariant kodu, nie opcję hardeningu.
Zakres: .onion + socks5h + loopback bind mają być domyślne i wymagane w runtime core.
Pliki: config.rs, worker_http.rs, db.rs, NXMS_STACK_SOURCE_OF_TRUTH.md.
Cel: brak publicznych bindów i brak non-Tor ścieżek w core.

[CORE][P1] Wymusić pełną spójność signer/orchestrator dla quorum proof bez flag warunkowych.
Zakres: verify/store proof bundle ma być twardym wymogiem przy submit_multisig, nie trybem zależnym od env.
Pliki: orchestrator_bridge.rs, agent.rs, flow_ops.rs, action_token.rs, db.rs.
Cel: jeden spójny dowód proof_* jti/req_id po obu stronach.

[CORE][P1] Wpiąć orchestrator w canonical stack albo jasno odciąć nieużywane części.
Zakres: jeśli docelowo używa mailboxa, to musi mieć realne zależności i aktywny flow z nxms-transport/nxms-mailbox-client; jeśli nie, trzeba to uczciwie nazwać i odseparować.
Pliki: Cargo.toml, main.rs.
Cel: koniec z pół-przeniesioną architekturą.

[OPS][P1] Naprawić i utwardzić OpenRC jako jedyne aktywne deploy source.
Zakres: poprawić realne flagi, bindy, env i hardening profile dla mailbox/signer/orchestratora.
Pliki: nxms-mailbox, nxms-mailbox.confd, nxms-signer, nxms-signer.confd, nxms-escrow-orchestrator, nxms-escrow-orchestrator.confd.
Cel: deploy ma uruchamiać dokładnie ten bezpieczny flow, który opisuje architektura.

[MANUAL/LEGACY][P2] Oczyścić tooling i docs z normalizacji legacy HTTP i break-glass.
Zakres: escrow-http, allow-non-tor, wallet-rpc fallback, shadow mode mają być oznaczone jako legacy/operator-only.
Pliki: cli_app.c, cli_ext_cmds.c, NXMS_TOR_FALCON_SERVICE_MAP.md, NXMS_MAILBOX_RUNBOOK.md.
Cel: operator nie może być prowadzony w stronę drugiego flow.

[CORE][P2] Posprzątać integralność repo przed dalszym hardeningiem.
Zakres: usunąć markdown z kodu orchestratora i dokończyć techniczne niespójności.
Pliki: main.rs, Cargo.toml.
Cel: najpierw spójna baza, potem dalszy security pass.

Jeśli chcesz, następnym krokiem mogę z tej listy zrobić krótkie P0/P1/P2 execution order z zależnościami między zadaniami.


**Podsumowanie**

Po prześledzeniu flow z plików widać dwa równoległe runtime paths. Dobra ścieżka to NxmsEnvelope -> nxms-mailbox -> nxms-signer, gdzie signer ma sensowne lokalne zabezpieczenia seq, req_id i jti w transport.rs:51, db.rs:790, db.rs:1085, db.rs:1219 i action_token.rs:336. Zła ścieżka to równoległy direct HTTP path: orchestrator -> worker_routes/direct HTTP -> signer worker API oraz orchestrator -> wallet-rpc.

To jest statyczny review architektury i granic bezpieczeństwa. Nie uruchamiałem build/test, bo zadanie dotyczyło audytu plików.

**Krytyczne**

1. Runtime core nadal utrzymuje HTTP-first/direct-execution path obok kanonicznego transport/mailbox/signer.
Pliki: Cargo.toml:8, worker.rs:67, worker.rs:231, wallet.rs:81, db.rs:1590, db.rs:2055.  
Dlaczego to ma znaczenie: control-plane nie jest już tylko control-plane. Orchestrator trzyma direct wallet-rpc i własny model worker_routes, więc w runtime istnieje drugi execution path, który omija nxms-transport i nxms-mailbox. To jest dokładnie konflikt z NXMS_STACK_SOURCE_OF_TRUTH.  
Klasa: CORE.

**Wysokie**

1. Mailbox ma zbyt słabą granicę autoryzacji: auth jest opcjonalne i globalne, nie per-inbox ani per-peer.
Pliki: main.rs:61, api.rs:154, api.rs:216, api.rs:269, api.rs:320, db.rs:389.  
Dlaczego to ma znaczenie: przy token=None mailbox jest otwartym relay/pull/ack API. Przy jednym wspólnym bearerze każdy posiadacz tokena może pullować dowolne to i ackować dowolny znany receipt, więc boundary relaya jest zbyt szerokie i łatwo zrobić DoS albo wyciek metadanych.  
Klasa: CORE.

2. nxms-signer worker API nie ma osobnej warstwy service-auth, a break-glass pozwala na remote bind.
Pliki: worker_http.rs:102, worker_http.rs:152, worker_http.rs:208, worker_http.rs:256, worker_http.rs:336, main.rs:48.  
Dlaczego to ma znaczenie: propose_multisig i auth_event nie wymagają auth w ogóle, a sign/submit traktują action token jako autoryzację biznesową, nie jako uwierzytelnienie wywołującego. Jeśli włączy się remote bind albo na hoście działa nieufny lokalny kod, signer wystawia wrażliwy HTTP control surface.  
Klasa: CORE.

3. Shadow mode realnie wyłącza twarde enforce action tokenów dla sign/submit/approve_pending.
Pliki: config.rs:321, flow_ops.rs:349, flow_ops.rs:1126, pending.rs:290, NXMS_TOR_FALCON_SERVICE_MAP.md:135.  
Dlaczego to ma znaczenie: jedna flaga env zamienia fail-closed w shadow_allow. To jest poprawny break-glass tylko jako wyjątek, ale repo nadal to normalizuje także operacyjnie w docs.  
Klasa: CORE.

4. Spójność signer/orchestrator dla quorum proof przy submit_multisig jest warunkowa, nie bezwzględna.
Pliki: orchestrator_bridge.rs:112, orchestrator_bridge.rs:452, agent.rs:515, flow_ops.rs:1061.  
Dlaczego to ma znaczenie: cross-check proof bundle z orchestratora jest wyłączalny poza production_hardening. To osłabia integralność proof_* jti/req_id dokładnie na granicy między signerem a orchestratorrem.  
Klasa: CORE.

5. Tor-only nie jest fail-closed w runtime core; jest tylko policy mode zależnym od hardeningu.
Pliki: config.rs:398, config.rs:413, db.rs:2055.  
Dlaczego to ma znaczenie: signer dopiero przy production_hardening=true wymusza .onion i socks5h://127.0.0.1. Orchestrator worker_routes akceptuje dowolne http|https hosty. To oznacza, że model “Tor-only communication” nie jest dziś invariantem kodu.  
Klasa: CORE.

**Średnie**

1. OpenRC jest kanoniczne, ale dostarczone template’y nie są jeszcze bezpiecznym source of truth dla deployu.
Pliki: nxms-mailbox.confd:8, main.rs:31, nxms-signer.confd:8, nxms-escrow-orchestrator.confd:8.  
Dlaczego to ma znaczenie: mailbox conf używa --listen, podczas gdy binarka ma serve --bind. Reszta też wygląda jak placeholdery bez jawnego, utwardzonego profilu uruchomieniowego. To zwiększa ryzyko ręcznego startu z pominięciem tokenów, bind policy albo hardeningu.  
Klasa: OPS.

2. Legacy HTTP i break-glass nadal są mocno obecne w toolingu i docs operatorskich.
Pliki: cli_app.c:142, cli_app.c:445, cli_ext_cmds.c:7320, NXMS_TOR_FALCON_SERVICE_MAP.md:135, NXMS_MAILBOX_RUNBOOK.md:50.  
Dlaczego to ma znaczenie: nawet jeśli nexum-cli jest tylko MANUAL, repo nadal utrzymuje nawyk escrow-http, allow-non-tor, wallet-rpc fallback i direct legacy flags. To nie łamie core samo przez się, ale silnie zwiększa ryzyko driftu operacyjnego.  
Klasa: MANUAL.

**Minimalny plan naprawy**

1. Zamknąć CORE do jednego runtime path: usunąć z orchestratora direct wallet-rpc i cross-host worker_routes, zostawić tylko workflow/action-token/quorum-state.  
2. Zrobić fail-closed granice sieciowe: mailbox auth obowiązkowy, rozdzielony co najmniej na push/pull/admin, a ack powiązać z leased inboxem lub auth principalem.  
3. Dodać osobne uwierzytelnienie do wszystkich endpointów worker API signera i zostawić loopback-only bez runtime override w profilu produkcyjnym.  
4. Uczynić shadow mode, allow_remote_bind, wallet-rpc fallback i podobne ścieżki wyłącznie dev/test albo jawnie legacy-break-glass, nie normalny runtime.  
5. Wymusić Tor-only i quorum-proof verification jako invariant kodu, nie opcję production_hardening; potem dopiero uporządkować OpenRC templates i wyciąć legacy guidance z docs/CLI.

jhak to widzisz
zgadzaasz sie ze mna czy wybieramy twoja sciezke ?

1. Masz dziś dwa równoległe runtime paths.
To jest najważniejszy problem. Dobra ścieżka to NxmsEnvelope -> mailbox -> signer. Zła ścieżka to direct HTTP / worker routes / direct wallet-rpc z orchestratora. To trzeba zamknąć do jednej architektury.

2. Orchestrator nie jest czystym control-plane.
Dziś nadal ma elementy execution path. Powinien tylko prowadzić workflow, quorum state, tokeny, integrity i SLO, a nie wykonywać alternatywną ścieżkę operacji.

3. Mailbox ma za szeroką granicę zaufania.
Auth jest zbyt słabe albo opcjonalne. Mailbox nie może być otwartym relayem z jednym szerokim tokenem albo bez auth.

4. Signer worker API jest zbyt łatwe do wystawienia.
Brakuje twardej osobnej warstwy service-auth, a remote bind / break-glass osłabiają model bezpieczeństwa.

5. Shadow mode i podobne ścieżki są zbyt normalne.
To nie może być zwykła opcja runtime. Ma to być tylko jawne legacy-break-glass albo dev/test.

6. Tor-only i quorum-proof verification nie są jeszcze invariantem kodu.
Są warunkowe, a powinny być fail-closed i domyślne.

7. OpenRC i docs są jeszcze tylko częściowo gotowe.
To nie jest największy problem, ale template’y i runbooki nie są jeszcze finalnym source of truth.

Konkretna lista zadań
Zadanie 1

Naprawić build workspace.
Najpierw cargo check ma działać dla całego nowego repo.

Zadanie 2

Wydzielić i doprowadzić do builda nxms-monero-core.
To ma być czysty crate domenowy bez escrow_http.

Zadanie 3

Usunąć z orchestratora drugi execution path.
Wyciąć direct HTTP / worker routes / direct wallet-rpc jako normalną ścieżkę runtime.

Zadanie 4

Zostawić orchestrator jako czysty control-plane.
Ma robić tylko workflow, state, quorum proof, action token tooling, integrity i SLO.

Zadanie 5

Utwardzić mailbox.
Auth ma być obowiązkowy i sensownie rozdzielony. Mailbox nie może być otwartym relayem.

Zadanie 6

Utwardzić signer worker API.
Loopback-only jako normalny tryb, bez półotwartego remote bind. Jeśli auth zostaje, to osobne service-auth.

Zadanie 7

Wyłączyć shadow mode i break-glass jako normalny runtime.
Zostawić tylko jako jawne dev/test albo legacy-break-glass.

Zadanie 8

Wymusić Tor-only jako invariant.
Nie jako opcję zależną od production_hardening, tylko jako domyślny model.

Zadanie 9

Wymusić quorum-proof verification jako invariant.
Submit ma wymagać pełnego i spójnego proof bundle bez warunkowego osłabiania.

Zadanie 10

Dopiero potem poprawić OpenRC, Alpine smoke i deployment.
Najpierw kod i architektura, potem usługi i VM-ki.

Kolejność prac

build workspace

nxms-monero-core

orchestrator bez drugiego flow

mailbox auth

signer worker hardening

wycięcie shadow/break-glass z normalnego runtime

Tor-only + quorum verification fail-closed

OpenRC + Alpine smoke

dopiero potem VM-ki

To jest teraz właściwa mapa.

jwk to widzisz czy idziemy twoja sciezka ?


Idziemy twoją ścieżką.

To nie jest w praktyce alternatywa wobec mojej, tylko lepiej docięta wersja tego samego kierunku. Zgadzam się z Twoją diagnozą i z kolejnością priorytetów: najpierw domknąć architekturę i invarianty bezpieczeństwa, dopiero potem deploy i VM-ki.

Widzę to tak:

build workspace
To ma być minimalny baseline techniczny, nie “wszystko gotowe”. Czyli: repo ma się składać, cargo check ma przechodzić, workspace ma być spójny.

nxms-monero-core
Zgoda. To trzeba ustawić jako czysty crate domenowy, bez wciągania go w stare flow.

orchestrator bez drugiego flow
To jest najważniejsza robota architektoniczna. Tu naprawdę zamykamy rozdwojenie systemu.

orchestrator jako czysty control-plane
Też zgoda. Dla mnie to jest naturalna druga połowa punktu 3.

mailbox auth
Tak. Mailbox musi być relayem z twardą granicą auth, nie szerokim API.

signer worker hardening
Tak. Loopback-only jako norma, osobny service-auth jeśli HTTP worker zostaje.

wycięcie shadow/break-glass z normalnego runtime
Tak. To musi przestać być zwykłą opcją operacyjną.

Tor-only + quorum verification fail-closed
Pełna zgoda. To mają być invarianty, nie “tryb hardened”.

OpenRC + Alpine smoke
Dopiero tutaj. To jest warstwa OPS po domknięciu CORE.

VM-ki
Na samym końcu. Też zgoda.

Jedyna drobna uwaga:

punkt 1 może wymagać minimalnych ruchów w nxms-monero-core i nxms-escrow-orchestrator, więc traktowałbym build workspace jako etap stabilizacji podstaw, a nie osobny duży milestone.
Czyli roboczo przyjmuję dokładnie ten plan jako właściwą mapę prac. Jeśli chcesz, w następnym kroku mogę zamienić to na bardzo twardy backlog wykonawczy P0/P1 z definicją done dla każdego zadania.