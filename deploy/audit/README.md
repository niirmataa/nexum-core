# NXMS Audit Profiles

Repo-managed profile files:

- `wsl-repo.rules`
- `alpine-vm.rules`

Założenia:

- `wsl-repo.rules` obserwuje tylko ścieżki o wysokim znaczeniu dla pracy nad repo.
- `alpine-vm.rules` obserwuje krytyczne pliki runtime i pełny `execve` na hoście runtime.
- `alpine-vm.rules` zakłada root-only custody dla logów audytu oraz blokadę reguł `-e 2` po ich załadowaniu.

Te profile nie próbują logować wszystkiego.
Ich celem jest szybka odpowiedź na pytania:

- czy ktoś czytał albo modyfikował repo / archive / bundle,
- czy ktoś dotykał konfiguracji runtime,
- czy ktoś uruchamiał procesy na hoście runtime,
- czy ktoś zaglądał do operatorskich śladów.

Instalacja i uruchomienie:

- pakiet `audit`
- pakiet `audit-openrc` na Alpine/OpenRC
- uruchomienie `tools/nxms-audit-install.sh <profile>` jako `root`
- restart `auditd`, jeśli host tego wymaga
- weryfikacja przez `auditctl -l` i `tools/nxms-audit-report.sh`

Na Alpine/OpenRC profil ma trafić do `/etc/audit/audit.rules`, bo to ten plik jest domyślnie ładowany przez `auditd`.

Repo nie wpisuje automatycznie lokalnych sekretów ani indywidualnych ścieżek poza znanym baseline tego środowiska.
