#!/bin/bash
# Skrot: uruchamia caly pakiet all-in-one (C1-C4) i zapisuje log.
dir=$(dirname "$(readlink -f "$0")")
log=/tmp/opencode/allinone-run.log
bash "$dir/nxms-allinone-run.sh" 2>&1 | tee "$log"
echo "(log: $log)"
