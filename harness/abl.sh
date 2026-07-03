#!/usr/bin/env bash
set -u
H=/opt/trust-lab/harness; DATA=/opt/trust-lab/data/abl_deftier; mkdir -p "$DATA"
export TARPIT_DELAY_MS=0
declare -A CFG=( [defprimary]=abl_defprimary.json [defquarantine]=steering.json )
echo "ABL start $(date)"
for d in defprimary defquarantine; do
  "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$d]}" >/dev/null 2>&1; sleep 5
  "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 16
  for r in $(seq 1 5); do
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
    python3 "$H/run_experiment.py" --out "$DATA/$d/r$r" --defense "$d" --attack slowloris --intensity 2000 \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 25 --cooldown 4 --score-mode oracle >> "$DATA/abl.log" 2>&1
    echo "[$(date +%H:%M:%S)] $d r$r" 
  done
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "ABL DONE $(date)"
