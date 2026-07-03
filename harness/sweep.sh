#!/usr/bin/env bash
# Run an experiment sweep on Platform A. Restarts ryu per defense (config change),
# uses /trust/reset between cells (clean state without full restart).
#   sweep.sh <sweep-name>
# Env overrides: DEFENSES, INTENS, REPS, ATTACK, BASE, ADUR, COOL, LEGIT, ATTACKERS, NCLIENTS
set -u
H=/opt/trust-lab/harness
NAME="${1:?usage: sweep.sh <name>}"
DATA=/opt/trust-lab/data/"$NAME"
mkdir -p "$DATA"
DEFENSES="${DEFENSES:-nodefense droponly binary gradual}"
INTENS="${INTENS:-500 1000 2000 5000 10000}"
REPS="${REPS:-5}"
ATTACK="${ATTACK:-synflood}"
BASE="${BASE:-8}"; ADUR="${ADUR:-25}"; COOL="${COOL:-4}"
LEGIT="${LEGIT:-c1,c3}"; ATTACKERS="${ATTACKERS:-c2}"; NCLIENTS="${NCLIENTS:-3}"
declare -A CFG=( [nodefense]=nodefense.json [droponly]=droponly.json \
                 [binary]=binary.json [gradual]=steering.json )

echo "SWEEP $NAME start $(date)  defenses=[$DEFENSES] intens=[$INTENS] reps=$REPS attack=$ATTACK" | tee -a "$DATA/sweep.log"
for d in $DEFENSES; do
  cfg="${CFG[$d]:-steering.json}"
  "$H/labctl.sh" topo-stop >/dev/null 2>&1
  "$H/labctl.sh" ryu-stop  >/dev/null 2>&1
  "$H/labctl.sh" clean     >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/$cfg" >/dev/null 2>&1; sleep 5
  "$H/labctl.sh" topo-start "$NCLIENTS" >/dev/null 2>&1; sleep 16
  for I in $INTENS; do
    for r in $(seq 1 "$REPS"); do
      "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
      python3 "$H/run_experiment.py" --out "$DATA/$d/i$I/r$r" \
        --defense "$d" --attack "$ATTACK" --intensity "$I" \
        --legit "$LEGIT" --attackers "$ATTACKERS" --nclients "$NCLIENTS" \
        --baseline "$BASE" --attack-dur "$ADUR" --cooldown "$COOL" \
        --score-mode oracle >> "$DATA/sweep.log" 2>&1
      echo "[$(date +%H:%M:%S)] done $d i$I r$r" | tee -a "$DATA/sweep.log"
    done
  done
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "SWEEP $NAME DONE $(date)" | tee -a "$DATA/sweep.log"
