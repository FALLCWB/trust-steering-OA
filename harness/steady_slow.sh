#!/usr/bin/env bash
# Steady-state re-measurement of the slow (connection-holding) attacks. These reach
# equilibrium saturation within ~15s, so a sustained attack characterizes them
# correctly (the regime the Erlang-B model predicts). Fresh topology per rep.
set -u
H=/opt/trust-lab/harness; DATA=/opt/trust-lab/data/steady_slow; mkdir -p "$DATA"
export TARPIT_DELAY_MS=0
BASE=8; ADUR=75; COOL=4; REPS=5; INTENS=2000
declare -A CFG=( [nodefense]=nodefense.json [gradual]=steering.json )
fresh() {
  for t in 1 2 3; do
    "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
    "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 14
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 1
    c=$("$H/labctl.sh" host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m4 http://10.0.0.100/ 2>/dev/null)
    [ "$c" = "200" ] && return 0; done; return 1
}
echo "STEADY-SLOW start $(date)"
for atk in slowloris slowpost slowread; do
  for d in nodefense gradual; do
    "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
    "$H/labctl.sh" ryu-start "$H/config/${CFG[$d]}" >/dev/null 2>&1; sleep 5
    for r in $(seq 1 $REPS); do
      out="$DATA/$atk/$d/r$r"; mkdir -p "$out"
      fresh || { echo "[$(date +%H:%M:%S)] $atk $d r$r SKIP"; continue; }
      python3 "$H/run_experiment.py" --out "$out" --defense "$d" --attack "$atk" --intensity "$INTENS" \
        --legit c1,c2 --attackers c3 --nclients 3 --baseline "$BASE" --attack-dur "$ADUR" --cooldown "$COOL" \
        --score-mode oracle >> "$DATA/sweep.log" 2>&1
      echo "[$(date +%H:%M:%S)] $atk $d r$r"
    done
  done
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "STEADY-SLOW DONE $(date)"
