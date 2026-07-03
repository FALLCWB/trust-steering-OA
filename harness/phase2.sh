#!/usr/bin/env bash
# Phase 2 (runs after the main 8-attack dataset): deception + tarpit + shrew/LDoS.
# Completes the elastic-defense story (absorb + protect + degrade + DECEIVE) and the low-rate cell.
set -u
H=/opt/trust-lab/harness
REPS="${REPS:-10}"
echo "PHASE2 start $(date)"

# 1) + 2) deception measurement + SvL tarpit
REPS="$REPS" "$H/run_deception_tarpit.sh"

# 3) shrew / LDoS: long-flow (iperf3) throughput, nodefense vs gradual, REPS reps
mkdir -p /opt/trust-lab/data/shrew
export TARPIT_DELAY_MS=0
"$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
"$H/labctl.sh" topo-start 6 >/dev/null 2>&1; sleep 18
declare -A CFG=( [nodefense]=nodefense.json [gradual]=steering.json )
for d in nodefense gradual; do
  "$H/labctl.sh" ryu-stop >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$d]}" >/dev/null 2>&1; sleep 7
  for r in $(seq 1 "$REPS"); do
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
    python3 "$H/rq_shrew.py" --out "/opt/trust-lab/data/shrew/$d" --label "${d}_r$r" \
      --legit c1 --attacker c3 --burst 400 --secs 15 >> /opt/trust-lab/data/shrew/log 2>&1
    echo "[$(date +%H:%M:%S)] shrew $d r$r"
  done
done
echo "PHASE2 DONE $(date)"
