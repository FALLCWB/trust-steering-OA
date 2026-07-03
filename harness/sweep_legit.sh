#!/usr/bin/env bash
# Legitimate-false-positive channel. Complement of the detector sweep: the attacker
# is held at the RF operating point but STABLE (mean 0.42, sigma 0, so it sits quietly
# in quarantine and does not leak onto the primary), and the LEGITIMATE score is the
# variable, mean 0.33 with sweeping noise sigma. Rising legit noise spikes above tau_c
# and demotes legitimate clients off the primary. Run under no hysteresis vs hysteresis
# to test whether hysteresis (slow promotion, immediate demotion) helps or hurts this
# channel. Topology restarted per rep (slowloris exhausts server pools otherwise).
set -u
H=/opt/trust-lab/harness
DATA=/opt/trust-lab/data/legit_sweep
mkdir -p "$DATA"
export TARPIT_DELAY_MS=0

ATTACK=slowloris; INTENS=2000
BASE=8; ADUR=35; COOL=4; INTERVAL=5
MAL_MEAN=0.42; MAL_STD=0.00        # attacker stable in quarantine (RF mean, no swing)
LEG_MEAN=0.33                       # realistic live legit mean
LEG_STDS=(0.00 0.10 0.20 0.30)
REPS=10
declare -A CFG=( [nohyst]=steering.json [hyst]=hyst_only.json )

fresh_topo() {
  for try in 1 2 3; do
    "$H/labctl.sh" topo-stop >/dev/null 2>&1
    "$H/labctl.sh" clean     >/dev/null 2>&1
    "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 14
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 1
    code=$("$H/labctl.sh" host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m4 http://10.0.0.100/ 2>/dev/null)
    [ "$code" = "200" ] && return 0
    echo "  health probe failed (code=$code), retry $try"
  done
  return 1
}

echo "LEGIT SWEEP start $(date)"
for cfg in nohyst hyst; do
  "$H/labctl.sh" topo-stop  >/dev/null 2>&1
  "$H/labctl.sh" ryu-stop   >/dev/null 2>&1
  "$H/labctl.sh" clean      >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$cfg]}" >/dev/null 2>&1; sleep 5
  for lstd in "${LEG_STDS[@]}"; do
    cell="$DATA/$cfg/l${lstd}"
    for r in $(seq 1 $REPS); do
      out="$cell/r$r"; mkdir -p "$out"
      fresh_topo || { echo "[$(date +%H:%M:%S)] $cfg lstd=$lstd r$r SKIP unhealthy"; continue; }
      python3 "$H/score_driver.py" \
        --attacker-ips 10.0.0.13 --legit-ips 10.0.0.11,10.0.0.12 \
        --mal-mean "$MAL_MEAN" --mal-std "$MAL_STD" \
        --legit-mean "$LEG_MEAN" --legit-std "$lstd" \
        --interval "$INTERVAL" --baseline "$BASE" --attack-dur "$ADUR" \
        --seed "$r" --log "$out/scores.csv" >/dev/null 2>&1 &
      SDPID=$!
      python3 "$H/run_experiment.py" --out "$out" --defense "$cfg" \
        --attack "$ATTACK" --intensity "$INTENS" \
        --legit c1,c2 --attackers c3 --nclients 3 \
        --baseline "$BASE" --attack-dur "$ADUR" --cooldown "$COOL" \
        --score-mode none >> "$DATA/sweep.log" 2>&1
      kill "$SDPID" 2>/dev/null; wait "$SDPID" 2>/dev/null
      echo "[$(date +%H:%M:%S)] $cfg lstd=$lstd r$r"
    done
  done
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "LEGIT SWEEP DONE $(date)"
