#!/usr/bin/env bash
# Detector-quality sweep. The steering policy is held fixed (gradual, default
# quarantine); only the score signal varies: attacker mean separation x stability
# (std), under two controllers -- no hysteresis (steering.json) and hysteresis-only
# (hyst_only.json). Legit are pinned clean (0.10). Slowloris i=2000 (the class that
# collapses under a live detector). The sidecar score_driver.py posts the scores;
# run_experiment.py runs in --score-mode none and drives the real attack traffic.
set -u
H=/opt/trust-lab/harness
DATA=/opt/trust-lab/data/detector_sweep
mkdir -p "$DATA"
export TARPIT_DELAY_MS=0

ATTACK=slowloris; INTENS=2000
BASE=8; ADUR=35; COOL=4; INTERVAL=5
MEANS=(0.35 0.45 0.55 0.70 0.90)
STDS=(0.00 0.30)
REPS=10

declare -A CFG=( [nohyst]=steering.json [hyst]=hyst_only.json )

# Slowloris holds server-side connections (-l 600), so worker pools do not recover
# between reps under a single long-lived topology. Restart the topology (fresh
# servers) EVERY rep, with a per-cell health probe, so availability reflects the
# score condition rather than cumulative server exhaustion.
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

echo "DETECTOR SWEEP start $(date)"
for cfg in nohyst hyst; do
  "$H/labctl.sh" topo-stop  >/dev/null 2>&1
  "$H/labctl.sh" ryu-stop   >/dev/null 2>&1
  "$H/labctl.sh" clean      >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$cfg]}" >/dev/null 2>&1; sleep 5
  for mean in "${MEANS[@]}"; do
    for std in "${STDS[@]}"; do
      cell="$DATA/$cfg/m${mean}_s${std}"
      for r in $(seq 1 $REPS); do
        out="$cell/r$r"; mkdir -p "$out"
        fresh_topo || { echo "[$(date +%H:%M:%S)] $cfg mean=$mean std=$std r$r SKIP unhealthy"; continue; }
        # sidecar posts the controlled score signal (seed varies per rep)
        python3 "$H/score_driver.py" \
          --attacker-ips 10.0.0.13 --legit-ips 10.0.0.11,10.0.0.12 \
          --mal-mean "$mean" --mal-std "$std" --legit-mean 0.10 --legit-std 0.00 \
          --interval "$INTERVAL" --baseline "$BASE" --attack-dur "$ADUR" \
          --seed "$r" --log "$out/scores.csv" >/dev/null 2>&1 &
        SDPID=$!
        python3 "$H/run_experiment.py" --out "$out" --defense "$cfg" \
          --attack "$ATTACK" --intensity "$INTENS" \
          --legit c1,c2 --attackers c3 --nclients 3 \
          --baseline "$BASE" --attack-dur "$ADUR" --cooldown "$COOL" \
          --score-mode none >> "$DATA/sweep.log" 2>&1
        kill "$SDPID" 2>/dev/null; wait "$SDPID" 2>/dev/null
        echo "[$(date +%H:%M:%S)] $cfg mean=$mean std=$std r$r"
      done
    done
  done
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "DETECTOR SWEEP DONE $(date)"
