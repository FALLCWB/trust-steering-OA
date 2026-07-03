#!/usr/bin/env bash
# Validate the model's c_H axis: vary the primary-pool size and measure no-defense
# steady-state availability under sustained Slowloris. The loss model predicts
# availability ~ c_H/a_A (a_A ~ 384), i.e. ~4%, ~8%, ~17% for c_H = 16, 32, 64.
set -u
H=/opt/trust-lab/harness; OUT=/opt/trust-lab/data/model_cH; mkdir -p "$OUT"
$H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh ryu-start $H/config/nodefense.json>/dev/null 2>&1; sleep 5
fresh() { for t in 1 2 3; do
  $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
  $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14; $H/labctl.sh reset>/dev/null 2>&1; sleep 1
  c=$($H/labctl.sh host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m4 http://10.0.0.100/ 2>/dev/null)
  [ "$c" = "200" ] && return 0; done; return 1; }
echo "MODEL-CH start $(date)"
for W in 16 32 64; do
  export SVH_WORKERS=$W
  for r in 1 2 3; do
    out="$OUT/w$W/r$r"; mkdir -p "$out"
    fresh || { echo "[$(date +%H:%M:%S)] w$W r$r SKIP"; continue; }
    python3 $H/run_experiment.py --out "$out" --defense nodefense --attack slowloris --intensity 2000 \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 60 --cooldown 4 \
      --score-mode oracle >> "$OUT/run.log" 2>&1
    echo "[$(date +%H:%M:%S)] SVH_WORKERS=$W r$r"
  done
done
$H/labctl.sh topo-stop>/dev/null 2>&1; unset SVH_WORKERS
echo "MODEL-CH DONE $(date)"
