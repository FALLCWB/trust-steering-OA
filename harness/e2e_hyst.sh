#!/usr/bin/env bash
# Live in-domain detector on Slowloris WITH asymmetric hysteresis enabled (hyst_only.json), to test
# whether hysteresis recovers the live-detector collapse the way it recovers injected per-window noise.
# Same setup as the live-detector run, only the controller config differs. n=10.
set -u
H=/opt/trust-lab/harness; LAB=/opt/trust-lab; D=$LAB/data/e2e_hyst; mkdir -p "$D"
MODEL=$LAB/sensor-retrain/RF_model_indomain.pck
export TARPIT_DELAY_MS=0
REPS=${REPS:-10}

sensor_start() {
  systemctl stop trust-sensor >/dev/null 2>&1; systemctl reset-failed trust-sensor >/dev/null 2>&1
  systemd-run --unit=trust-sensor --working-directory="$H" \
    "$LAB/sensor-venv/bin/python" sensor_service.py \
    --interfaces s1-eth1,s1-eth2,s1-eth3 --window 5 --model "$MODEL" >/dev/null 2>&1
}

$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
$H/labctl.sh ryu-start $H/config/hyst_only.json>/dev/null 2>&1; sleep 5
$H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14
sensor_start; sleep 8
echo "E2E-HYST start $(date)"
for r in $(seq 1 "$REPS"); do
  out="$D/r$r"; mkdir -p "$out"
  $H/labctl.sh reset>/dev/null 2>&1; sleep 2
  python3 $H/run_experiment.py --out "$out" --defense e2e_hyst --attack slowloris --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 10 --attack-dur 30 --cooldown 4 \
    --score-mode rf >>"$D/log" 2>&1
  sleep 6
  echo "  [$(date +%H:%M:%S)] hyst rf r$r done"
done
systemctl stop trust-sensor>/dev/null 2>&1
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1
echo "E2E-HYST DONE $(date)"
