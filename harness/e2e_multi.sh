#!/usr/bin/env bash
# Live end-to-end detector beyond Slowloris. The same in-domain Random Forest sensor that scored
# the Slowloris run (Section on the live detector) is driven against the other connection-holding
# classes (Slow POST, Slow Read) and two high-rate classes (SYN flood, HTTP GET flood), with the
# policy steering on the live score (no oracle). Measures whether the live detector preserves
# legitimate service per class. Topology and sensor are restarted per class; scores reset per rep.
set -u
H=/opt/trust-lab/harness; LAB=/opt/trust-lab; REST=http://127.0.0.1:8080
D=$LAB/data/e2e_multi; mkdir -p "$D"
MODEL=$LAB/sensor-retrain/RF_model_indomain.pck     # in-domain detector (RandomForest-Testbed)
export TARPIT_DELAY_MS=0
REPS=${REPS:-10}

sensor_start() {
  systemctl stop trust-sensor >/dev/null 2>&1; systemctl reset-failed trust-sensor >/dev/null 2>&1
  systemd-run --unit=trust-sensor --working-directory="$H" \
    "$LAB/sensor-venv/bin/python" sensor_service.py \
    --interfaces s1-eth1,s1-eth2,s1-eth3 --window 5 --model "$MODEL" >/dev/null 2>&1
}

$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
$H/labctl.sh ryu-start $H/config/steering.json>/dev/null 2>&1; sleep 5

echo "E2E-MULTI start $(date)"
for atk in slowpost slowread synflood httpflood; do
  case "$atk" in
    synflood)  INT=100000 ;;
    httpflood) INT=200 ;;
    *)         INT=2000 ;;
  esac
  $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
  $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14
  sensor_start; sleep 8           # let the sensor process one window before scoring
  for r in $(seq 1 "$REPS"); do
    out="$D/$atk/r$r"; mkdir -p "$out"
    $H/labctl.sh reset>/dev/null 2>&1; sleep 2
    python3 $H/run_experiment.py --out "$out" --defense e2e_$atk --attack "$atk" --intensity "$INT" \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 10 --attack-dur 30 --cooldown 4 \
      --score-mode rf >>"$D/log" 2>&1
    sleep 6                         # recovery: let held connections close before next rep
    echo "  [$(date +%H:%M:%S)] $atk rf r$r done"
  done
done
systemctl stop trust-sensor>/dev/null 2>&1
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1
echo "E2E-MULTI DONE $(date)"
