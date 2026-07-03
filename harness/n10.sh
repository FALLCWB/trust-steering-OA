#!/usr/bin/env bash
set -u
H=/opt/trust-lab/harness; export TARPIT_DELAY_MS=0
echo "N10 TOPUP start $(date)"
# clear old n=5 data
rm -rf /opt/trust-lab/data/rq6 /opt/trust-lab/data/abl_deftier /opt/trust-lab/data/overhead
mkdir -p /opt/trust-lab/data/rq6 /opt/trust-lab/data/overhead

# ===== Phase A: 6-client topo — hysteresis (gradual+mechanisms) + overhead =====
"$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
"$H/labctl.sh" topo-start 6 >/dev/null 2>&1; sleep 16
# hysteresis gradual (steering.json)
"$H/labctl.sh" ryu-start "$H/config/steering.json" >/dev/null 2>&1; sleep 7
python3 "$H/rq6_hysteresis.py" --out /opt/trust-lab/data/rq6 --label gradual --probe c3 --reps 10 >> /opt/trust-lab/data/rq6/log 2>&1
echo "[$(date +%H:%M:%S)] hyst gradual done"
# overhead (steering.json) 10 reps
for r in $(seq 1 10); do "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
  python3 "$H/rq5_overhead.py" --out /opt/trust-lab/data/overhead --attacker c3 --intensity 100000 --baseline 8 --attack 12 --rep $r >/dev/null 2>&1
done
echo "[$(date +%H:%M:%S)] overhead x10 done"
# hysteresis mechanisms (mechanisms.json, promote_stab_s=5)
"$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-start "$H/config/mechanisms.json" >/dev/null 2>&1; sleep 7
python3 "$H/rq6_hysteresis.py" --out /opt/trust-lab/data/rq6 --label mechanisms --probe c3 --reps 10 >> /opt/trust-lab/data/rq6/log 2>&1
echo "[$(date +%H:%M:%S)] hyst mechanisms done"

# ===== Phase B: 3-client topo — default-tier ablation (10 reps each arm) =====
DATA=/opt/trust-lab/data/abl_deftier; mkdir -p "$DATA"
declare -A CFG=( [defprimary]=abl_defprimary.json [defquarantine]=steering.json )
for d in defprimary defquarantine; do
  "$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$d]}" >/dev/null 2>&1; sleep 5
  "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 16
  for r in $(seq 1 10); do "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
    python3 "$H/run_experiment.py" --out "$DATA/$d/r$r" --defense "$d" --attack slowloris --intensity 2000 \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 25 --cooldown 4 --score-mode oracle >> "$DATA/abl.log" 2>&1
  done
  echo "[$(date +%H:%M:%S)] ablation $d x10 done"
done
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "N10 TOPUP DONE $(date)"
