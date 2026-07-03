#!/usr/bin/env bash
set -u
H=/opt/trust-lab/harness; export TARPIT_DELAY_MS=0
fresh(){ for t in 1 2 3; do
  $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
  $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14; $H/labctl.sh reset>/dev/null 2>&1; sleep 1
  c=$($H/labctl.sh host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m4 http://10.0.0.100/ 2>/dev/null)
  [ "$c" = "200" ] && return 0; done; return 1; }
echo "RERUN start $(date)"
# A) drop-only with quarantine default (fair drop baseline)
D=/opt/trust-lab/data/droponly_q; mkdir -p $D
$H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh ryu-start $H/config/droponly_q.json>/dev/null 2>&1; sleep 5
for atk in slowloris slowpost slowread; do for r in 1 2 3 4 5; do
  out="$D/$atk/r$r"; mkdir -p $out; fresh||{ echo "A $atk r$r SKIP";continue;}
  python3 $H/run_experiment.py --out $out --defense droponly_q --attack $atk --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 75 --cooldown 4 --score-mode oracle >>$D/log 2>&1
  echo "[$(date +%H:%M:%S)] A $atk r$r"
done; done
# B) model c_H validation (vary SvH workers)
M=/opt/trust-lab/data/model_cH2; mkdir -p $M
$H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh ryu-start $H/config/nodefense.json>/dev/null 2>&1; sleep 5
for W in 16 32 64; do export SVH_WORKERS=$W; for r in 1 2 3; do
  out="$M/w$W/r$r"; mkdir -p $out; fresh||{ echo "B w$W r$r SKIP";continue;}
  w=$(pgrep -af "slow_server.py.*10.0.0.201"|grep -oE "workers [0-9]+"); echo "  [w$W] server=$w" >>$M/log
  python3 $H/run_experiment.py --out $out --defense nodefense --attack slowloris --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 75 --cooldown 4 --score-mode oracle >>$M/log 2>&1
  echo "[$(date +%H:%M:%S)] B SVH_WORKERS=$W r$r ($w)"
done; done
unset SVH_WORKERS; $H/labctl.sh topo-stop>/dev/null 2>&1
echo "RERUN DONE $(date)"
