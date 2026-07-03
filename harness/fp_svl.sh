#!/usr/bin/env bash
# False-positive service quality in the isolation tier under attack. A legitimate client
# (c1) is mis-scored into SvL while the attacker (c3) loads SvL with Slowloris and the
# tarpit is on; c2 is a correctly-scored control on the primary. Measures what a false
# positive trapped in the isolation tier actually experiences.
set -u
H=/opt/trust-lab/harness; REST=http://127.0.0.1:8080; D=/opt/trust-lab/data/fp_svl; mkdir -p $D
export TARPIT_DELAY_MS=300
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
$H/labctl.sh ryu-start $H/config/steering.json>/dev/null 2>&1; sleep 5
fresh(){ for t in 1 2 3; do
  $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
  $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14; $H/labctl.sh reset>/dev/null 2>&1; sleep 1
  c=$($H/labctl.sh host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m6 http://10.0.0.100/ 2>/dev/null)
  [ "$c" = "200" ] && return 0; done; return 1; }
echo "FP-SVL start $(date)"
for r in 1 2 3 4 5; do
  out=$D/r$r; mkdir -p $out; fresh||{ echo "r$r SKIP";continue;}
  # c1 = false positive -> SvL ; c2 = control -> SvH ; c3 = attacker -> SvL
  $H/labctl.sh score 10.0.0.11 0.9 >/dev/null; $H/labctl.sh score 10.0.0.12 0.1 >/dev/null; $H/labctl.sh score 10.0.0.13 0.9 >/dev/null
  sleep 2
  python3 $H/run_experiment.py --out $out --defense fp_svl --attack slowloris --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 60 --cooldown 4 --score-mode none >>$D/log 2>&1
  echo "[$(date +%H:%M:%S)] r$r"
done
$H/labctl.sh topo-stop>/dev/null 2>&1; echo "FP-SVL DONE $(date)"
