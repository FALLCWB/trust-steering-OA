#!/usr/bin/env bash
# Resource-matched two-tier baseline (reviewer point): the plain two-tier arm leaves the isolation-tier
# pool idle, so a fair binary should fold those workers into the single quarantine. Here the two-tier
# secondary (SvC) is provisioned with 16 workers (the three-tier SvC=12 plus the SvL=4), holding total
# server resources fixed. Same oracle scenario as sec:binary: c1 mis-scored FP (0.5), c2 control (0.1),
# c3 attacker (0.9) running Slowloris. If the FP still collapses, the third tier's value is the separation,
# not the extra workers.
set -u
H=/opt/trust-lab/harness; D=/opt/trust-lab/data/binary_rmatched; mkdir -p "$D"
export TARPIT_DELAY_MS=300
export SVC_WORKERS=16          # 12 (SvC) + 4 (idle SvL) folded into the single secondary
REPS=${REPS:-10}

echo "RMATCHED start $(date) (two-tier, tau_l=1.1, SvC=16 workers)"
$H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh ryu-stop >/dev/null 2>&1; $H/labctl.sh clean >/dev/null 2>&1
$H/labctl.sh ryu-start "$H/config/twotier.json" >/dev/null 2>&1; sleep 5
for r in $(seq 1 "$REPS"); do
  out="$D/r$r"; mkdir -p "$out"
  ok=0
  for t in 1 2 3; do
    $H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh clean >/dev/null 2>&1
    SVC_WORKERS=16 $H/labctl.sh topo-start 3 >/dev/null 2>&1; sleep 14; $H/labctl.sh reset >/dev/null 2>&1; sleep 1
    c=$($H/labctl.sh host-exec c2 curl -s -o /dev/null -w '%{http_code}' -m6 http://10.0.0.100/ 2>/dev/null)
    [ "$c" = "200" ] && { ok=1; break; }
  done
  [ "$ok" = "1" ] || { echo "  r$r SKIP"; continue; }
  $H/labctl.sh score 10.0.0.11 0.5 >/dev/null
  $H/labctl.sh score 10.0.0.12 0.1 >/dev/null
  $H/labctl.sh score 10.0.0.13 0.9 >/dev/null
  sleep 2
  python3 $H/run_experiment.py --out "$out" --defense twotier_rmatched --attack slowloris --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 60 --cooldown 4 \
    --score-mode none >>"$D/log" 2>&1
  echo "  [$(date +%H:%M:%S)] r$r done"
done
$H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh ryu-stop >/dev/null 2>&1
echo "RMATCHED DONE $(date)"
# quick verify SvC actually got 16 workers on a fresh topo
$H/labctl.sh clean >/dev/null 2>&1
