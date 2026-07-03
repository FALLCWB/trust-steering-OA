#!/usr/bin/env bash
# Binary (two-tier) vs graduated (three-tier) baseline. Reviewer's strongest objection:
# does the third, isolation tier add anything over a single quarantine secondary?
#
# Scenario (oracle scores): c1 is a benign client mis-scored as SUSPICIOUS (0.5) and sent
# to the quarantine secondary; c2 is a correctly-scored control on the primary (0.1 -> SvH);
# c3 is a CONFIRMED attacker (0.9) running Slowloris.
#   three-tier (steering.json, tau_l=0.7): c3 -> SvL (isolated+tarpit), c1 alone on SvC.
#   two-tier   (twotier.json,  tau_l=1.1): c3 and c1 share SvC (no isolation tier exists).
# Both keep c2 on the primary. The discriminating metric is c1 availability under attack:
# the third tier should protect the benign-but-flagged client; the two-tier scheme cannot,
# because it has nowhere to put the confirmed attacker except the same quarantine.
set -u
H=/opt/trust-lab/harness; D=/opt/trust-lab/data/binary; mkdir -p "$D"
export TARPIT_DELAY_MS=300
REPS=${REPS:-10}

run_arm() {  # $1 = arm label ; $2 = config
  local arm="$1" cfg="$2"
  echo "=== ARM $arm ($cfg) $(date) ==="
  $H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh ryu-stop >/dev/null 2>&1; $H/labctl.sh clean >/dev/null 2>&1
  $H/labctl.sh ryu-start "$cfg" >/dev/null 2>&1; sleep 5
  for r in $(seq 1 "$REPS"); do
    out="$D/$arm/r$r"; mkdir -p "$out"
    # fresh topology each repetition (default tier SvC before scoring)
    ok=0
    for t in 1 2 3; do
      $H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh clean >/dev/null 2>&1
      $H/labctl.sh topo-start 3 >/dev/null 2>&1; sleep 14; $H/labctl.sh reset >/dev/null 2>&1; sleep 1
      c=$($H/labctl.sh host-exec c2 curl -s -o /dev/null -w '%{http_code}' -m6 http://10.0.0.100/ 2>/dev/null)
      [ "$c" = "200" ] && { ok=1; break; }
    done
    [ "$ok" = "1" ] || { echo "  r$r SKIP (no fresh topo)"; continue; }
    # oracle scores: c1 false-positive -> secondary ; c2 control -> primary ; c3 attacker
    $H/labctl.sh score 10.0.0.11 0.5 >/dev/null
    $H/labctl.sh score 10.0.0.12 0.1 >/dev/null
    $H/labctl.sh score 10.0.0.13 0.9 >/dev/null
    sleep 2
    python3 $H/run_experiment.py --out "$out" --defense "$arm" --attack slowloris --intensity 2000 \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 60 --cooldown 4 \
      --score-mode none >>"$D/log" 2>&1
    echo "  [$(date +%H:%M:%S)] $arm r$r done"
  done
}

echo "BINARY-BASELINE start $(date)"
run_arm threetier $H/config/steering.json
run_arm twotier   $H/config/twotier.json
$H/labctl.sh topo-stop >/dev/null 2>&1; $H/labctl.sh ryu-stop >/dev/null 2>&1
echo "BINARY-BASELINE DONE $(date)"
