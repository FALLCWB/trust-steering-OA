#!/usr/bin/env bash
# Collateral cost of /24 subnet aggregation. A benign, never-scored client (c1) shares the /24 with a
# flagged attacker (c3, Slowloris). With subnet aggregation ON (mechanisms.json) c1 inherits the flagged
# /24 reputation and is isolated to SvL alongside the attacker; with it OFF (steering.json) c1 falls to
# the default quarantine SvC instead. c2 is a correctly-scored benign control on the primary. Measures the
# availability the co-resident benign client actually gets, quantifying the collateral the paper names.
set -u
H=/opt/trust-lab/harness; D=/opt/trust-lab/data/subnet_collateral; mkdir -p "$D"
export TARPIT_DELAY_MS=300
REPS=${REPS:-10}

run_arm() {  # $1 label ; $2 config
  local arm="$1" cfg="$2"
  echo "=== ARM $arm ($cfg) $(date) ==="
  $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
  $H/labctl.sh ryu-start "$cfg">/dev/null 2>&1; sleep 5
  for r in $(seq 1 "$REPS"); do
    out="$D/$arm/r$r"; mkdir -p "$out"
    ok=0
    for t in 1 2 3; do
      $H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
      $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14; $H/labctl.sh reset>/dev/null 2>&1; sleep 1
      c=$($H/labctl.sh host-exec c2 curl -s -o /dev/null -w '%{http_code}' -m6 http://10.0.0.100/ 2>/dev/null)
      [ "$c" = "200" ] && { ok=1; break; }
    done
    [ "$ok" = "1" ] || { echo "  r$r SKIP"; continue; }
    # c1 benign but LEFT UNSCORED (so it inherits the /24 when aggregation is on); c2 scored benign control;
    # c3 flagged attacker -> raises the /24 reputation and runs Slowloris.
    $H/labctl.sh score 10.0.0.12 0.1 >/dev/null
    $H/labctl.sh score 10.0.0.13 0.9 >/dev/null
    sleep 2
    python3 $H/run_experiment.py --out "$out" --defense "$arm" --attack slowloris --intensity 2000 \
      --legit c1,c2 --attackers c3 --nclients 3 --baseline 8 --attack-dur 60 --cooldown 4 \
      --score-mode none >>"$D/log" 2>&1
    echo "  [$(date +%H:%M:%S)] $arm r$r done"
  done
}

echo "SUBNET-COLLATERAL start $(date)"
run_arm subnet_on  $H/config/mechanisms.json
run_arm subnet_off $H/config/steering.json
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1
echo "SUBNET-COLLATERAL DONE $(date)"
