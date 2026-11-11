#!/usr/bin/env bash
# Runs for review risks R1 and R2 (review/RISK-LEDGER.md), approved by Filipe on 2026-11-11.
# Same procedure as rerun_restart.sh: fresh topology per repetition with a served-client health check,
# live RF sensor restarted per repetition and its log saved next to the run, controller config copied.
#   R1  reconnecting attacker: Slowloris with -c 6000 at the same 200 connections/s, so the attacker keeps
#       opening connections for the whole 30 s attack instead of finishing its ramp in 10 s;
#       with hysteresis (hyst_only.json) and without (steering.json).
#   R2  baselines under the live detector: drop-only with quarantine (droponly_q.json) with and without
#       hysteresis (droponly_q_hyst.json = droponly_q.json + promote_stab_s 5.0), three slow attacks;
#       steering with hysteresis on Slow POST and Slow Read, so every attack has all four cells.
# Usage on the lab VM:  MODE=sanity|full bash rerun_r1r2.sh
# Output: /opt/trust-lab/data/rr2611/r1r2-<MODE>/...   (earlier data are not touched)
set -u
H=/opt/trust-lab/harness; LAB=/opt/trust-lab
MODE=${MODE:-sanity}
ROOT=$LAB/data/rr2611/r1r2-$MODE; mkdir -p "$ROOT"
MODEL=$LAB/sensor-retrain/RF_model_indomain.pck
export TARPIT_DELAY_MS=0
LOG=$ROOT/progress.log
say() { echo "[$(date +%F' '%H:%M:%S)] $*" | tee -a "$LOG"; }

# drop-only with quarantine plus the hysteresis of hyst_only.json (written once, never overwritten)
if [ ! -f "$H/config/droponly_q_hyst.json" ]; then
  python3 - "$H/config/droponly_q.json" "$H/config/droponly_q_hyst.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c["promote_stab_s"] = 5.0
json.dump(c, open(sys.argv[2], "w"), indent=2)
EOF
fi

CFG_NOW=""
ryu() {   # $1 = config file name
  [ -f "$H/config/$1" ] || { say "FATAL missing config $1"; exit 2; }
  "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/$1" >/dev/null 2>&1; sleep 5
  systemctl is-active --quiet trust-ryu || { say "FATAL controller not active with $1"; exit 2; }
  CFG_NOW="$H/config/$1"; say "controller up with $1 md5 $(md5sum "$CFG_NOW" | cut -c1-12)"
}
fresh() { # fresh topology with 3 clients, controller scores reset, legitimate client served
  for t in 1 2 3; do
    "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
    "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 14
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 1
    c=$("$H/labctl.sh" host-exec c1 curl -s -o /dev/null -w '%{http_code}' -m4 http://10.0.0.100/ 2>/dev/null)
    if [ "$c" = "200" ]; then "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2; return 0; fi
  done
  return 1
}
sensor_start() {
  systemctl stop trust-sensor >/dev/null 2>&1; systemctl reset-failed trust-sensor >/dev/null 2>&1
  systemd-run --unit=trust-sensor --working-directory="$H" \
    "$LAB/sensor-venv/bin/python" sensor_service.py \
    --interfaces s1-eth1,s1-eth2,s1-eth3 --window 5 --model "$MODEL" >/dev/null 2>&1
}
sensor_stop() { systemctl stop trust-sensor >/dev/null 2>&1; systemctl reset-failed trust-sensor >/dev/null 2>&1; }

live_rep() { # $1 out  $2 label  $3 attack  $4 intensity (slowhttptest -c)
  fresh || { say "SKIP (health) $1"; return; }
  sensor_start; sleep 8
  systemctl is-active --quiet trust-sensor || { say "SKIP (sensor not active) $1"; sensor_stop; return; }
  t0=$(date +%s)
  python3 "$H/run_experiment.py" --out "$1" --defense "$2" --attack "$3" --intensity "$4" \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 10 --attack-dur 30 --cooldown 4 \
    --score-mode rf >> "$ROOT/run.log" 2>&1
  sleep 12
  journalctl -u trust-sensor --since "@$t0" --no-pager -o short-unix > "$1/sensor.log" 2>/dev/null
  sensor_stop
  cp "$CFG_NOW" "$1/controller-config.json"
  nw=$(grep -c 'win#' "$1/sensor.log" 2>/dev/null); [ "${nw:-0}" -gt 0 ] || say "WARN no sensor windows $1"
  say "done $1 (sensor windows ${nw:-0})"
}
series() { # $1 dir under ROOT  $2 label  $3 attack  $4 intensity
  for r in $REPS; do mkdir -p "$ROOT/$1/r$r"; live_rep "$ROOT/$1/r$r" "$2" "$3" "$4"; done
}

if [ "$MODE" = "sanity" ]; then REPS="1"; else REPS="$(seq 1 10)"; fi
trap 'sensor_stop; "$H/labctl.sh" topo-stop >/dev/null 2>&1' EXIT
sensor_stop
say "R1R2 $MODE start"

ryu hyst_only.json
series reconn_hyst reconn_hyst slowloris 6000
series hyst/slowpost e2e_hyst slowpost 2000
series hyst/slowread e2e_hyst slowread 2000
ryu steering.json
series reconn_nohyst reconn_nohyst slowloris 6000
ryu droponly_q.json
for atk in slowloris slowpost slowread; do series "dq_live/$atk" dq_live "$atk" 2000; done
ryu droponly_q_hyst.json
for atk in slowloris slowpost slowread; do series "dq_live_hyst/$atk" dq_live_hyst "$atk" 2000; done

"$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-stop >/dev/null 2>&1
say "R1R2 $MODE DONE"
