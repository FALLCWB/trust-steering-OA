#!/usr/bin/env bash
# Re-run of 2026-11-10/11 (JISA plan, OPEN-2 and OPEN-3 of jisa/CONSISTENCY-AUDIT.md).
# Every repetition starts on a fresh topology (servers, worker pools and held connections rebuilt), with a
# health check that a legitimate client is served before the run starts, as in steady_slow.sh. The live
# series also restart the sensor per repetition and save its log next to the run.
# Usage on the lab VM:  MODE=sanity|full bash rerun_restart.sh
# Output: /opt/trust-lab/data/rr2611/<MODE>/...   (original data are not touched)
set -u
H=/opt/trust-lab/harness; LAB=/opt/trust-lab
MODE=${MODE:-sanity}
ROOT=$LAB/data/rr2611/$MODE; mkdir -p "$ROOT"
MODEL=$LAB/sensor-retrain/RF_model_indomain.pck
export TARPIT_DELAY_MS=0
LOG=$ROOT/progress.log
say() { echo "[$(date +%F' '%H:%M:%S)] $*" | tee -a "$LOG"; }

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

# one live repetition: fresh topology, fresh sensor, run, save the sensor log of this repetition
live_rep() { # $1 out  $2 label  $3 attack  $4 intensity
  fresh || { say "SKIP (health) $1"; return; }
  sensor_start; sleep 8
  systemctl is-active --quiet trust-sensor || { say "SKIP (sensor not active) $1"; sensor_stop; return; }
  t0=$(date +%s)
  python3 "$H/run_experiment.py" --out "$1" --defense "$2" --attack "$3" --intensity "$4" \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline 10 --attack-dur 30 --cooldown 4 \
    --score-mode rf >> "$ROOT/run.log" 2>&1
  sleep 12                                    # let the sensor post the window that closes the attack
  journalctl -u trust-sensor --since "@$t0" --no-pager -o short-unix > "$1/sensor.log" 2>/dev/null
  sensor_stop
  cp "$CFG_NOW" "$1/controller-config.json"
  nw=$(grep -c 'win#' "$1/sensor.log" 2>/dev/null); [ "${nw:-0}" -gt 0 ] || say "WARN no sensor windows $1"
  say "done $1 (sensor windows ${nw:-0})"
}
oracle_rep() { # $1 out  $2 label  $3 attack  $4 baseline  $5 attack-dur
  fresh || { say "SKIP (health) $1"; return; }
  python3 "$H/run_experiment.py" --out "$1" --defense "$2" --attack "$3" --intensity 2000 \
    --legit c1,c2 --attackers c3 --nclients 3 --baseline "$4" --attack-dur "$5" --cooldown 4 \
    --score-mode oracle >> "$ROOT/run.log" 2>&1
  cp "$CFG_NOW" "$1/controller-config.json"
  say "done $1"
}

if [ "$MODE" = "sanity" ]; then
  LIVE_R="1"; ABL_R="1"; DQ_R="6"; MC_R="4"
else
  LIVE_R="$(seq 1 10)"; ABL_R="$(seq 1 10)"; DQ_R="$(seq 6 10)"; MC_R="$(seq 4 10)"
fi
trap 'sensor_stop; "$H/labctl.sh" topo-stop >/dev/null 2>&1' EXIT
sensor_stop
say "RERUN $MODE start"

# A) live in-domain detector, Slowloris and the four other classes (steering.json)
ryu steering.json
for atk in slowloris slowpost slowread synflood httpflood; do
  case "$atk" in synflood) INT=100000 ;; httpflood) INT=200 ;; *) INT=2000 ;; esac
  for r in $LIVE_R; do mkdir -p "$ROOT/e2e/$atk/r$r"; live_rep "$ROOT/e2e/$atk/r$r" "e2e_$atk" "$atk" "$INT"; done
done
# B) live detector with asymmetric hysteresis, Slowloris (hyst_only.json)
ryu hyst_only.json
for r in $LIVE_R; do mkdir -p "$ROOT/e2e_hyst/r$r"; live_rep "$ROOT/e2e_hyst/r$r" e2e_hyst slowloris 2000; done
# C) default-tier ablation (oracle; baseline 8 s, attack 25 s as in n10.sh)
ryu abl_defprimary.json
for r in $ABL_R; do mkdir -p "$ROOT/abl_deftier/defprimary/r$r"; oracle_rep "$ROOT/abl_deftier/defprimary/r$r" defprimary slowloris 8 25; done
ryu steering.json
for r in $ABL_R; do mkdir -p "$ROOT/abl_deftier/defquarantine/r$r"; oracle_rep "$ROOT/abl_deftier/defquarantine/r$r" defquarantine slowloris 8 25; done
# D) drop-only with quarantine default, top-up r6..r10 (rerun.sh settings: baseline 8 s, attack 75 s)
ryu droponly_q.json
for atk in slowloris slowpost slowread; do
  for r in $DQ_R; do mkdir -p "$ROOT/droponly_q/$atk/r$r"; oracle_rep "$ROOT/droponly_q/$atk/r$r" droponly_q "$atk" 8 75; done
done
# E) provisioning test, top-up r4..r10 (rerun.sh settings: nodefense, Slowloris 2000, attack 75 s)
ryu nodefense.json
for W in 16 32 64; do
  export SVH_WORKERS=$W
  for r in $MC_R; do mkdir -p "$ROOT/model_cH2/w$W/r$r"; oracle_rep "$ROOT/model_cH2/w$W/r$r" nodefense slowloris 8 75; done
done
unset SVH_WORKERS
# F) no defense on the live-run schedule (baseline 10 s, attack 30 s), the like-for-like comparison for A and B
ryu nodefense.json
for r in $LIVE_R; do mkdir -p "$ROOT/nodef_live/r$r"; oracle_rep "$ROOT/nodef_live/r$r" nodefense slowloris 10 30; done
"$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" ryu-stop >/dev/null 2>&1
say "RERUN $MODE DONE"
