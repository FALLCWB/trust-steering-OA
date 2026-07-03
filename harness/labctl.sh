#!/usr/bin/env bash
# Lab control for Platform A on the experiment VM. Runs services as transient
# systemd units so they survive SSH disconnects, and uses TARGETED cleanup that
# never kills ryu-manager (mininet's own `mn -c` does `killall ryu-manager`).
set -u
LAB=/opt/trust-lab
HARNESS=$LAB/harness
RYU=$LAB/ryu-venv/bin/ryu-manager
CFG=$HARNESS/config/steering.json
APP=trust_steering_app.py
REST=http://127.0.0.1:8080

clean_topo() {   # remove mininet/OVS state WITHOUT touching ryu
  pkill -9 -f topo.py 2>/dev/null
  pkill -9 -f 'mininet:' 2>/dev/null
  for b in $(ovs-vsctl list-br 2>/dev/null); do ovs-vsctl --if-exists del-br "$b"; done
  systemctl reset-failed trust-topo 2>/dev/null
  ip -o link show 2>/dev/null | awk -F': ' '/(s1-eth|-eth[0-9])/{print $2}' | cut -d@ -f1 \
    | while read -r i; do ip link del "$i" 2>/dev/null; done
  echo "clean_topo done; bridges=$(ovs-vsctl list-br 2>/dev/null | wc -l)"
}

case "${1:-}" in
  clean)        clean_topo ;;
  ryu-start)   # $2 = optional config path (default steering.json)
    systemctl reset-failed trust-ryu 2>/dev/null
    systemd-run --unit=trust-ryu --working-directory="$HARNESS" \
      --setenv=TRUST_CONFIG="${2:-$CFG}" \
      "$RYU" --wsapi-host 0.0.0.0 --wsapi-port 8080 --ofp-tcp-listen-port 6653 "$APP"
    ;;
  reset)        curl -s -m4 -X POST $REST/trust/reset; echo ;;
  ryu-stop)     systemctl stop trust-ryu 2>/dev/null; echo stopped ;;
  topo-start)   # $2 = n clients ; forwards TARPIT_DELAY_MS to the topo (SvL tarpit)
    systemctl reset-failed trust-topo 2>/dev/null
    systemd-run --unit=trust-topo --working-directory="$HARNESS" \
      --setenv=TARPIT_DELAY_MS="${TARPIT_DELAY_MS:-0}" --setenv=SVH_WORKERS="${SVH_WORKERS:-32}" --setenv=SVC_WORKERS="${SVC_WORKERS:-12}" \
      /usr/bin/python3 topo.py --clients "${2:-3}" --controller-ip 127.0.0.1 \
      --controller-port 6653 --no-cli
    ;;
  topo-stop)    systemctl stop trust-topo 2>/dev/null; clean_topo ;;
  sensor-start) # $2=interfaces(csv) $3=window
    systemctl reset-failed trust-sensor 2>/dev/null
    systemd-run --unit=trust-sensor --working-directory="$HARNESS" \
      "$LAB/sensor-venv/bin/python" sensor_service.py \
      --interfaces "${2:-s1-eth1,s1-eth2,s1-eth3}" --window "${3:-5}"
    ;;
  sensor-stop)  systemctl stop trust-sensor 2>/dev/null; echo stopped ;;
  sensor-log)   journalctl -u trust-sensor --no-pager -n "${2:-15}" ;;
  status)
    echo "ryu:  $(systemctl is-active trust-ryu 2>/dev/null)"
    echo "topo: $(systemctl is-active trust-topo 2>/dev/null)"
    echo "bridges: $(ovs-vsctl list-br 2>/dev/null | tr '\n' ' ')"
    echo "rest: $(curl -s -m4 $REST/trust/stats 2>/dev/null || echo DOWN)"
    ;;
  score)        # $2=ip $3=score
    curl -s -m4 -X POST $REST/trust/score -H 'Content-Type: application/json' \
      -d "{\"ip\":\"$2\",\"score\":$3}"; echo
    ;;
  host-exec)    # $2=host (c1..) ; rest = command, run inside that host netns
    h="$2"; shift 2
    pid=$(pgrep -f "mininet:${h}\$" | head -1)
    [ -z "$pid" ] && { echo "host $h not found"; exit 1; }
    nsenter -t "$pid" -n -- "$@"
    ;;
  steer-test)   # validate score -> tier mapping end to end (client c1 = 10.0.0.11)
    cip=10.0.0.11; vip=10.0.0.100
    p1=$(pgrep -f 'mininet:c1$' | head -1)
    hit() { nsenter -t "$p1" -n -- curl -s -m5 "http://$vip/" 2>/dev/null | tr -d '\n'; }
    post() { curl -s -m4 -X POST $REST/trust/score -H 'Content-Type: application/json' -d "{\"ip\":\"$cip\",\"score\":$1}" >/dev/null; }
    echo "default (no score)      -> $(hit)"
    post 0.10; sleep 3; echo "score 0.10 (trusted)    -> $(hit)"
    post 0.90; sleep 3; echo "score 0.90 (malicious)  -> $(hit)"
    post 0.55; sleep 3; echo "score 0.55 (suspicious) -> $(hit)"
    ;;
  *) echo "usage: labctl.sh {clean|ryu-start|ryu-stop|topo-start N|topo-stop|status|score IP S|host-exec H CMD|steer-test}"; exit 1 ;;
esac
