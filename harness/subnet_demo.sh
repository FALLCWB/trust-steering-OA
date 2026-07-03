#!/usr/bin/env bash
# Subnet-aggregation mechanism demonstration. One source in 10.0.0.0/24 is flagged;
# fresh (never-scored) sources in the same /24 then send a probe. With subnet
# aggregation the fresh sources inherit the /24 reputation (-> SvL isolation);
# without it they fall to the default tier (SvC quarantine). Reports the tier each
# fresh source lands on, for both controllers, so churn placement can be compared.
# Usage: subnet_demo.sh   (runs both configs)
set -u
H=/opt/trust-lab/harness
REST=http://127.0.0.1:8080
OUT=/opt/trust-lab/data/subnet_demo; mkdir -p "$OUT"
FRESH=(10.0.0.40 10.0.0.41 10.0.0.42 10.0.0.43 10.0.0.44 10.0.0.45 10.0.0.46 10.0.0.47)

run_cfg() {
  cfg=$1; json=$2
  echo "===== config=$cfg ($json) ====="
  "$H/labctl.sh" topo-stop >/dev/null 2>&1
  "$H/labctl.sh" ryu-stop  >/dev/null 2>&1
  "$H/labctl.sh" clean     >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/$json" >/dev/null 2>&1; sleep 5
  "$H/labctl.sh" topo-start 3 >/dev/null 2>&1; sleep 16
  "$H/labctl.sh" reset >/dev/null 2>&1; sleep 1

  iface=$("$H/labctl.sh" host-exec c3 ip -o -4 addr show 2>/dev/null | awk '{print $2}' | grep -v lo | head -1)
  [ -z "$iface" ] && iface=c3-eth0
  echo "c3 iface=$iface"

  # add fresh source aliases on the attacker host
  for ip in "${FRESH[@]}"; do
    "$H/labctl.sh" host-exec c3 ip addr add "$ip/24" dev "$iface" >/dev/null 2>&1
  done

  # flag ONE source -> raises the /24 reputation (subnet aggregation, if enabled)
  "$H/labctl.sh" score 10.0.0.13 0.9 >/dev/null; sleep 2

  # each fresh source sends a probe so the controller classifies it
  for ip in "${FRESH[@]}"; do
    "$H/labctl.sh" host-exec c3 curl --interface "$ip" -s -o /dev/null -m 3 http://10.0.0.100/ >/dev/null 2>&1
  done
  sleep 2

  # read assigned tiers
  curl -s -m4 "$REST/trust/stats" > "$OUT/${cfg}_stats.json"
  echo "assigned tiers for fresh sources:"
  python3 - "$OUT/${cfg}_stats.json" "${FRESH[@]}" <<'PY'
import json, sys
stats = json.load(open(sys.argv[1]))
assigned = stats.get("assigned", {})
fresh = sys.argv[2:]
from collections import Counter
c = Counter()
for ip in fresh:
    t = assigned.get(ip, "(unclassified)")
    c[t] += 1
    print("  %-12s -> %s" % (ip, t))
print("  histogram:", dict(c))
PY
}

run_cfg nosubnet steering.json
run_cfg subnet   subnet_only.json
"$H/labctl.sh" topo-stop >/dev/null 2>&1
echo "SUBNET DEMO DONE $(date)"
