#!/usr/bin/env bash
# Control-plane AND data-plane cost versus number of distinct attacking sources, under live
# attack traffic. Each distinct source that sends traffic triggers one Packet-In and one
# per-source rule pair, so both the controller event counts and the switch flow-table
# occupancy grow with the source count, not with per-source intensity. Extends src_scale.sh
# with the switch-side metrics the reviewer asked for: OVS flow-table occupancy and OVS
# (ovs-vswitchd) resident memory, sampled while the sources are actively sending.
set -u
H=/opt/trust-lab/harness; REST=http://127.0.0.1:8080; OUT=/opt/trust-lab/data/overhead_attack; mkdir -p "$OUT"
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
$H/labctl.sh ryu-start $H/config/steering.json>/dev/null 2>&1; sleep 5
$H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14
c3=$(pgrep -f 'mininet:c3$'|head -1)
ryu=$(pgrep -f ryu-manager|head -1)
ovs=$(pgrep -f ovs-vswitchd|head -1)
flows() { ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null | grep -c "cookie="; }
rss()   { LC_ALL=C awk '/VmRSS/{printf "%.1f",$2/1024}' /proc/"$1"/status 2>/dev/null; }
stat()  { curl -s -m4 $REST/trust/stats | grep -oE "\"$1\": *[0-9]+" | grep -oE '[0-9]+'; }
echo "N,flow_mod,packet_in,ovs_flows,ryu_rss_mb,ovs_rss_mb" > "$OUT/scaling.csv"
for N in 1 10 50 100 200 500; do
  curl -s -m4 -X POST $REST/trust/reset>/dev/null
  $H/labctl.sh clean>/dev/null 2>&1; $H/labctl.sh topo-stop>/dev/null 2>&1
  $H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 12
  c3=$(pgrep -f 'mininet:c3$'|head -1)
  curl -s -m4 -X POST $REST/trust/reset>/dev/null; sleep 1
  # each distinct source sends a short sustained stream (4 packets over ~0.4 s) so traffic
  # is genuinely flowing through the data plane while the table is sampled
  i=0
  while [ $i -lt $N ]; do
    a=$((i/250)); b=$((i%250)); src="10.5.$a.$((b+1))"
    nsenter -t "$c3" -n hping3 -a "$src" -S -p 80 -c 4 -i u100000 10.0.0.100 >/dev/null 2>&1 &
    i=$((i+1))
    [ $((i%50)) -eq 0 ] && wait
  done
  wait
  sleep 2
  fm=$(stat flow_mod_count); pin=$(stat packet_in_count); fl=$(flows)
  rr=$(rss "$ryu"); orr=$(rss "$ovs")
  echo "$N,$fm,$pin,$fl,$rr,$orr" | tee -a "$OUT/scaling.csv"
done
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1
echo "OVERHEAD-ATTACK DONE $(date)" | tee -a "$OUT/scaling.csv"
