#!/usr/bin/env bash
# Control-plane scaling vs number of distinct sources. Each spoofed source triggers one
# packet-in and one per-source rule pair, so rule count and packet-in scale with source
# count, not with intensity. Also measures the fresh-source-per-packet saturation case.
set -u
H=/opt/trust-lab/harness; REST=http://127.0.0.1:8080; OUT=/opt/trust-lab/data/src_scale; mkdir -p "$OUT"
$H/labctl.sh topo-stop>/dev/null 2>&1; $H/labctl.sh ryu-stop>/dev/null 2>&1; $H/labctl.sh clean>/dev/null 2>&1
$H/labctl.sh ryu-start $H/config/steering.json>/dev/null 2>&1; sleep 5
$H/labctl.sh topo-start 3>/dev/null 2>&1; sleep 14
c3=$(pgrep -f 'mininet:c3$'|head -1)
ryu=$(pgrep -f ryu-manager|head -1)
echo "N,flow_mod,packet_in,ryu_rss_mb" > "$OUT/scaling.csv"
for N in 1 10 50 100 200 500; do
  curl -s -m4 -X POST $REST/trust/reset>/dev/null; sleep 2
  i=0
  while [ $i -lt $N ]; do
    a=$((i/250)); b=$((i%250)); src="10.5.$a.$((b+1))"
    nsenter -t "$c3" -n hping3 -a "$src" -S -p 80 -c 1 -i u500 10.0.0.100 >/dev/null 2>&1
    i=$((i+1))
  done
  sleep 3
  st=$(curl -s -m4 $REST/trust/stats)
  fm=$(echo "$st"|grep -oE '"flow_mod_count": *[0-9]+'|grep -oE '[0-9]+')
  pin=$(echo "$st"|grep -oE '"packet_in_count": *[0-9]+'|grep -oE '[0-9]+')
  rss=$(awk '/VmRSS/{printf "%.1f",$2/1024}' /proc/$ryu/status 2>/dev/null)
  echo "$N,$fm,$pin,$rss" | tee -a "$OUT/scaling.csv"
done
# saturation: fresh source per packet for 10s -> packet-in rate
curl -s -m4 -X POST $REST/trust/reset>/dev/null; sleep 2
p0=$(curl -s -m4 $REST/trust/stats|grep -oE '"packet_in_count": *[0-9]+'|grep -oE '[0-9]+')
nsenter -t "$c3" -n timeout 10 hping3 --rand-source -S -p 80 -i u1000 10.0.0.100 >/dev/null 2>&1
p1=$(curl -s -m4 $REST/trust/stats|grep -oE '"packet_in_count": *[0-9]+'|grep -oE '[0-9]+')
echo "spoof_per_packet_rate_pps,$(( (p1-p0)/10 ))" | tee -a "$OUT/scaling.csv"
$H/labctl.sh topo-stop>/dev/null 2>&1
echo "SRC-SCALE DONE $(date)" | tee -a "$OUT/scaling.csv"
