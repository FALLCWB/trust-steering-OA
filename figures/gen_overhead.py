#!/usr/bin/env python3
"""
f14: control-plane and data-plane cost versus the number of distinct attacking sources, under live
attack traffic. One rule pair and one controller event per distinct source, so installed rules,
Packet-In events, and switch flow-table occupancy all grow linearly with source count, not with
per-source intensity. Controller and switch resident memory stay flat, and a fresh-source-per-packet
flood forces a Packet-In per packet (saturation). Measured on the testbed (overhead_attack.sh).
Run with the sensor-venv python.
"""
import sys, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f14_overhead.pdf"
CSV = os.environ.get("OVH_CSV", "/opt/trust-lab/data/overhead_attack/scaling.csv")

N, flow_mod, pkt_in, ovs_flows = [], [], [], []
ryu_rss = ovs_rss = None
for row in csv.reader(open(CSV)):
    if not row or row[0] in ("N",):
        continue
    if row[0].startswith("spoof") or row[0].startswith("OVERHEAD"):
        continue
    if len(row) < 6:
        continue
    N.append(int(row[0])); flow_mod.append(int(row[1])); pkt_in.append(int(row[2]))
    ovs_flows.append(int(row[3])); ryu_rss = float(row[4]); ovs_rss = float(row[5])
SPOOF_PPS = 914  # fresh-source-per-packet Packet-In rate (separate saturation measurement)

print("N=%s" % N)
print("installed rules=%s" % flow_mod)
print("packet-in=%s" % pkt_in)
print("ovs flow-table occupancy=%s" % ovs_flows)
print("ryu RSS=%.1f MB  ovs-vswitchd RSS=%.1f MB (flat)" % (ryu_rss, ovs_rss))

fig, ax = plt.subplots(figsize=(3.6, 2.8))
ax.plot(N, flow_mod, "o-", color="#1f77b4", ms=4, label="installed rules")
ax.plot(N, ovs_flows, "D-", color="#2ca02c", ms=4, label="switch flow-table")
ax.plot(N, pkt_in, "s--", color="#d62728", ms=4, label="Packet-In events")
ax.plot(N, N, ":", color="#999", lw=1, label="slope 1")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("number of distinct sources $N$")
ax.set_ylabel("control-/data-plane events")
ax.legend(fontsize=7.5, loc="upper left")
ax.grid(alpha=0.3, which="both")
ax.text(0.97, 0.05,
        "controller RSS flat %.0f\\,MB; switch RSS flat %.0f\\,MB\nspoofed source / packet: %d\\,Packet-In/s"
        % (ryu_rss, ovs_rss, SPOOF_PPS),
        transform=ax.transAxes, fontsize=6.0, ha="right", va="bottom", color="#444")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
