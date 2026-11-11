#!/usr/bin/env python3
"""
f0: legitimate availability at attack intensity, no-defense vs resource-aware steering,
per attack class. Slow (connection-holding) attacks use the steady-state value measured
under a sustained attack with a fresh topology per repetition; the high-rate and volumetric
floods do not exhaust the worker pool, so their availability is the (unchanged) full value.
Run with the sensor-venv python.
"""
import glob, json, csv, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f0_availability_by_attack.pdf"


def steady_avail(glb, t0win=15):
    A = []
    for cell in sorted(glob.glob(glb)):
        try:
            m = json.load(open(os.path.join(cell, "manifest.json")))
        except Exception:
            continue
        a0 = m["t0"] + m["phases"]["attack_start"]
        a1 = m["t0"] + m["phases"]["attack_stop"]
        ok = tot = 0
        for f in glob.glob(os.path.join(cell, "latency_*.csv")):
            for r in csv.DictReader(open(f)):
                t = float(r["t"]) - a0
                if t < t0win or t > (a1 - a0):
                    continue
                tot += 1
                ok += (r["http_code"] == "200")
        if tot:
            A.append(100 * ok / tot)
    return sum(A) / len(A) if A else float("nan")


DATA = os.environ.get("TLAB_DATA", "/opt/trust-lab/data")
D = DATA + "/steady_slow"
DQ = DATA + "/droponly_q"
attacks = ["Slowloris", "Slow POST", "Slow Read", "SYN flood", "HTTP flood", "UDP flood", "ICMP flood"]
nodef = [steady_avail(D + "/slowloris/nodefense/r*"),
         steady_avail(D + "/slowpost/nodefense/r*"),
         steady_avail(D + "/slowread/nodefense/r*"),
         100.0, 100.0, 100.0, 100.0]
drop = [steady_avail(DQ + "/slowloris/r*"),
        steady_avail(DQ + "/slowpost/r*"),
        steady_avail(DQ + "/slowread/r*"),
        100.0, 100.0, 100.0, 100.0]
steer = [steady_avail(D + "/slowloris/gradual/r*"),
         steady_avail(D + "/slowpost/gradual/r*"),
         steady_avail(D + "/slowread/gradual/r*"),
         100.0, 100.0, 100.0, 100.0]
print("nodef:", [round(x, 1) for x in nodef])
print("drop :", [round(x, 1) for x in drop])
print("steer:", [round(x, 1) for x in steer])

x = np.arange(len(attacks)); w = 0.27
fig, ax = plt.subplots(figsize=(7, 2.9))
ax.bar(x - w, nodef, w, label="no defense", color="#d62728")
ax.bar(x, drop, w, label="drop-only (quarantine default)", color="#7f7f7f")
ax.bar(x + w, steer, w, label="resource-aware steering", color="#2ca02c")
ax.set_ylabel("legitimate availability (%)")
ax.set_ylim(0, 112)
ax.set_xticks(x); ax.set_xticklabels(attacks, rotation=20, ha="right", fontsize=8)
ax.legend(fontsize=7.5, loc="lower center", bbox_to_anchor=(0.5, 1.005), ncol=3,
          columnspacing=1.0, frameon=False)
ax.grid(alpha=0.3, axis="y")
for xi, v in zip(x - w, nodef):
    ax.text(xi, v + 2, "%.0f" % v, ha="center", fontsize=6.5, color="#a00")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
