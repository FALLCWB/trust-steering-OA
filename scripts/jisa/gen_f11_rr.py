#!/usr/bin/env python3
"""Fig. 8 (re-run data): posted live scores during the attack phase of the ten live Slowloris runs.

Each run restarts the topology and the sensor, so its sensor.log holds only that run. Windows are kept when
posted inside the attack phase or up to 5 s after it (same rule as analyze_rerun.py); runs are drawn one after
the other, separated by thin vertical lines.
Usage: gen_f11_rr.py RUNS_DIR OUT.pdf      (RUNS_DIR = .../rr2611/full/e2e/slowloris)
"""
import glob
import json
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RUNS, OUT = sys.argv[1], sys.argv[2]
ATT, LEG = "10.0.0.13", ("10.0.0.11", "10.0.0.12")
plt.rcParams.update({"font.size": 11})

xs, att, leg, bounds = [], [], [], []
k = 0
for d in sorted(glob.glob(os.path.join(RUNS, "r*")), key=lambda p: int(os.path.basename(p)[1:])):
    m = json.load(open(os.path.join(d, "manifest.json")))
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    first = True
    for line in open(os.path.join(d, "sensor.log")):
        g = re.match(r"\s*(\d+\.\d+)\s.*win#\d+.*scored=\{([^}]*)\}", line)
        if not g:
            continue
        ts = float(g.group(1)) - t0
        if not (a0 <= ts <= a1 + 5.0):
            continue
        sc = {ip: float(v) for ip, v in re.findall(r"'(10\.0\.0\.\d+)':\s*([0-9.]+)", g.group(2))}
        if first and k:
            bounds.append(k + 0.5)
        first = False
        k += 1
        xs.append(k)
        att.append(sc.get(ATT, float("nan")))
        ls = [sc[x] for x in LEG if x in sc]
        leg.append(sum(ls) / len(ls) if ls else float("nan"))

plt.figure(figsize=(7, 3.2))
for b in bounds:
    plt.axvline(b, color="#ddd", lw=0.8)
plt.plot(xs, att, "o-", color="#d62728", ms=4, label="attacker (flagged) score")
plt.plot(xs, leg, "s-", color="#2ca02c", ms=4, label="legitimate client score")
plt.axhline(0.4, ls="--", color="#888", label=r"$\tau_c=0.4$ (SvH/SvC boundary)")
plt.axhline(0.7, ls=":", color="#bbb", label=r"$\tau_l=0.7$")
plt.xlabel("sensor window during the attack, ten runs in sequence (5 s each)")
plt.ylabel("posted maliciousness score")
plt.ylim(0, 1)
plt.legend(fontsize=8, ncol=2, loc="lower center", bbox_to_anchor=(0.5, 1.005), frameon=False)
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
a = [x for x in att if x == x]
print("windows %d (attacker scored %d), runs %d" % (len(xs), len(a), len(bounds) + 1 if xs else 0))
