#!/usr/bin/env python3
"""
Figure: scale / tolerance study (Reviewer 3.2).

Two panels sharing the tolerance-limit reading the reviewer asked for.
Left  (legitimate-workload scale): steady legitimate availability vs benign background
      concurrency B, no-defense vs steering, with 95 % CIs over ten repetitions.
Right (threat scale): steady legitimate availability vs number of Slowloris attacker
      sources A, for no-defense, steering with correctly-scored attackers, and steering
      with attackers not yet scored (arriving at the default quarantine), with 95 % CIs.

Reads the aggregated rev2_stats.json produced by scripts/rev2_analyze.py.

Usage: gen_rev2_scale.py rev2_stats.json out.pdf
"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

STATS = sys.argv[1] if len(sys.argv) > 1 else "rev2_stats.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "figs/f_scale.pdf"
R = json.load(open(STATS))


def series(block, arm):
    d = block.get(arm, {})
    xs = sorted(int(k) for k in d)
    ys = [d[str(x)]["avail"]["mean"] for x in xs]
    es = [d[str(x)]["avail"]["ci"] for x in xs]
    return xs, ys, es


fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.0, 2.9))

# --- left: legit-workload scale (merge base 0-400 and high 400-6400) ---
sl = R.get("scale_legit", {})
slh = R.get("scale_legit_hi", {})
def merged(arm):
    d = {}
    for blk in (sl.get(arm, {}), slh.get(arm, {})):
        for k, v in blk.items():
            d.setdefault(int(k), []).append((v["avail"]["mean"], v["avail"]["ci"], v["n"]))
    xs = sorted(d)
    # pooled mean weighted by n where a level appears in both sweeps
    ys, es = [], []
    for x in xs:
        pts = d[x]; N = sum(p[2] for p in pts)
        ys.append(sum(p[0]*p[2] for p in pts)/N)
        es.append(max(p[1] for p in pts))
    return xs, ys, es
for arm, style, color, lab in (("nodefense", "s--", "#d62728", "no defense"),
                               ("gradual", "o-", "#2ca02c", "resource-aware steering")):
    if arm in sl or arm in slh:
        xs, ys, es = merged(arm)
        axL.errorbar(xs, ys, yerr=es, fmt=style, color=color, ms=5, capsize=3, lw=1.6, label=lab)
axL.set_xscale("symlog", linthresh=100)
axL.set_xlabel("benign background load (concurrent conns.)")
axL.set_ylabel("legitimate availability (\\%)")
axL.set_ylim(-3, 108)
axL.grid(alpha=0.3)
axL.legend(fontsize=7.5, loc="lower left")
axL.set_title("(a) legitimate-workload scale", fontsize=8.5)

# --- right: threat scale ---
st = R.get("scale_threat", {})
for arm, style, color, lab in (("nodefense", "s--", "#d62728", "no defense"),
                               ("gradual", "o-", "#2ca02c", "steering, attackers scored"),
                               ("gradual_unscored", "^:", "#ff7f0e", "steering, pre-classification")):
    if arm in st:
        xs, ys, es = series(st, arm)
        axR.errorbar(xs, ys, yerr=es, fmt=style, color=color, ms=5, capsize=3, lw=1.6, label=lab)
axR.set_xlabel("number of attacker sources $A$")
axR.set_ylim(-3, 108)
axR.grid(alpha=0.3)
axR.legend(fontsize=7.0, loc="lower left")
axR.set_title("(b) threat scale", fontsize=8.5)

plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
