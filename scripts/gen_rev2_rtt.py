#!/usr/bin/env python3
"""
Figure: external validity under injected propagation delay (Reviewer 2.1).

Left: steady legitimate availability vs injected RTT under Slowloris, no-defense vs steering.
      The protection is RTT-invariant (steering flat near 100 %, no-defense flat near 0),
      which is the qualitative finding that transfers.
Right: legitimate median latency of served requests vs RTT under steering, showing the
      absolute latency rises by roughly the added propagation delay, which is the
      testbed-specific quantity that does not transfer unchanged.

Reads rev2_stats.json (from scripts/rev2_analyze.py).

Usage: gen_rev2_rtt.py rev2_stats.json out.pdf
"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

STATS = sys.argv[1] if len(sys.argv) > 1 else "rev2_stats.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "figs/f_rtt.pdf"
R = json.load(open(STATS))["rtt"]


def series(arm, field):
    d = R.get(arm, {})
    xs = sorted(int(k) for k in d)
    ys = [d[str(x)][field]["mean"] for x in xs]
    es = [d[str(x)][field]["ci"] for x in xs]
    return xs, ys, es


fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.0, 2.9))

for arm, style, color, lab in (("nodefense", "s--", "#d62728", "no defense"),
                               ("gradual", "o-", "#2ca02c", "resource-aware steering")):
    if arm in R:
        xs, ys, es = series(arm, "avail")
        axL.errorbar(xs, ys, yerr=es, fmt=style, color=color, ms=5, capsize=3, lw=1.6, label=lab)
axL.set_xlabel("injected round-trip time (ms)")
axL.set_ylabel("legitimate availability (\\%)")
axL.set_ylim(-3, 108)
axL.grid(alpha=0.3)
axL.legend(fontsize=7.5, loc="center left")
axL.set_title("(a) protection is RTT-invariant", fontsize=8.5)

if "gradual" in R:
    xs, ys, es = series("gradual", "median_lat")
    axR.errorbar(xs, ys, yerr=es, fmt="o-", color="#1f77b4", ms=5, capsize=3, lw=1.6,
                 label="served-request median")
    axR.legend(fontsize=7.5, loc="upper left")
axR.set_xlabel("injected round-trip time (ms)")
axR.set_ylabel("legitimate median latency (ms)")
axR.grid(alpha=0.3)
axR.set_title("(b) absolute latency shifts with RTT", fontsize=8.5)

plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
