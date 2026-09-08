#!/usr/bin/env python3
"""
Figure: latency side-channel (Reviewer 2.1).

Left: attacker-observed response-time distribution on the primary tier (no defense) versus
      the isolation tier at tarpit delays 0, 100, 300, 600 ms, as box plots over the pooled
      probes. The primary and isolation distributions never overlap, which is the visual form
      of the side-channel: a latency-aware adversary separates the two with near-certainty.
Right: the single-threshold distinguishability accuracy (primary vs isolation) as a function
      of tarpit delay, annotated with the median latencies, showing that the tarpit trades
      deception latency for detectability rather than closing the channel.

Reads rev2_stats.json (from scripts/rev2_analyze.py) and the raw sidechannel samples.

Usage: gen_rev2_sidechannel.py rev2_stats.json <data/rev2/sidechannel> out.pdf
"""
import glob
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

STATS = sys.argv[1] if len(sys.argv) > 1 else "rev2_stats.json"
SCDIR = sys.argv[2] if len(sys.argv) > 2 else "/opt/trust-lab/data/rev2/sidechannel"
OUT = sys.argv[3] if len(sys.argv) > 3 else "figs/f_sidechannel.pdf"
R = json.load(open(STATS))["sidechannel"]


def pooled(cond):
    xs = []
    for p in sorted(glob.glob(os.path.join(SCDIR, cond, "r*", "samples.json"))):
        xs += json.load(open(p))["latencies_ms"]
    return np.asarray(xs, float)


conds = [("primary", "primary\n(no defense)"),
         ("svl_0ms", "SvL\ntarpit 0"),
         ("svl_100ms", "SvL\ntarpit 100"),
         ("svl_300ms", "SvL\ntarpit 300"),
         ("svl_600ms", "SvL\ntarpit 600")]
data = [pooled(c) for c, _ in conds]
labels = [l for _, l in conds]

fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.0, 2.9))

bp = axL.boxplot(data, tick_labels=labels, showfliers=False, patch_artist=True, widths=0.6)
colors = ["#2ca02c", "#d62728", "#d62728", "#d62728", "#d62728"]
for patch, c in zip(bp["boxes"], colors):
    patch.set_facecolor(c)
    patch.set_alpha(0.35)
axL.set_yscale("log")
axL.set_ylabel("attacker-observed latency (ms)")
axL.tick_params(axis="x", labelsize=7)
axL.grid(alpha=0.3, axis="y", which="both")
axL.set_title("(a) response-time distributions", fontsize=8.5)

# right: distinguishability accuracy vs tarpit delay
delays, accs, meds = [], [], []
for cond, _ in conds[1:]:
    if cond in R and "distinguish_acc_vs_primary" in R[cond]:
        delays.append(R[cond]["median_ms"].get("mean"))  # not used for x; placeholder
for cond in ("svl_0ms", "svl_100ms", "svl_300ms", "svl_600ms"):
    d = int(cond.split("_")[1].replace("ms", ""))
    if cond in R and "distinguish_acc_vs_primary" in R[cond]:
        delays.append(d)
        accs.append(100.0 * R[cond]["distinguish_acc_vs_primary"])
        meds.append(R[cond]["pooled_median"])
delays = [0, 100, 300, 600][:len(accs)]
axR.plot(delays, accs, "o-", color="#7b3294", ms=6, lw=1.8)
axR.axhline(50, ls=":", color="#999", lw=1)
axR.text(delays[-1] if delays else 0, 52, "chance", fontsize=7, ha="right", color="#777")
axR.set_ylim(40, 103)
axR.set_xlabel("tarpit delay (ms)")
axR.set_ylabel("primary-vs-isolation\ndistinguishability (\\%)")
axR.grid(alpha=0.3)
axR.set_title("(b) side-channel detectability", fontsize=8.5)
for x, a, m in zip(delays, accs, meds):
    axR.annotate("%.0f ms" % m, (x, a), textcoords="offset points", xytext=(0, -12),
                 fontsize=6.5, ha="center", color="#555")

plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
