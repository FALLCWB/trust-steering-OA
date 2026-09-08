#!/usr/bin/env python3
"""
Figure: sensor failure-mode study (Reviewer 3.3).

A grouped bar chart of steady legitimate availability under Slowloris for each failure mode,
with 95 % CIs over ten repetitions, annotated with the tier the attacker ends up on. It shows
the honest failure surface: the default-quarantine design survives a silent outage, a stale
trusting verdict is the genuine single point of failure, a naive score-TTL fail-safe relocates
the collapse rather than preventing it, and a compromised sensor inverts placement.

Reads rev2_stats.json (from scripts/rev2_analyze.py).

Usage: gen_rev2_sensor.py rev2_stats.json out.pdf
"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

STATS = sys.argv[1] if len(sys.argv) > 1 else "rev2_stats.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "figs/f_sensor.pdf"
R = json.load(open(STATS))["sensor_failure"]

order = [("baseline_live", "sensor\nlive"),
         ("outage_nottl", "outage\n(fail-open)"),
         ("outage_ttl", "outage\n+ TTL"),
         ("stale_nottl", "stale benign\n(fail-open)"),
         ("stale_ttl", "stale benign\n+ TTL"),
         ("poisoned", "poisoned\nsensor")]
names = [n for _, n in order if _ in R]
keys = [k for k, _ in order if k in R]
means = [R[k]["avail"]["mean"] for k in keys]
cis = [R[k]["avail"]["ci"] for k in keys]
tiers = [R[k]["attacker_tier_mode"] for k in keys]

# green = clients truly protected (high availability AND still on the primary);
# red = collapse; amber = misleading/degraded (e.g. poisoned inverts placement)
colors = []
legit_tiers = [R[k]["legit_tier_mode"] for k in keys]
for k, lt in zip(keys, legit_tiers):
    m = R[k]["avail"]["mean"]
    if m <= 5:
        colors.append("#d62728")
    elif m >= 95 and lt == "SvH":
        colors.append("#2ca02c")
    else:
        colors.append("#ff7f0e")

fig, ax = plt.subplots(figsize=(7.0, 3.0))
x = np.arange(len(keys))
ax.bar(x, means, 0.62, yerr=cis, capsize=3, color=colors, alpha=0.85)
ax.set_ylabel("legitimate availability (\\%)")
ax.set_ylim(0, 112)
ax.set_xticks(x)
ax.set_xticklabels(names, fontsize=7.5)
ax.grid(alpha=0.3, axis="y")
for xi, m, t, lt in zip(x, means, tiers, legit_tiers):
    lab = "attacker\non %s" % t
    if lt != "SvH":
        lab += "\nclients\non %s" % lt
    ax.text(xi, (m + 3) if m > 5 else 3, lab, ha="center", fontsize=6.3, color="#333")
ax.set_title("Legitimate availability under Slowloris across sensor failure modes",
             fontsize=8.5)
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
