#!/usr/bin/env python3
"""Fig. 9 (re-run data): live in-domain detector across attack classes, with the no-defense reference and
the live Slowloris run with asymmetric hysteresis, all on the same 30 s live-run schedule and 3-client topology.

Bars: steady-state legitimate availability (Eq. 4, Delta = 15 s), mean over ten repetitions, read from
analysis.json (analyze_rerun.py). Each bar carries its collapse count (repetitions in which no steady-state
request is answered before the attack stops). The dashed line is the floor of Eq. 4 on this schedule: under
complete denial each client's last request is answered after the attack stops, 2 of 6 requests.
Usage: gen_f17_rr.py ANALYSIS_JSON OUT.pdf
"""
import json, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

A = json.load(open(sys.argv[1])); OUT = sys.argv[2]
bars = [("no defense\n(Slowloris)", "nodef_live", "#7f7f7f"),
        ("Slowloris", "live_slowloris", None),
        ("Slow POST", "live_slowpost", None),
        ("Slow Read", "live_slowread", None),
        ("SYN flood", "live_synflood", None),
        ("HTTP flood", "live_httpflood", None),
        ("Slowloris +\nhysteresis", "live_hyst", "#1f77b4")]
x = np.arange(len(bars))
fig, ax = plt.subplots(figsize=(6.2, 3.0))
for xi, (lbl, key, col) in zip(x, bars):
    r = A[key]
    mu = r["steady_mean"]; k = int(r["collapse_steady"].split("/")[0]); n = r["n"]
    c = col or ("#d62728" if k * 2 >= n else "#2ca02c")
    ax.bar(xi, mu, 0.62, color=c)
    ax.text(xi, mu + 2.5, "%.0f%%" % mu, ha="center", fontsize=7)
    ax.text(xi, mu + 8.5, "%d/%d coll." % (k, n), ha="center", fontsize=6.5, color="#a00")
ax.axhline(100 * 2 / 6, ls="--", color="#555", lw=0.9)
ax.text(-0.42, 53, "dashed: floor of Eq. 4\n(no request answered\nduring the attack)", ha="left", va="bottom", fontsize=6.3, color="#333")
ax.set_ylabel("steady-state legitimate\navailability (%)")
ax.set_ylim(0, 116)
ax.set_xticks(x); ax.set_xticklabels([b[0] for b in bars], fontsize=7.5)
ax.grid(alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
