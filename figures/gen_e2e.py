#!/usr/bin/env python3
"""
f17: live in-domain detector across attack classes. The same Random Forest sensor that scored the
Slowloris run drives the policy against the other connection-holding classes (Slow POST, Slow Read)
and two high-rate classes (SYN flood, HTTP GET flood), with no oracle. Reports steady-state legitimate
availability per class, mean over ten repetitions with 95% CI, and the per-class collapse count (reps at
or near zero). Slowloris is shown as the reference point established earlier. Run with sensor-venv python.
"""
import glob, json, csv, os, sys, math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = "/opt/trust-lab/data/e2e_multi"
SLOW_REF = "/opt/trust-lab/data/e2e_rf"   # slowloris reference run
OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f17_e2e.pdf"
T95 = {5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}


def steady_avail(cell, win=15):
    if not os.path.exists(os.path.join(cell, "manifest.json")):
        return None
    m = json.load(open(os.path.join(cell, "manifest.json")))
    a0 = m["t0"] + m["phases"]["attack_start"]
    a1 = m["t0"] + m["phases"]["attack_stop"]
    ok = tot = 0
    for f in glob.glob(os.path.join(cell, "latency_*.csv")):
        for r in csv.DictReader(open(f)):
            t = float(r["t"]) - a0
            if t < win or t > (a1 - a0):
                continue
            tot += 1
            ok += (r["http_code"] == "200")
    return (100.0 * ok / tot) if tot else None


def per_class(d):
    vals = [steady_avail(c) for c in sorted(glob.glob(os.path.join(d, "r*")))]
    vals = [v for v in vals if v is not None]
    return vals


def stat(vals):
    n = len(vals)
    if n == 0:
        return float("nan"), 0.0, 0, 0
    mu = sum(vals) / n
    collapse = sum(1 for v in vals if v < 5.0)
    if n < 2:
        return mu, 0.0, n, collapse
    sd = math.sqrt(sum((x - mu) ** 2 for x in vals) / (n - 1))
    return mu, T95.get(n, 2.262) * sd / math.sqrt(n), n, collapse


# Slowloris is reported separately in the live-detector subsection (whole-window method); the four
# classes here use the steady-state window and extend that single run across the attack taxonomy.
classes = [("slowpost", "Slow POST", ROOT + "/slowpost"),
           ("slowread", "Slow Read", ROOT + "/slowread"),
           ("synflood", "SYN flood", ROOT + "/synflood"),
           ("httpflood", "HTTP flood", ROOT + "/httpflood")]
res = []
for key, lbl, d in classes:
    mu, ci, n, col = stat(per_class(d))
    res.append((lbl, mu, ci, n, col))
    print("%-11s n=%2d  avail=%.0f +- %.0f  collapse=%d/%d" % (lbl, n, mu, ci, col, n))

# res = (label, mean, ci, n, collapse_count). The slow classes are bimodal, so the bar is the mean
# availability and each bar is annotated with its collapse rate (runs at/near zero out of n); no
# normal-approximation CI is drawn, since it is invalid for a bimodal collapse.
labels = [r[0] for r in res]
mus = [r[1] for r in res]
cols = ["#d62728" if m < 50 else "#2ca02c" for m in mus]
x = np.arange(len(labels))
fig, ax = plt.subplots(figsize=(4.4, 2.9))
ax.bar(x, mus, 0.6, color=cols)
ax.set_ylabel("legitimate availability (\\%)")
ax.set_ylim(0, 116)
ax.set_xticks(x); ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
ax.grid(alpha=0.3, axis="y")
for xi, r in zip(x, res):
    lbl, mu, ci, n, col = r
    ax.text(xi, mu + 3, "%.0f\\%%" % mu, ha="center", fontsize=7)
    ax.text(xi, mu + 9, "%d/%d coll." % (col, n), ha="center", fontsize=6, color="#a00")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
