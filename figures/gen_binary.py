#!/usr/bin/env python3
"""
f15: does the third (isolation) tier add anything over a single quarantine secondary?
A benign client mis-scored as suspicious (c1) is held in the quarantine secondary while a
confirmed attacker (c3) runs Slowloris and a correctly-scored control (c2) sits on the primary.
Two-tier (no isolation tier) forces the attacker into the same quarantine as the false positive;
three-tier isolates the attacker to SvL. Both keep the primary intact; only the third tier keeps
the benign-but-flagged client served. Steady-state legit availability, mean over the runs with a
95% t-interval. Run with the sensor-venv python.
"""
import glob, json, csv, os, sys, math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f15_binary.pdf"
ROOT = "/opt/trust-lab/data/binary"
T95 = {5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}  # two-sided 95%, df=n-1


def steady_avail(cell, ip, win=15):
    f = os.path.join(cell, "latency_%s.csv" % ip)
    if not os.path.exists(f):
        return None
    try:
        m = json.load(open(os.path.join(cell, "manifest.json")))
    except Exception:
        return None
    a0 = m["t0"] + m["phases"]["attack_start"]
    a1 = m["t0"] + m["phases"]["attack_stop"]
    ok = tot = 0
    for r in csv.DictReader(open(f)):
        t = float(r["t"]) - a0
        if t < win or t > (a1 - a0):
            continue
        tot += 1
        ok += (r["http_code"] == "200")
    return (100.0 * ok / tot) if tot else None


def series(arm, ip):
    vals = []
    for cell in sorted(glob.glob(os.path.join(ROOT, arm, "r*"))):
        v = steady_avail(cell, ip)
        if v is not None:
            vals.append(v)
    return vals


def mean_ci(vals):
    n = len(vals)
    if n == 0:
        return float("nan"), 0.0
    mu = sum(vals) / n
    if n < 2:
        return mu, 0.0
    sd = math.sqrt(sum((x - mu) ** 2 for x in vals) / (n - 1))
    return mu, T95.get(n, 2.262) * sd / math.sqrt(n)


C1, C2 = "10.0.0.11", "10.0.0.12"     # c1 false positive -> quarantine ; c2 control -> primary
arms = [("threetier", "three-tier\n(graduated)"), ("twotier", "two-tier\n(binary)")]
fp = [mean_ci(series(a, C1)) for a, _ in arms]
ctl = [mean_ci(series(a, C2)) for a, _ in arms]
for (a, _), f, c in zip(arms, fp, ctl):
    print("%-10s n=%d  FP-in-quarantine=%.1f+-%.1f  control-on-primary=%.1f+-%.1f"
          % (a, len(series(a, C1)), f[0], f[1], c[0], c[1]))

x = np.arange(len(arms)); w = 0.36
fig, ax = plt.subplots(figsize=(3.6, 2.9))
ax.bar(x - w / 2, [f[0] for f in fp], w, yerr=[f[1] for f in fp], capsize=3,
       color="#2ca02c", label="benign-but-flagged (quarantine)")
ax.bar(x + w / 2, [c[0] for c in ctl], w, yerr=[c[1] for c in ctl], capsize=3,
       color="#7f7f7f", label="control (primary)")
ax.set_ylabel("legitimate availability (\\%)")
ax.set_ylim(0, 112)
ax.set_xticks(x); ax.set_xticklabels([lbl for _, lbl in arms], fontsize=8)
ax.legend(fontsize=7, loc="lower center")
ax.grid(alpha=0.3, axis="y")
for xi, f in zip(x - w / 2, fp):
    ax.text(xi, f[0] + 3, "%.0f" % f[0], ha="center", fontsize=7,
            color="#176117", fontweight="bold")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
