#!/usr/bin/env python3
"""
f16: reset cost for legitimate clients under noisy scores. When a legitimate client's score
crosses tau_c upward it is demoted off the primary, which deletes its rule pair and resets its
established connection; the next request reinstalls a rule on the new tier. This quantifies, per
legitimate-score noise level, how many such demotions a client suffers and how many requests fail
as a result, for the no-hysteresis and hysteresis policies. Reads the existing legit_sweep runs
(no new experiment). Run with the sensor-venv python.
"""
import glob, os, csv, sys, math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = "/opt/trust-lab/data/legit_sweep"
TAU_C = 0.4
LEGIT_IPS = ["10.0.0.11", "10.0.0.12"]
STDS = ["0.00", "0.10", "0.20", "0.30"]
OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f16_reset.pdf"


def attack_window(cell):
    # manifest holds t0 and phase offsets
    import json
    m = json.load(open(os.path.join(cell, "manifest.json")))
    a0 = m["t0"] + m["phases"]["attack_start"]
    a1 = m["t0"] + m["phases"]["attack_stop"]
    return a0, a1


def demotions(cell, ip, a0, a1):
    """Upward crossings of tau_c for this legit IP within the attack window = reset-inducing demotions."""
    f = os.path.join(cell, "scores.csv")
    if not os.path.exists(f):
        return None
    prev = None
    n = 0
    for row in csv.reader(open(f)):
        if len(row) < 4 or row[2] != ip:
            continue
        t, s = float(row[0]), float(row[3])
        if t < a0 or t > a1:
            continue
        if prev is not None and prev < TAU_C <= s:   # crossed up into quarantine -> demotion + reset
            n += 1
        prev = s
    return n


def failed(cell, ip, a0, a1):
    f = os.path.join(cell, "latency_%s.csv" % ip)
    if not os.path.exists(f):
        return None, None
    bad = tot = 0
    for r in csv.DictReader(open(f)):
        t = float(r["t"])
        if t < a0 or t > a1:
            continue
        tot += 1
        bad += (r["http_code"] != "200")
    return bad, tot


def mean_sd(xs):
    xs = [x for x in xs if x is not None]
    n = len(xs)
    if n == 0:
        return float("nan"), 0.0
    mu = sum(xs) / n
    sd = math.sqrt(sum((x - mu) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    return mu, sd


def collect(arm):
    dem, fail, avail = [], [], []
    for std in STDS:
        ds, fs, av = [], [], []
        for cell in sorted(glob.glob(os.path.join(ROOT, arm, "l%s" % std, "r*"))):
            if not os.path.exists(os.path.join(cell, "manifest.json")):
                continue
            a0, a1 = attack_window(cell)
            for ip in LEGIT_IPS:
                d = demotions(cell, ip, a0, a1)
                b, t = failed(cell, ip, a0, a1)
                if d is not None:
                    ds.append(d)
                if t:
                    fs.append(b)
                    av.append(100.0 * (t - b) / t)
        dem.append(mean_sd(ds)); fail.append(mean_sd(fs)); avail.append(mean_sd(av))
    return dem, fail, avail


arms = {"nohyst": "no hysteresis", "hyst": "hysteresis"}
data = {a: collect(a) for a in arms}
print("legit-score noise sigma:", STDS, "(tau_c=%.1f)" % TAU_C)
for a, lbl in arms.items():
    dem, fail, avail = data[a]
    print("%-10s demotions/client: %s" % (a, ["%.1f" % d[0] for d in dem]))
    print("%-10s failed reqs/client: %s" % (a, ["%.1f" % f[0] for f in fail]))
    print("%-10s availability(%%): %s" % (a, ["%.0f" % v[0] for v in avail]))

x = [float(s) for s in STDS]
fig, ax = plt.subplots(1, 2, figsize=(7, 2.9))
for a, lbl in arms.items():
    dem, fail, avail = data[a]
    style = "o-" if a == "nohyst" else "s--"
    ax[0].errorbar(x, [d[0] for d in dem], yerr=[d[1] for d in dem], fmt=style, capsize=3, label=lbl)
    ax[1].errorbar(x, [f[0] for f in fail], yerr=[f[1] for f in fail], fmt=style, capsize=3, label=lbl)
ax[0].set_xlabel("legitimate-score noise $\\sigma$"); ax[0].set_ylabel("tier demotions per client")
ax[1].set_xlabel("legitimate-score noise $\\sigma$"); ax[1].set_ylabel("failed requests per client")
for a in ax:
    a.grid(alpha=0.3); a.legend(fontsize=8)
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
