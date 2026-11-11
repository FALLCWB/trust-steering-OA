#!/usr/bin/env python3
"""
Patched copy for the JISA package: availability on the whole attack window (the original averaged the
whole run, baseline included), bootstrap percentile intervals, and the live RF attacker mean (0.368, re-run
of 2026-11-11) in place of the old operating-point band.
f12: detector-quality requirement. Legit availability under slowloris as a function
of the attacker score mean, for a stable detector and a noisy one (sigma=0.30),
with and without asymmetric hysteresis. Shows that a stable detector only needs to
separate above tau_c, a noisy detector needs to reach tau_l, and hysteresis buys
back tolerance to detector noise. Run with the sensor-venv python (has matplotlib).
"""
import csv, glob, json, math, os, random, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/detector_sweep"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/opt/trust-lab/data/detector_sweep/f12_detector.pdf"


def cell_avail(cell):
    """Whole attack window (Methods, Eq. 2 with Delta = 0): requests issued in [t_a, t_e)."""
    m = json.load(open(os.path.join(cell, "manifest.json")))
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    codes = ok = 0
    for lf in glob.glob(os.path.join(cell, "latency_*.csv")):
        with open(lf) as f:
            for row in csv.DictReader(f):
                t = float(row["t"]) - t0
                if not (a0 <= t < a1):
                    continue
                codes += 1
                if row["http_code"] == "200":
                    ok += 1
    return (ok / codes) if codes else float("nan")


def series(cfg, std):
    """-> (means, avail%, ci%) sorted by mean for one (config, std)."""
    cdir = os.path.join(ROOT, cfg)
    pts = []
    for cell in os.listdir(cdir):
        if not cell.startswith("m"):
            continue
        try:
            mean = float(cell.split("_")[0][1:]); s = float(cell.split("_")[1][1:])
        except Exception:
            continue
        if abs(s - std) > 1e-9:
            continue
        vals = [cell_avail(r) for r in sorted(glob.glob(os.path.join(cdir, cell, "r*")))]
        vals = [v for v in vals if v == v]
        if not vals:
            continue
        n = len(vals); m = sum(vals) / n
        rng = random.Random(20261110)
        bs = sorted(sum(rng.choice(vals) for _ in vals) / n for _ in range(10000))
        lo, hi = bs[250], bs[9749]
        pts.append((mean, 100 * m, (100 * (m - lo), 100 * (hi - m))))
    pts.sort()
    return [p[0] for p in pts], [p[1] for p in pts], [[p[2][0] for p in pts], [p[2][1] for p in pts]]


plt.figure(figsize=(7, 3.2))
CURVES = [
    ("nohyst", 0.00, "no hysteresis, stable detector",        "o-",  "#1f77b4"),
    ("nohyst", 0.30, r"no hysteresis, noisy detector ($\sigma{=}0.30$)", "o--", "#d62728"),
    ("hyst",   0.30, r"hysteresis, noisy detector ($\sigma{=}0.30$)",    "s-",  "#2ca02c"),
]
for cfg, std, label, fmt, color in CURVES:
    x, y, ci = series(cfg, std)
    if not x:
        continue
    plt.errorbar(x, y, yerr=ci, fmt=fmt, color=color, ms=5, capsize=3, label=label)

plt.axvline(0.4, ls="--", color="#888", lw=1)
plt.axvline(0.7, ls=":", color="#bbb", lw=1)
plt.text(0.407, 30, r"$\tau_c$", color="#555", fontsize=9)
plt.text(0.707, 30, r"$\tau_l$", color="#777", fontsize=9)
plt.axvline(0.368, ls="-", color="#a00", lw=1, alpha=0.5)
plt.text(0.362, 3, "live RF\nmean", color="#a00", fontsize=7, ha="right", va="bottom")
plt.xlabel("attacker score mean (legitimate clients fixed at 0.10)")
plt.ylabel("legitimate availability,\nwhole attack window (%)")
plt.ylim(0, 102)
plt.xlim(0.30, 0.95)
plt.legend(fontsize=8, loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
