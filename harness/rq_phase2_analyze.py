#!/usr/bin/env python3
"""
Aggregate Phase-2 results (deception + tarpit + shrew) into means with 95% CIs and produce the
figures referenced by the Deception subsection. Reads the per-cell JSON written by rq_deception.py
and rq_shrew.py. Run after phase2.sh completes. Pure stdlib + matplotlib.
"""
import glob, json, math, os, statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

DATA = "/opt/trust-lab/data"
OUT = "/opt/trust-lab/figures/final_synthesis"
os.makedirs(OUT, exist_ok=True)


def ci95(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    if not xs:
        return float("nan"), 0.0
    m = st.mean(xs)
    h = 1.96 * (st.pstdev(xs) / math.sqrt(len(xs))) if len(xs) > 1 else 0.0
    return m, h


def load(pat, key):
    vals = []
    for f in glob.glob(pat):
        try:
            vals.append(json.load(open(f)).get(key))
        except Exception:
            pass
    return vals


# ===== 1) Deception: attacker success-signal + legit protection, per defense =====
defs = ["nodefense", "droponly", "gradual"]
asr, alat, lsr, det = {}, {}, {}, {}
for d in defs:
    p = "%s/deception/%s/deception_*.json" % (DATA, d)
    asr[d] = ci95([100 * v for v in load(p, "attacker_success_rate")])
    alat[d] = ci95(load(p, "attacker_lat_ms"))
    lsr[d] = ci95([100 * v for v in load(p, "legit_success_rate")])
    ds = [v for v in load(p, "attacker_detect_s") if v is not None]
    det[d] = (st.mean(ds), len(ds)) if ds else (None, 0)
print("=== DECEPTION ===")
for d in defs:
    print("%-10s attacker_success=%.0f%%(+-%.0f) attacker_lat=%.0fms legit_success=%.0f%% detected_runs=%d/%d detect_mean=%s" % (
        d, asr[d][0], asr[d][1], alat[d][0], lsr[d][0], det[d][1],
        len(load("%s/deception/%s/deception_*.json" % (DATA, d), "attacker_success_rate")),
        ("%.1fs" % det[d][0]) if det[d][0] is not None else "n/a"))

# Fig f9: deception bar (attacker success vs legit success, per defense)
x = np.arange(len(defs)); w = 0.36
fig, ax = plt.subplots(figsize=(6, 3.6))
a = ax.bar(x - w / 2, [asr[d][0] for d in defs], w, yerr=[asr[d][1] for d in defs], capsize=4,
           label="attacker success (deception signal)", color="#d62728")
l = ax.bar(x + w / 2, [lsr[d][0] for d in defs], w, yerr=[lsr[d][1] for d in defs], capsize=4,
           label="legitimate success (primary protection)", color="#2ca02c")
ax.bar_label(a, fmt="%.0f%%", fontsize=7); ax.bar_label(l, fmt="%.0f%%", fontsize=7)
ax.set_xticks(x); ax.set_xticklabels(["no defense", "drop-only", "elastic (steer)"])
ax.set_ylabel("success rate (%)"); ax.set_ylim(0, 112); ax.legend(fontsize=8, loc="lower center")
ax.set_title("Deception signal vs primary protection, per defense (10 reps, 95% CI)")
ax.grid(axis="y", alpha=0.3); fig.tight_layout()
fig.savefig(OUT + "/f9_deception.pdf"); fig.savefig(OUT + "/f9_deception.png", dpi=130)

# ===== 2) Tarpit ramp: attacker success + latency vs bg intensity, off vs on =====
ints = [50, 150, 300]
print("=== TARPIT ===")
tp = {}
for mode in ["off", "on"]:
    tp[mode] = {}
    for I in ints:
        p = "%s/tarpit/%s/i%d/deception_*.json" % (DATA, mode, I)
        tp[mode][I] = (ci95([100 * v for v in load(p, "attacker_success_rate")]),
                       ci95(load(p, "attacker_lat_ms")),
                       ci95([100 * v for v in load(p, "legit_success_rate")]))
        print("tarpit %-3s i=%-3d attacker_success=%.0f%% attacker_lat=%.0fms legit=%.0f%%" % (
            mode, I, tp[mode][I][0][0], tp[mode][I][1][0], tp[mode][I][2][0]))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8, 3.4))
for mode, c in (("off", "#d62728"), ("on", "#2ca02c")):
    ax1.errorbar(ints, [tp[mode][I][0][0] for I in ints], yerr=[tp[mode][I][0][1] for I in ints],
                 marker="o", capsize=3, color=c, label="tarpit %s" % mode)
    ax2.errorbar(ints, [tp[mode][I][1][0] for I in ints], yerr=[tp[mode][I][1][1] for I in ints],
                 marker="o", capsize=3, color=c, label="tarpit %s" % mode)
ax1.set_xlabel("attacker background load (concurrency)"); ax1.set_ylabel("attacker success (%)")
ax1.set_ylim(0, 112); ax1.legend(fontsize=8); ax1.grid(alpha=0.3); ax1.set_title("Deception signal")
ax2.set_xlabel("attacker background load (concurrency)"); ax2.set_ylabel("attacker latency (ms)")
ax2.legend(fontsize=8); ax2.grid(alpha=0.3); ax2.set_title("Attacker-perceived latency")
fig.tight_layout()
fig.savefig(OUT + "/f10_tarpit.pdf"); fig.savefig(OUT + "/f10_tarpit.png", dpi=130)

# ===== 3) Shrew: throughput retained, nodefense vs gradual =====
print("=== SHREW ===")
for d in ["nodefense", "gradual"]:
    p = "%s/shrew/%s/shrew_*.json" % (DATA, d)
    base = ci95(load(p, "baseline_mbps")); und = ci95(load(p, "under_shrew_mbps"))
    ret = ci95(load(p, "throughput_retained_pct"))
    print("shrew %-9s baseline=%.1f under=%.1f retained=%.1f%%(+-%.1f)" % (d, base[0], und[0], ret[0], ret[1]))

print("FIGURES: f9_deception, f10_tarpit written to", OUT)
