#!/usr/bin/env python3
"""
f0b: legitimate latency at peak attack intensity, no-defense vs resource-aware steering, per attack
class, with 95% confidence intervals. Latency is the mean request completion time over ALL legitimate
requests in the attack window; a request that fails is counted at the curl timeout (5 s), so the metric
captures the user-visible cost of an attack that mostly times out (the slow classes) as well as one that
merely inflates latency (the high-rate floods). Slow classes use the steady-state runs; floods use the
peak-intensity cell. Run with the sensor-venv python.
"""
import glob, json, csv, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f0b_latency_by_attack.pdf"
TO = 5000.0  # curl -m5 timeout (ms): a failed request costs the client the full timeout
D = "/opt/trust-lab/data"


def cell_lat(cell):
    mp = os.path.join(cell, "manifest.json")
    if not os.path.exists(mp):
        return None
    m = json.load(open(mp)); t0 = m["t0"]; a0 = m["phases"]["attack_start"]; a1 = m["phases"]["attack_stop"]
    lat = []
    for f in glob.glob(cell + "/latency_*.csv"):
        for r in csv.DictReader(open(f)):
            t = float(r["t"]) - t0
            if a0 <= t < a1:
                lat.append(float(r["time_total"]) * 1000 if r["http_code"] == "200" else TO)
    return float(np.mean(lat)) if lat else None


def agg(pat):
    v = [cell_lat(c) for c in sorted(glob.glob(pat))]
    v = [x for x in v if x is not None]
    if not v:
        return float("nan"), 0.0
    ci = 1.96 * np.std(v, ddof=1) / np.sqrt(len(v)) if len(v) > 1 else 0.0
    return float(np.mean(v)), float(ci)


# (label, no-defense glob, steering glob)
SPEC = [
    ("Slowloris",  "steady_slow/slowloris/nodefense/r*", "steady_slow/slowloris/gradual/r*"),
    ("Slow POST",  "steady_slow/slowpost/nodefense/r*",  "steady_slow/slowpost/gradual/r*"),
    ("Slow Read",  "steady_slow/slowread/nodefense/r*",  "steady_slow/slowread/gradual/r*"),
    ("SYN flood",  "final_synflood/nodefense/i100000/r*", "final_synflood/gradual/i100000/r*"),
    ("HTTP flood", "final_httpflood/nodefense/i250/r*",   "final_httpflood/gradual/i250/r*"),
    ("UDP flood",  "final_udpflood/nodefense/i100000/r*", "final_udpflood/gradual/i100000/r*"),
    ("ICMP flood", "final_icmpflood/nodefense/i100000/r*", "final_icmpflood/gradual/i100000/r*"),
]
attacks = [s[0] for s in SPEC]
nod = [agg(os.path.join(D, s[1])) for s in SPEC]
ste = [agg(os.path.join(D, s[2])) for s in SPEC]
for a, n, s in zip(attacks, nod, ste):
    print("%-11s nodef=%.0f+-%.0f  steer=%.0f+-%.0f" % (a, n[0], n[1], s[0], s[1]))

x = np.arange(len(attacks)); w = 0.38
fig, ax = plt.subplots(figsize=(7, 2.9))
ax.bar(x - w / 2, [n[0] for n in nod], w, yerr=[n[1] for n in nod], capsize=3,
       label="no defense", color="#d62728")
ax.bar(x + w / 2, [s[0] for s in ste], w, yerr=[s[1] for s in ste], capsize=3,
       label="resource-aware steering", color="#2ca02c")
ax.set_yscale("log")
ax.set_ylabel("legitimate latency (ms)")
ax.set_xticks(x); ax.set_xticklabels(attacks, rotation=20, ha="right", fontsize=8)
ax.legend(fontsize=8, loc="upper right")
ax.grid(alpha=0.3, axis="y", which="both")
plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
