#!/usr/bin/env python3
"""Detector-quality and legitimate-noise sweeps (Figs. 12 and 16) on the three windows: whole run (what the
original generators used), whole attack window and steady state (Methods, Eq. 4). Mean over repetitions and
95 % percentile bootstrap (10^4 resamples, fixed seed).
Usage: sweep_windows.py DATA_ROOT OUT_JSON
"""
import csv, glob, json, os, random, sys

ROOT, OUT = sys.argv[1], sys.argv[2]

def rep(d):
    m = json.load(open(os.path.join(d, "manifest.json")))
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    rows = []
    for f in glob.glob(os.path.join(d, "latency_*.csv")):
        for x in csv.DictReader(open(f)):
            rows.append((float(x["t"]) - t0, x["http_code"] == "200"))
    def av(lo, hi):
        s = [ok for t, ok in rows if lo <= t < hi]
        return 100.0 * sum(s) / len(s) if s else None
    return dict(whole_run=av(-1e9, 1e9), attack=av(a0, a1), steady=av(a0 + 15, a1))

def boot(v):
    if len(v) < 2 or max(v) == min(v):
        return [round(min(v), 1), round(max(v), 1)]
    rng = random.Random(20261110)
    ms = sorted(sum(rng.choice(v) for _ in v) / len(v) for _ in range(10000))
    return [round(ms[250], 1), round(ms[9749], 1)]

res = {}
for sweep in ("detector_sweep", "legit_sweep"):
    for cell in sorted(glob.glob(os.path.join(ROOT, sweep, "*", "m*")) + glob.glob(os.path.join(ROOT, sweep, "*", "l*"))):
        reps = [rep(r) for r in sorted(glob.glob(os.path.join(cell, "r*"))) if os.path.exists(os.path.join(r, "manifest.json"))]
        if not reps:
            continue
        key = os.path.relpath(cell, ROOT)
        res[key] = {"n": len(reps)}
        for w in ("whole_run", "attack", "steady"):
            v = [r[w] for r in reps if r[w] is not None]
            res[key][w] = round(sum(v) / len(v), 1)
            res[key][w + "_ci95"] = boot(v)
json.dump(res, open(OUT, "w"), indent=1)
for k, v in res.items():
    print("%-40s n=%2d whole %5.1f %-14s attack %5.1f %-14s steady %5.1f %s" % (k, v["n"], v["whole_run"], v["whole_run_ci95"], v["attack"], v["attack_ci95"], v["steady"], v["steady_ci95"]))
