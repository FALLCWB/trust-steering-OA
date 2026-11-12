#!/usr/bin/env python3
"""Every number of the re-run (2026-11-10/11), from the raw run folders, on the windows the Methods define.

Usage: analyze_rerun.py RR_ROOT ORIG_ROOT OUT_JSON
  RR_ROOT   .../rr2611/full  (re-run with a fresh topology per repetition)
  ORIG_ROOT .../data         (original data: droponly_q r1-r5 and model_cH2 r1-r3, both already fresh per rep)

Windows (Methods, Eq. 4): baseline [0, attack_start); whole attack window [attack_start, attack_stop);
steady state [attack_start + 15 s, attack_stop). Availability = share of legitimate requests answered 200,
by issue time. A repetition "collapses" when none of the legitimate requests issued in its steady-state window
is answered before the attack stops (under complete denial Eq. 4 still counts each client's last request,
answered once the attack ends, so the steady value sits at a floor of 2/n instead of 0).
Intervals: 95 % percentile bootstrap over repetitions (10^4 resamples, fixed seed) for means; Clopper-Pearson
for collapse counts. Sensor windows: a window belongs to a run when it is posted inside the attack phase or
up to 5 s after it (the window that closes the attack).
"""
import csv
import glob
import json
import math
import os
import random
import re
import sys

RR, ORIG, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
SETTLE, TAU_C = 15.0, 0.4
ATT, LEG = "10.0.0.13", ("10.0.0.11", "10.0.0.12")
random.seed(20261110)


def run_dirs(path):
    ds = [d for d in glob.glob(os.path.join(path, "r*")) if os.path.exists(os.path.join(d, "manifest.json"))]
    return sorted(ds, key=lambda d: int(os.path.basename(d)[1:]))


def load(d):
    m = json.load(open(os.path.join(d, "manifest.json")))
    t0, ph = m["t0"], m["phases"]
    rows = []
    for f in glob.glob(os.path.join(d, "latency_*.csv")):
        for x in csv.DictReader(open(f)):
            rows.append((float(x["t"]) - t0, x["http_code"] == "200", float(x["time_total"])))
    return dict(dir=d, t0=t0, a0=ph["attack_start"], a1=ph["attack_stop"], rows=rows)


def avail(run, lo, hi):
    s = [ok for t, ok, _ in run["rows"] if lo <= t < hi]
    return (100.0 * sum(s) / len(s) if s else float("nan")), len(s)


def windows(run):
    b, nb = avail(run, 0.0, run["a0"])
    a, na = avail(run, run["a0"], run["a1"])
    s, ns = avail(run, run["a0"] + SETTLE, run["a1"])
    # steady-state requests answered 200 before the attack stops (issue time + time_total < t_e)
    served = sum(1 for t, ok, tt in run["rows"] if run["a0"] + SETTLE <= t < run["a1"] and ok and t + tt < run["a1"])
    return dict(baseline=b, attack=a, steady=s, n_baseline=nb, n_attack=na, n_steady=ns, steady_served_before_stop=served)


def boot_ci(v, B=10000):
    v = [x for x in v if x == x]
    if len(v) < 2 or max(v) == min(v):
        return (min(v), max(v)) if v else (float("nan"), float("nan"))
    rng = random.Random(20261110)
    ms = sorted(sum(rng.choice(v) for _ in v) / len(v) for _ in range(B))
    return ms[int(0.025 * B)], ms[int(0.975 * B) - 1]


def betainc_inv(p, a, b):  # inverse regularized incomplete beta by bisection (for Clopper-Pearson)
    def I(x):
        # continued fraction (Numerical Recipes betacf)
        if x <= 0: return 0.0
        if x >= 1: return 1.0
        lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        front = math.exp(lbeta + a * math.log(x) + b * math.log(1 - x))
        def cf(x, a, b):
            qab, qap, qam = a + b, a + 1, a - 1
            c, d = 1.0, 1 - qab * x / qap
            d = 1 / (d if abs(d) > 1e-30 else 1e-30); h = d
            for m in range(1, 300):
                m2 = 2 * m
                aa = m * (b - m) * x / ((qam + m2) * (a + m2))
                d = 1 + aa * d; d = 1 / (d if abs(d) > 1e-30 else 1e-30)
                c = 1 + aa / c if abs(1 + aa / c) > 1e-30 else 1e-30
                h *= d * c
                aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
                d = 1 + aa * d; d = 1 / (d if abs(d) > 1e-30 else 1e-30)
                c = 1 + aa / c if abs(1 + aa / c) > 1e-30 else 1e-30
                h *= d * c
            return h
        return front * cf(x, a, b) / a if x < (a + 1) / (a + b + 2) else 1 - math.exp(lbeta + b * math.log(1 - x) + a * math.log(x)) * cf(1 - x, b, a) / b
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if I(mid) < p: lo = mid
        else: hi = mid
    return (lo + hi) / 2


def clopper(k, n):
    lo = 0.0 if k == 0 else betainc_inv(0.025, k, n - k + 1)
    hi = 1.0 if k == n else betainc_inv(0.975, k + 1, n - k)
    return lo, hi


def summarize(runs, label, expected=10):
    w = [windows(r) for r in runs]
    names = [os.path.basename(r["dir"]) for r in runs]
    nan_runs = [nm for nm, x in zip(names, w) if any(x[k] != x[k] for k in ("baseline", "attack", "steady"))]
    if len(runs) != expected or nan_runs or len(set(names)) != len(names):
        print("CHECK %s: n=%d (expected %d), empty-window runs %s, duplicate names %s"
              % (label, len(runs), expected, nan_runs, len(set(names)) != len(names)))
    out = dict(label=label, n=len(runs), expected=expected, empty_window_runs=nan_runs,
               runs=[dict(run=nm, **{k: (round(v, 1) if isinstance(v, float) and v == v else (None if isinstance(v, float) else v)) for k, v in x.items()}) for nm, x in zip(names, w)])
    for key in ("baseline", "attack", "steady"):
        v = [x[key] for x in w if x[key] == x[key]]
        out[key + "_mean"] = round(sum(v) / len(v), 1) if v else None
        out[key + "_ci95"] = [round(c, 1) for c in boot_ci(v)] if v else None
    # collapse: no legitimate request issued in the steady state is answered before the attack stops
    k = sum(x["steady_served_before_stop"] == 0 for x in w)
    out["collapse_steady"] = "%d/%d" % (k, len(w))
    out["collapse_steady_cp95"] = [round(c, 2) for c in clopper(k, len(w))]
    out["baseline_not_clean"] = [nm for nm, x in zip(names, w) if not (x["baseline"] >= 100)]
    return out


def sensor_stats(runs):
    per_run, legs = {}, []
    for r in runs:
        p = os.path.join(r["dir"], "sensor.log")
        if not os.path.exists(p):
            continue
        for line in open(p):
            m = re.match(r"\s*(\d+\.\d+)\s.*win#\d+.*scored=\{([^}]*)\}", line)
            if not m:
                continue
            ts = float(m.group(1)) - r["t0"]
            if not (r["a0"] <= ts <= r["a1"] + 5.0):
                continue
            sc = {ip: float(v) for ip, v in re.findall(r"'(10\.0\.0\.\d+)':\s*([0-9.]+)", m.group(2))}
            if ATT in sc:
                per_run.setdefault(os.path.basename(r["dir"]), []).append(sc[ATT])
                legs += [sc[k] for k in LEG if k in sc]
    a = [x for v in per_run.values() for x in v]
    if not a:
        return {}
    m = sum(a) / len(a)
    sd = math.sqrt(sum((x - m) ** 2 for x in a) / (len(a) - 1)) if len(a) > 1 else 0.0
    below = sum(x < TAU_C for x in a)
    cross = sum(sum(1 for i in range(1, len(v)) if (v[i - 1] < TAU_C) != (v[i] < TAU_C)) for v in per_run.values())
    return dict(windows=len(a), runs=len(per_run), per_run_windows=sorted(len(v) for v in per_run.values()),
                attacker_mean=round(m, 3), attacker_sd=round(sd, 3), attacker_min=min(a), attacker_max=max(a),
                below_tau_c=below, p_leak=round(below / len(a), 3), crossings_within_runs=cross,
                legit_mean=round(sum(legs) / len(legs), 3) if legs else None, legit_windows=len(legs))


res = {}
for cls in ("slowloris", "slowpost", "slowread", "synflood", "httpflood"):
    runs = [load(d) for d in run_dirs(os.path.join(RR, "e2e", cls))]
    if runs:
        res["live_" + cls] = summarize(runs, "live detector, " + cls)
        if cls == "slowloris":
            res["live_slowloris"]["sensor"] = sensor_stats(runs)
runs = [load(d) for d in run_dirs(os.path.join(RR, "e2e_hyst"))]
if runs:
    res["live_hyst"] = summarize(runs, "live detector + hysteresis, slowloris")
    res["live_hyst"]["sensor"] = sensor_stats(runs)
for arm in ("defprimary", "defquarantine"):
    runs = [load(d) for d in run_dirs(os.path.join(RR, "abl_deftier", arm))]
    if runs:
        res["abl_" + arm] = summarize(runs, "default-tier ablation, " + arm)
runs = [load(d) for d in run_dirs(os.path.join(RR, "nodef_live"))]
if runs:
    res["nodef_live"] = summarize(runs, "no defense, live-run schedule")
KEYS = ("attack", "intensity", "baseline", "attack_dur", "cooldown", "nclients", "score_mode", "legit", "attackers")


def merged(orig_dir, rr_dir, label):
    o = run_dirs(orig_dir); n = run_dirs(rr_dir)
    names_o = {os.path.basename(d) for d in o}; names_n = {os.path.basename(d) for d in n}
    if names_o & names_n:
        sys.exit("merge overlap in %s: %s" % (label, sorted(names_o & names_n)))
    args = {json.dumps({k: json.load(open(os.path.join(d, "manifest.json")))["args"].get(k) for k in KEYS}, sort_keys=True) for d in o + n}
    if len(args) != 1:
        sys.exit("merge settings differ in %s: %s" % (label, args))
    return [load(d) for d in o + n]


for atk in ("slowloris", "slowpost", "slowread"):
    runs = merged(os.path.join(ORIG, "droponly_q", atk), os.path.join(RR, "droponly_q", atk), "droponly_q " + atk)
    if runs:
        res["droponly_q_" + atk] = summarize(runs, "drop-only (quarantine default), " + atk + " (orig r1-5 + re-run r6-10)")
for W in (16, 32, 64):
    runs = merged(os.path.join(ORIG, "model_cH2", "w%d" % W), os.path.join(RR, "model_cH2", "w%d" % W), "model_cH2 w%d" % W)
    if runs:
        res["model_cH2_w%d" % W] = summarize(runs, "provisioning test, SvH workers %d (orig r1-3 + re-run r4-10)" % W)

json.dump(res, open(OUT, "w"), indent=1, allow_nan=False)
for k, v in res.items():
    line = "%-26s n=%2d  baseline %s  attack %s %s  steady %s %s  collapse %s %s" % (
        k, v["n"], v["baseline_mean"], v["attack_mean"], v["attack_ci95"], v["steady_mean"], v["steady_ci95"],
        v["collapse_steady"], v["collapse_steady_cp95"])
    if v["baseline_not_clean"]:
        line += "  BASELINE NOT CLEAN: %s" % v["baseline_not_clean"]
    print(line)
    if v.get("sensor"):
        print("    sensor:", v["sensor"])
