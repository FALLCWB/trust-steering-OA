#!/usr/bin/env python3
"""
Shared metric definitions for the revision-2 experiments.

Every definition here reproduces exactly the definition already used for the published
figures, so new and old numbers are computed the same way:

  steady_availability(cell)   -- gen_f0.py steady_avail(): fraction of legitimate requests
                                 answered 200, counted from T_SETTLE seconds after attack
                                 onset to attack stop, pooled over the legitimate clients
                                 of one repetition.
  window_availability(cell)   -- analyze.py: same fraction over the whole attack window.
  mean_latency_all(cell)      -- gen_f0b.py cell_lat(): mean completion time over ALL
                                 legitimate requests in the attack window, a failed request
                                 charged at the client timeout (5000 ms).
  mean_latency_ok(cell)       -- analyze.py: mean over the 200 responses only.

The repetition is the unit of analysis: aggregate() takes per-repetition values and
returns mean, 95 % half-width (normal and bootstrap), and n.
"""
import csv
import glob
import json
import os

import numpy as np

T_SETTLE = 15.0     # seconds after attack onset before the steady state is read
CURL_TIMEOUT_MS = 5000.0
Z95 = 1.96


# ---------------------------------------------------------------- per cell --
def _manifest(cell):
    return json.load(open(os.path.join(cell, "manifest.json")))


def _requests(cell, t_from=0.0):
    """Yield (t_since_attack_start, http_code, time_total_ms) inside the attack window."""
    m = _manifest(cell)
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    for f in sorted(glob.glob(os.path.join(cell, "latency_*.csv"))):
        for r in csv.DictReader(open(f)):
            t = float(r["t"]) - t0 - a0
            if t < t_from or t > (a1 - a0):
                continue
            yield t, r["http_code"], float(r["time_total"]) * 1000.0


def steady_availability(cell):
    ok = tot = 0
    for _, code, _ in _requests(cell, T_SETTLE):
        tot += 1
        ok += (code == "200")
    return 100.0 * ok / tot if tot else float("nan")


def window_availability(cell):
    ok = tot = 0
    for _, code, _ in _requests(cell, 0.0):
        tot += 1
        ok += (code == "200")
    return 100.0 * ok / tot if tot else float("nan")


def request_counts(cell, t_from=T_SETTLE):
    ok = tot = 0
    for _, code, _ in _requests(cell, t_from):
        tot += 1
        ok += (code == "200")
    return ok, tot


def mean_latency_all(cell):
    v = [ms if code == "200" else CURL_TIMEOUT_MS for _, code, ms in _requests(cell)]
    return float(np.mean(v)) if v else float("nan")


def mean_latency_ok(cell):
    v = [ms for _, code, ms in _requests(cell) if code == "200"]
    return float(np.mean(v)) if v else float("nan")


def per_client_availability(cell):
    """{client_ip: availability %} over the steady window, for fairness analysis."""
    m = _manifest(cell)
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    out = {}
    for f in sorted(glob.glob(os.path.join(cell, "latency_*.csv"))):
        ip = os.path.basename(f)[len("latency_"):-len(".csv")]
        ok = tot = 0
        for r in csv.DictReader(open(f)):
            t = float(r["t"]) - t0 - a0
            if t < T_SETTLE or t > (a1 - a0):
                continue
            tot += 1
            ok += (r["http_code"] == "200")
        if tot:
            out[ip] = 100.0 * ok / tot
    return out


def tier_delta(cell, tier, field="txpkts"):
    """Packets/bytes delivered by the switch to one tier over the attack window."""
    m = _manifest(cell)
    a0, a1 = m["phases"]["attack_start"], m["phases"]["attack_stop"]
    col = "%s_%s" % (tier, field)
    v = []
    ts_path = os.path.join(cell, "timeseries.csv")
    if not os.path.exists(ts_path):
        return float("nan")
    for r in csv.DictReader(open(ts_path)):
        if r.get(col) in (None, ""):
            continue
        if a0 <= float(r["t"]) < a1:
            v.append(float(r[col]))
    return (v[-1] - v[0]) if len(v) >= 2 else float("nan")


def control_delta(cell, field):
    m = _manifest(cell)
    a0, a1 = m["phases"]["attack_start"], m["phases"]["attack_stop"]
    v = []
    for r in csv.DictReader(open(os.path.join(cell, "timeseries.csv"))):
        if r.get(field) in (None, ""):
            continue
        if a0 <= float(r["t"]) < a1:
            v.append(float(r[field]))
    return (v[-1] - v[0]) if len(v) >= 2 else float("nan")


def tmit(cell, sources):
    """Mean reaction-and-install time for the given source addresses, from the event log."""
    p = os.path.join(cell, "events.jsonl")
    if not os.path.exists(p):
        return float("nan")
    v = []
    for line in open(p):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("src") in sources and e.get("kind") in ("steer", "drop", "resteer_trigger"):
            if e.get("tmit_since_score") is not None:
                v.append(e["tmit_since_score"])
    return float(np.mean(v)) if v else float("nan")


# -------------------------------------------------------------- aggregate --
def bootstrap_ci(vals, n=10000, seed=0):
    a = np.asarray([v for v in vals if v == v], float)
    if a.size < 2:
        return 0.0
    rng = np.random.default_rng(seed)
    means = rng.choice(a, size=(n, a.size), replace=True).mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return float(max(a.mean() - lo, hi - a.mean()))


def aggregate(vals, boot=True, seed=0):
    """-> dict(mean, ci_normal, ci_boot, sd, n, min, max) over repetitions."""
    a = np.asarray([v for v in vals if v == v], float)
    if a.size == 0:
        return dict(mean=float("nan"), ci_normal=float("nan"), ci_boot=float("nan"),
                    sd=float("nan"), n=0, min=float("nan"), max=float("nan"))
    m = float(a.mean())
    sd = float(a.std(ddof=1)) if a.size > 1 else 0.0
    cin = Z95 * sd / np.sqrt(a.size) if a.size > 1 else 0.0
    cib = bootstrap_ci(a, seed=seed) if (boot and a.size > 1) else 0.0
    return dict(mean=m, ci_normal=float(cin), ci_boot=float(cib), sd=sd,
                n=int(a.size), min=float(a.min()), max=float(a.max()))


def clopper_pearson(k, n, alpha=0.05):
    """Exact binomial interval, for collapse rates and other near-degenerate proportions."""
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def cells(pattern):
    return [c for c in sorted(glob.glob(pattern))
            if os.path.exists(os.path.join(c, "manifest.json"))]
