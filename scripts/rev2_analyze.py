#!/usr/bin/env python3
"""
Aggregate every revision-2 experiment into one JSON of verified statistics, and print a
human-readable summary. All aggregation uses the repetition as the unit of analysis and
reports mean, 95 % normal and bootstrap half-widths, and n, matching the paper's protocol.

Run on the VM (has scipy in sensor-venv) or anywhere the data tree is mounted:
  rev2_analyze.py --data /opt/trust-lab/data/rev2 --out rev2_stats.json
"""
import argparse
import glob
import json
import os

import numpy as np

# rev2_lib lives in the harness dir; add it to the path so scale cells can be scored
# with exactly the metric definitions used everywhere else.
import sys as _sys
for _p in ("/opt/trust-lab/harness",
           os.path.join(os.path.dirname(__file__), "..", "harness")):
    if os.path.isdir(_p):
        _sys.path.insert(0, _p)
try:
    import rev2_lib as RL
except Exception:
    RL = None

Z95 = 1.96


def boot_ci(a, n=10000, seed=0):
    a = np.asarray([x for x in a if x is not None and x == x], float)
    if a.size < 2:
        return 0.0
    rng = np.random.default_rng(seed)
    m = rng.choice(a, size=(n, a.size), replace=True).mean(axis=1)
    lo, hi = np.percentile(m, [2.5, 97.5])
    return float(max(a.mean() - lo, hi - a.mean()))


def agg(vals):
    a = np.asarray([x for x in vals if x is not None and x == x], float)
    if a.size == 0:
        return dict(mean=None, ci=None, ci_boot=None, sd=None, n=0, min=None, max=None)
    m = float(a.mean())
    sd = float(a.std(ddof=1)) if a.size > 1 else 0.0
    return dict(mean=round(m, 3),
                ci=round(Z95 * sd / np.sqrt(a.size), 3) if a.size > 1 else 0.0,
                ci_boot=round(boot_ci(a), 3),
                sd=round(sd, 3), n=int(a.size),
                min=round(float(a.min()), 3), max=round(float(a.max()), 3))


def load(pattern):
    return [json.load(open(p)) for p in sorted(glob.glob(pattern))
            if os.path.getsize(p) > 0]


def collapse_rate(vals, thresh=1.0):
    """Fraction of reps at or below `thresh` percent availability (a collapse)."""
    a = [v for v in vals if v is not None]
    if not a:
        return None
    k = sum(1 for v in a if v <= thresh)
    return dict(k=k, n=len(a), rate=round(k / len(a), 3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="/opt/trust-lab/data/rev2")
    ap.add_argument("--out", default="rev2_stats.json")
    args = ap.parse_args()
    D = args.data
    R = {}

    # ---- scale: legit -------------------------------------------------------
    sl = {}
    cfgp = os.path.join(D, "scale_legit", "sweep_config.json")
    if os.path.exists(cfgp):
        cfg = json.load(open(cfgp))
        for arm in cfg["arms"]:
            for lvl in cfg["levels"]:
                cdirs = [os.path.dirname(m) for m in
                         sorted(glob.glob(os.path.join(D, "scale_legit", arm, "L%d" % lvl, "r*", "manifest.json")))]
                if cdirs and RL:
                    sl.setdefault(arm, {})[lvl] = dict(
                        avail=agg([RL.steady_availability(c) for c in cdirs]),
                        lat=agg([RL.mean_latency_all(c) for c in cdirs]),
                        n=len(cdirs))
    R["scale_legit"] = sl

    # ---- scale: legit high-load extension --------------------------------
    slh = {}
    cfgp = os.path.join(D, "scale_legit_hi", "sweep_config.json")
    if os.path.exists(cfgp) and RL:
        cfg = json.load(open(cfgp))
        for arm in cfg["arms"]:
            for lvl in cfg["levels"]:
                cdirs = [os.path.dirname(m) for m in
                         sorted(glob.glob(os.path.join(D, "scale_legit_hi", arm, "L%d" % lvl, "r*", "manifest.json")))]
                if cdirs:
                    slh.setdefault(arm, {})[lvl] = dict(
                        avail=agg([RL.steady_availability(c) for c in cdirs]),
                        lat=agg([RL.mean_latency_all(c) for c in cdirs]),
                        n=len(cdirs))
    R["scale_legit_hi"] = slh

    # ---- scale: threat ------------------------------------------------------
    st = {}
    cfgp = os.path.join(D, "scale_threat", "sweep_config.json")
    if os.path.exists(cfgp):
        cfg = json.load(open(cfgp))
        for arm in cfg["arms"]:
            for lvl in cfg["levels"]:
                cdirs = [os.path.dirname(m) for m in
                         sorted(glob.glob(os.path.join(D, "scale_threat", arm, "L%d" % lvl, "r*", "manifest.json")))]
                if cdirs and RL:
                    av = [RL.steady_availability(c) for c in cdirs]
                    st.setdefault(arm, {})[lvl] = dict(
                        avail=agg(av), collapse=collapse_rate(av), n=len(cdirs))
    R["scale_threat"] = st

    # ---- spoofing: ip in-prefix --------------------------------------------
    ipf = {}
    for aggm in ("off", "on"):
        cells = load(os.path.join(D, "spoof_ip_inprefix", "agg_%s" % aggm, "r*", "result.json"))
        if cells:
            ipf[aggm] = dict(
                legit_avail=agg([c["legit_avail"] for c in cells]),
                forged_on_svl=agg([c["forged_on_svl"] for c in cells]),
                forged_on_svc=agg([c["forged_on_svc"] for c in cells]),
                n=len(cells))
    R["spoof_ip_inprefix"] = ipf

    # ---- spoofing: random source -------------------------------------------
    cells = load(os.path.join(D, "spoof_ip_random", "r*", "result.json"))
    if cells:
        R["spoof_ip_random"] = dict(
            packet_in_rate=agg([c["packet_in_rate"] for c in cells]),
            distinct_scored=agg([c["distinct_scored"] for c in cells]),
            legit_avail=agg([c["legit_avail"] for c in cells]),
            n=len(cells))

    # ---- spoofing: mac ------------------------------------------------------
    mac = {}
    for pin in ("on", "off"):
        cells = load(os.path.join(D, "spoof_mac", "pin_%s" % pin, "r*", "result.json"))
        if cells:
            mac[pin] = dict(
                hijacked=collapse_rate([100.0 if c["binding_hijacked"] else 0.0 for c in cells], thresh=0.0),
                hijacked_count=sum(1 for c in cells if c["binding_hijacked"]),
                rej=agg([c["arp_bind_rejected_delta"] for c in cells]),
                legit_avail=agg([c["legit_avail"] for c in cells]),
                n=len(cells))
    R["spoof_mac"] = mac

    # ---- reflection ---------------------------------------------------------
    cells = load(os.path.join(D, "reflection", "r*", "result.json"))
    if cells:
        R["reflection"] = dict(
            amplification=cells[0]["amplification_factor"],
            legit_http_avail=agg([c["legit_avail"] for c in cells]),
            n=len(cells))

    # ---- sensor failure -----------------------------------------------------
    sf = {}
    for arm in ("baseline_live", "outage_nottl", "outage_ttl",
                "stale_nottl", "stale_ttl", "poisoned"):
        cells = load(os.path.join(D, "sensor_failure", arm, "r*", "result.json"))
        if cells:
            av = [c["legit_avail_steady"] for c in cells]
            sf[arm] = dict(
                avail=agg(av), collapse=collapse_rate(av),
                median_lat=agg([c.get("legit_median_lat_ms") for c in cells]),
                attacker_tier_mode=_mode([c["attacker_tier"] for c in cells]),
                legit_tier_mode=_mode([c.get("legit_tier") for c in cells]),
                n=len(cells))
    R["sensor_failure"] = sf

    # ---- side-channel -------------------------------------------------------
    sc = {}
    for cond in ("primary", "svl_0ms", "svl_100ms", "svl_300ms", "svl_600ms"):
        cells = load(os.path.join(D, "sidechannel", cond, "r*", "samples.json"))
        if cells:
            meds = [np.median(c["latencies_ms"]) for c in cells if c["latencies_ms"]]
            alllat = np.concatenate([np.asarray(c["latencies_ms"]) for c in cells if c["latencies_ms"]])
            sc[cond] = dict(median_ms=agg(meds),
                            pooled_median=round(float(np.median(alllat)), 2),
                            pooled_p10=round(float(np.percentile(alllat, 10)), 2),
                            pooled_p90=round(float(np.percentile(alllat, 90)), 2),
                            n_reps=len(cells))
    # distinguishability: nearest-threshold classifier accuracy, primary vs each svl
    if "primary" in sc:
        prim = np.concatenate([np.asarray(json.load(open(p))["latencies_ms"])
                               for p in glob.glob(os.path.join(D, "sidechannel", "primary", "r*", "samples.json"))])
        for cond in ("svl_0ms", "svl_100ms", "svl_300ms", "svl_600ms"):
            ps = glob.glob(os.path.join(D, "sidechannel", cond, "r*", "samples.json"))
            if not ps:
                continue
            svl = np.concatenate([np.asarray(json.load(open(p))["latencies_ms"]) for p in ps])
            # best single threshold accuracy (balanced): midpoint of the two medians
            thr = (np.median(prim) + np.median(svl)) / 2
            acc = (np.mean(prim < thr) + np.mean(svl >= thr)) / 2
            sc[cond]["distinguish_acc_vs_primary"] = round(float(acc), 4)
    R["sidechannel"] = sc

    # ---- rtt ----------------------------------------------------------------
    rtt = {}
    for arm in ("nodefense", "gradual"):
        for owd in (0, 5, 25, 50):
            cells = load(os.path.join(D, "rtt", arm, "owd%d" % owd, "r*", "result.json"))
            if cells:
                rtt.setdefault(arm, {})[2 * owd] = dict(
                    avail=agg([c["avail"] for c in cells]),
                    median_lat=agg([c["lat_ok_median_ms"] for c in cells]),
                    n=len(cells))
    R["rtt"] = rtt

    # ---- decompose ----------------------------------------------------------
    cells = load(os.path.join(D, "decompose", "r*", "result.json"))
    if cells:
        R["decompose"] = {tier: agg([c["tiers"][tier]["median_ms"] for c in cells])
                          for tier in ("SvH", "SvC", "SvL")}
        R["decompose"]["n"] = len(cells)

    json.dump(R, open(args.out, "w"), indent=2)
    print(json.dumps(R, indent=2))
    print("\nwrote", args.out)


def _mode(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return max(set(xs), key=xs.count)


if __name__ == "__main__":
    main()
