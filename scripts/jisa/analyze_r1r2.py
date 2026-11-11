#!/usr/bin/env python3
"""Numbers of the R1/R2 runs (2026-11-11), on the windows, intervals and collapse rule of analyze_rerun.py.

Usage: analyze_r1r2.py R1R2_ROOT RR_FULL_ROOT OUT_JSON
  R1R2_ROOT     .../rr2611/r1r2-full  (rerun_r1r2.sh)
  RR_FULL_ROOT  .../rr2611/full       (rerun_restart.sh; the live steering series without and with hysteresis)

The functions load, windows, summarize and sensor_stats are taken from analyze_rerun.py unchanged (its code
before the line "res = {}" is executed here), so both files apply the same definitions.
First promotion: the first second of the attack window in which timeseries.csv shows the attacker (10.0.0.13)
assigned to the primary (SvH), in seconds after attack start; None when it never reaches the primary.
Primary share: share of the attack-window seconds with the attacker on SvH. Drop seconds: seconds with the
attacker assigned DROP (drop-only arms).
"""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
R1R2, RR, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(os.path.join(HERE, "analyze_rerun.py")).read().split("\nres = {}\n")[0]
sys.argv = [sys.argv[0], RR, "", OUT]          # analyze_rerun.py reads its three paths when it is loaded
exec(compile(src, os.path.join(HERE, "analyze_rerun.py"), "exec"))


def tiers(run):
    out = []
    for x in csv.DictReader(open(os.path.join(run["dir"], "timeseries.csv"))):
        t = float(x["t"])
        if run["a0"] <= t < run["a1"]:
            a = json.loads(x["assigned"].replace(";", ",")) if x["assigned"] else {}
            out.append((t - run["a0"], a.get(ATT)))
    return out


def promo(run):
    ts = tiers(run)
    first = next((round(t, 1) for t, tier in ts if tier == "SvH"), None)
    n = len(ts) or 1
    return dict(first_promotion_s=first, primary_share=round(sum(tier == "SvH" for _, tier in ts) / n, 2),
                drop_seconds=sum(tier == "DROP" for _, tier in ts))


SERIES = [  # key, root, subdir, label, with sensor stats
    ("live_slowloris", RR, "e2e/slowloris", "steering, live, no hysteresis, Slowloris (re-run)", False),
    ("live_slowpost", RR, "e2e/slowpost", "steering, live, no hysteresis, Slow POST (re-run)", False),
    ("live_slowread", RR, "e2e/slowread", "steering, live, no hysteresis, Slow Read (re-run)", False),
    ("live_hyst_slowloris", RR, "e2e_hyst", "steering, live, hysteresis, Slowloris (re-run)", False),
    ("live_hyst_slowpost", R1R2, "hyst/slowpost", "steering, live, hysteresis, Slow POST", True),
    ("live_hyst_slowread", R1R2, "hyst/slowread", "steering, live, hysteresis, Slow Read", True),
    ("dq_live_slowloris", R1R2, "dq_live/slowloris", "drop-only, live, no hysteresis, Slowloris", True),
    ("dq_live_slowpost", R1R2, "dq_live/slowpost", "drop-only, live, no hysteresis, Slow POST", True),
    ("dq_live_slowread", R1R2, "dq_live/slowread", "drop-only, live, no hysteresis, Slow Read", True),
    ("dq_live_hyst_slowloris", R1R2, "dq_live_hyst/slowloris", "drop-only, live, hysteresis, Slowloris", True),
    ("dq_live_hyst_slowpost", R1R2, "dq_live_hyst/slowpost", "drop-only, live, hysteresis, Slow POST", True),
    ("dq_live_hyst_slowread", R1R2, "dq_live_hyst/slowread", "drop-only, live, hysteresis, Slow Read", True),
    ("reconn_nohyst", R1R2, "reconn_nohyst", "steering, live, no hysteresis, reconnecting Slowloris (-c 6000)", True),
    ("reconn_hyst", R1R2, "reconn_hyst", "steering, live, hysteresis, reconnecting Slowloris (-c 6000)", True),
]

res = {}
for key, root, sub, label, sens in SERIES:
    runs = [load(d) for d in run_dirs(os.path.join(root, sub))]
    if not runs:
        print("MISSING", key)
        continue
    s = summarize(runs, label)
    for row, r in zip(s["runs"], runs):
        row.update(promo(r))
        row["collapsed"] = row["steady_served_before_stop"] == 0
    if sens:
        s["sensor"] = sensor_stats(runs)
    res[key] = s

# promotion timing against collapse, over every live slow-HTTP run (the grouping stated in the text)
groups = {}
for key, s in res.items():
    for row in s["runs"]:
        f = row["first_promotion_s"]
        g = "never" if f is None else ("early (<12 s)" if f < 12 else "late (>=12 s)")
        k = ("reconnecting " if key.startswith("reconn") else "2000-connection ramp ") + g
        d = groups.setdefault(k, dict(runs=0, collapsed=0, first_promotion_s=[]))
        d["runs"] += 1; d["collapsed"] += row["collapsed"]
        if f is not None:
            d["first_promotion_s"].append(f)
for d in groups.values():
    d["first_promotion_s"].sort()
res["_promotion_groups"] = groups

json.dump(res, open(OUT, "w"), indent=1, allow_nan=False)
for k, v in res.items():
    if k.startswith("_"):
        continue
    fp = [r["first_promotion_s"] for r in v["runs"]]
    print("%-24s n=%2d base %s | attack %s %s | steady %s %s | collapse %s %s | first promo %s | drop-s %s" % (
        k, v["n"], v["baseline_mean"], v["attack_mean"], v["attack_ci95"], v["steady_mean"], v["steady_ci95"],
        v["collapse_steady"], v["collapse_steady_cp95"], fp, sum(r["drop_seconds"] for r in v["runs"])))
    if v["baseline_not_clean"]:
        print("    BASELINE NOT CLEAN:", v["baseline_not_clean"])
    if v.get("sensor"):
        print("    sensor:", {x: v["sensor"].get(x) for x in ("windows", "attacker_mean", "p_leak", "crossings_within_runs")})
for k, d in sorted(groups.items()):
    print("%-40s runs %2d collapsed %2d  first promotion %s" % (k, d["runs"], d["collapsed"], d["first_promotion_s"]))
