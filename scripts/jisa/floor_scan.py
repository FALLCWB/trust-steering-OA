#!/usr/bin/env python3
"""Scan every run series for the issue-time floor of Eq. 4.

For each series (a folder whose r* subfolders hold manifest.json and latency_*.csv) prints the steady-state
availability by Eq. 4 (issue time in [t_a+15 s, t_e), answered 200) next to the share answered 200 *before the
attack stops* (t_i + time_total < t_e). Where they differ, part of the Eq. 4 value is requests issued during
the attack and answered only after it stopped.
Usage: floor_scan.py ROOT [ROOT...]
"""
import csv, glob, json, os, sys

def series_dirs(root):
    seen = set()
    for m in glob.glob(os.path.join(root, "**", "r*", "manifest.json"), recursive=True):
        seen.add(os.path.dirname(os.path.dirname(m)))
    return sorted(seen)

def run(d):
    m = json.load(open(os.path.join(d, "manifest.json")))
    t0, a0, a1 = m["t0"], m["phases"]["attack_start"], m["phases"]["attack_stop"]
    n = ok = okin = 0
    for f in glob.glob(os.path.join(d, "latency_*.csv")):
        for x in csv.DictReader(open(f)):
            t = float(x["t"]) - t0
            if a0 + 15 <= t < a1:
                n += 1
                s = x["http_code"] == "200"
                ok += s
                okin += s and (t + float(x["time_total"]) < a1)
    return n, ok, okin

for root in sys.argv[1:]:
    for s in series_dirs(root):
        rs = [r for r in glob.glob(os.path.join(s, "r*")) if os.path.exists(os.path.join(r, "manifest.json"))]
        vals = [run(r) for r in rs]
        vals = [v for v in vals if v[0]]
        if not vals:
            continue
        eq2 = sum(100.0 * ok / n for n, ok, _ in vals) / len(vals)
        inw = sum(100.0 * okin / n for n, _, okin in vals) / len(vals)
        flag = "FLOOR" if eq2 - inw > 1.0 else ""
        print("%-70s runs %2d  eq2 %5.1f  answered-before-stop %5.1f  %s" % (os.path.relpath(s, root), len(vals), eq2, inw, flag))
