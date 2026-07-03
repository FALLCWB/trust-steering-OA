#!/usr/bin/env python3
"""
Deception measurement. Deception = the attacker BELIEVES it is succeeding. It is observable as the
"success signal" the attacker receives: under elastic defense the attacker is steered to SvL, which
RESPONDS (slow/degraded but alive) -> the attacker sees apparent success and keeps wasting effort;
under drop the attacker gets nothing -> it KNOWS it is blocked and would adapt/pivot.

This script measures, from the ATTACKER's vantage, its own request success-rate and latency (the
deception signal) AND, in parallel, a legitimate client's success-rate (primary protection). Run
once per controller config (elastic/drop/nodefense); the caller sets the ryu config beforehand.

Metrics (per run):
  attacker_success_rate  fraction of attacker probes that got HTTP 200 (high = deceived)
  attacker_lat_ms        attacker-observed latency (looks-overloaded-but-alive if elastic+tarpit)
  attacker_detect_s      time until K consecutive failures (= attacker concludes mitigated); None if never
  legit_success_rate     primary protection (legit availability during the attack)

Usage: rq_deception.py --out DIR --label elastic --attacker c3 --legit c1 --secs 30
"""
import argparse, csv, json, os, subprocess, threading, time, urllib.request

VIP = "10.0.0.100"


def ns_pid(h):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % h], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def post_score(ip, s):
    d = json.dumps({"ip": ip, "score": s}).encode()
    r = urllib.request.Request("http://127.0.0.1:8080/trust/score", data=d,
                               headers={"Content-Type": "application/json"})
    urllib.request.urlopen(r, timeout=3).read()


def probe(pid):
    """One HTTP request from a host; return (latency_ms, code)."""
    p = subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-o", "/dev/null", "-m", "4",
                        "-w", "%{time_total} %{http_code}", "http://%s/" % VIP],
                       capture_output=True, text=True)
    o = p.stdout.split()
    return (float(o[0]) * 1000, o[1]) if len(o) >= 2 else (4000.0, "000")


def loop(pid, out_list, stop, interval=0.2):
    while not stop.is_set():
        out_list.append((time.time(), *probe(pid)))
        stop.wait(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--attacker", default="c3")
    ap.add_argument("--legit", default="c1")
    ap.add_argument("--secs", type=float, default=30)
    ap.add_argument("--detect-k", type=int, default=5, help="consecutive failures = detected mitigation")
    ap.add_argument("--bg-intensity", type=int, default=0,
                    help="background HTTP flood concurrency from the attacker (loads SvL; for tarpit test)")
    ap.add_argument("--rep", type=int, default=0)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    apid = ns_pid(args.attacker); lpid = ns_pid(args.legit)
    aip = "10.0.0.%d" % (11 + int(args.attacker[1:]) - 1)
    lip = "10.0.0.%d" % (11 + int(args.legit[1:]) - 1)

    # warm + score: attacker malicious, legit trusted
    for pid in (apid, lpid):
        subprocess.run(["nsenter", "-t", pid, "-n", "ping", "-c1", "-W2", VIP],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    post_score(lip, 0.05); post_score(aip, 0.95)
    time.sleep(3)  # let steering settle

    # optional background flood from the attacker (loads its tier; used for the tarpit ramp)
    bg = None
    if args.bg_intensity > 0:
        bg = subprocess.Popen(["nsenter", "-t", apid, "-n", "ab", "-t", str(int(args.secs) + 5),
                               "-n", "100000000", "-c", str(args.bg_intensity), "http://%s/" % VIP],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    atk, leg = [], []
    stop = threading.Event()
    ta = threading.Thread(target=loop, args=(apid, atk, stop), daemon=True)
    tl = threading.Thread(target=loop, args=(lpid, leg, stop), daemon=True)
    t0 = time.time(); ta.start(); tl.start()
    time.sleep(args.secs)
    stop.set(); ta.join(timeout=5); tl.join(timeout=5)
    if bg:
        bg.terminate()
        subprocess.run(["pkill", "-9", "ab"], stderr=subprocess.DEVNULL)

    def succ(rows):
        return sum(1 for r in rows if r[2] == "200") / len(rows) if rows else float("nan")
    def avglat(rows):
        v = [r[1] for r in rows if r[2] == "200"]
        return sum(v) / len(v) if v else float("nan")
    # time-to-detect: first window of K consecutive non-200 in attacker probes
    detect = None; run = 0
    for r in atk:
        if r[2] != "200":
            run += 1
            if run >= args.detect_k:
                detect = round(r[0] - t0, 2); break
        else:
            run = 0

    res = dict(label=args.label, rep=args.rep,
               attacker_success_rate=round(succ(atk), 3), attacker_lat_ms=round(avglat(atk), 1),
               attacker_detect_s=detect, attacker_probes=len(atk),
               legit_success_rate=round(succ(leg), 3), legit_lat_ms=round(avglat(leg), 1))
    # raw attacker signal over time (for indistinguishability analysis)
    with open(os.path.join(args.out, "attacker_signal_%s_r%d.csv" % (args.label, args.rep)), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["t", "lat_ms", "code"])
        for r in atk:
            w.writerow([round(r[0] - t0, 2), round(r[1], 1), r[2]])
    json.dump(res, open(os.path.join(args.out, "deception_%s_r%d.json" % (args.label, args.rep)), "w"), indent=2)
    print(res)


if __name__ == "__main__":
    main()
