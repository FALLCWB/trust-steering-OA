#!/usr/bin/env python3
"""
RQ6 / C4 - asymmetric hysteresis (defence against trust-building attacks). Measures, for a
client, the promotion latency (time to earn SvH after sustained good score) vs the demotion
latency (time to be isolated to SvL after turning malicious). With symmetric behaviour
(baseline gradual, promote_stab_s=0) both are fast, so a short good burst trivially earns
SvH. With asymmetric hysteresis (mechanisms) promotion is slow (must hold good for the
stabilisation window) while demotion stays immediate -> trust-building is defeated.

Run once per controller config (gradual vs mechanisms). Keeps light traffic from the probe
client so tier changes actually install; polls /trust/stats to time SvH/SvL transitions.

Usage: rq6_hysteresis.py --out DIR --label gradual --probe c3 --reps 5
"""
import argparse, csv, json, os, subprocess, threading, time, urllib.request

REST = "http://127.0.0.1:8080"
VIP = "10.0.0.100"


def ns_pid(h):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % h], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def post_score(ip, s):
    d = json.dumps({"ip": ip, "score": s}).encode()
    req = urllib.request.Request(REST + "/trust/score", data=d, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=3).read()


def assigned_tier(ip):
    with urllib.request.urlopen(REST + "/trust/stats", timeout=3) as r:
        return json.load(r).get("assigned", {}).get(ip)


def light_traffic(pid, stop):
    while not stop.is_set():
        subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-o", "/dev/null", "-m", "2",
                        "http://%s/" % VIP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop.wait(0.25)


def wait_tier(ip, target, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if assigned_tier(ip) == target:
            return time.time() - t0
        time.sleep(0.2)
    return float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", required=True, help="controller config label (gradual|mechanisms)")
    ap.add_argument("--probe", default="c3")
    ap.add_argument("--reps", type=int, default=5)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    pid = ns_pid(args.probe)
    ip = "10.0.0.%d" % (11 + int(args.probe[1:]) - 1)
    subprocess.run(["nsenter", "-t", pid, "-n", "ping", "-c1", "-W2", VIP],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    stop = threading.Event()
    th = threading.Thread(target=light_traffic, args=(pid, stop), daemon=True)
    th.start()

    rows = []
    for r in range(args.reps):
        # reset to malicious baseline (SvL), then measure promotion to SvH
        post_score(ip, 0.95); wait_tier(ip, "SvL", 20); time.sleep(1)
        post_score(ip, 0.05)
        promote = wait_tier(ip, "SvH", 20)
        # now malicious: measure demotion to SvL
        time.sleep(1)
        post_score(ip, 0.95)
        demote = wait_tier(ip, "SvL", 20)
        rows.append(dict(rep=r, promote_s=promote, demote_s=demote))
        print("%s rep%d promote=%.2fs demote=%.2fs" % (args.label, r, promote, demote))

    stop.set(); th.join(timeout=3)
    with open(os.path.join(args.out, "rq6_hyst_%s.csv" % args.label), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rep", "promote_s", "demote_s"])
        w.writeheader(); w.writerows(rows)
    import statistics as st
    pr = [x["promote_s"] for x in rows if x["promote_s"] == x["promote_s"]]
    de = [x["demote_s"] for x in rows if x["demote_s"] == x["demote_s"]]
    print("%s: promote mean=%.2fs demote mean=%.2fs" %
          (args.label, st.mean(pr) if pr else -1, st.mean(de) if de else -1))


if __name__ == "__main__":
    main()
