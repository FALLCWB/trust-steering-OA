#!/usr/bin/env python3
"""
RQ3 - threshold sensitivity. Characterises the trade-off between false positives trapped
in the isolation tier (SvL) and malicious traffic escaping to better tiers, as the SvL
threshold tau_l is swept.

A population of N clients is given evenly-spaced ground-truth malicious scores in [lo, hi].
Clients with true score >= 0.5 are "malicious" (ground truth). For each tau_l on a grid the
controller's threshold is live-updated, flows re-steer, and we record, per client, the tier
it lands in plus its HTTP latency (one attacker floods SvL so trapped FPs feel real cost).

Outputs CSV: tau_l, fp_in_svl, mal_escaped, fp_rate, escape_rate, mean_fp_latency_ms.

Assumes trust-ryu (gradual config) + trust-topo (>=N+1 clients) are up.
"""
import argparse, csv, json, os, subprocess, time, urllib.request

REST = "http://127.0.0.1:8080"
VIP = "10.0.0.100"


def ns_pid(host):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % host], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def post(path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(REST + path, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=3).read()


def stats():
    with urllib.request.urlopen(REST + "/trust/stats", timeout=3) as r:
        return json.load(r)


def curl(pid):
    p = subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-o", "/dev/null",
                        "-m", "5", "-w", "%{time_total} %{http_code}", "http://%s/" % VIP],
                       capture_output=True, text=True)
    out = p.stdout.split()
    return (float(out[0]) * 1000, out[1]) if len(out) >= 2 else (5000.0, "000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--lo", type=float, default=0.05)
    ap.add_argument("--hi", type=float, default=0.95)
    ap.add_argument("--taus", default="0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9")
    ap.add_argument("--attacker", default="c11", help="floods to load SvL")
    ap.add_argument("--samples", type=int, default=8)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    taus = [float(x) for x in args.taus.split(",")]

    hosts = ["c%d" % i for i in range(1, args.clients + 1)]
    pids = {h: ns_pid(h) for h in hosts}
    ips = {h: "10.0.0.%d" % (11 + i) for i, h in enumerate(hosts)}
    true = {h: args.lo + (args.hi - args.lo) * i / (args.clients - 1) for i, h in enumerate(hosts)}

    # warm ARP + assign ground-truth scores
    for h in hosts:
        subprocess.run(["nsenter", "-t", pids[h], "-n", "ping", "-c1", "-W2", VIP],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        post("/trust/score", {"ip": ips[h], "score": true[h]})
    # start an attacker to load SvL so trapped FPs feel cost
    apid = ns_pid(args.attacker)
    aproc = None
    if apid:
        post("/trust/score", {"ip": "10.0.0.%d" % (11 + args.clients), "score": 0.99})
        aproc = subprocess.Popen(["nsenter", "-t", apid, "-n", "hping3", "-S", "-p", "80",
                                  "--flood", VIP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    rows = []
    for tau in taus:
        post("/trust/config", {"tau_l": tau, "tau_c": min(tau, 0.2)})
        time.sleep(3)  # let re-steer settle
        # generate light traffic so every client has an installed flow / latency sample
        lat = {h: [] for h in hosts}
        for _ in range(args.samples):
            for h in hosts:
                t, code = curl(pids[h])
                lat[h].append((t, code))
        asg = stats().get("assigned", {})
        fp_in_svl = mal_escaped = 0
        n_legit = sum(1 for h in hosts if true[h] < 0.5)
        n_mal = sum(1 for h in hosts if true[h] >= 0.5)
        fp_lat = []
        for h in hosts:
            tier = asg.get(ips[h], "?")
            if true[h] < 0.5 and tier == "SvL":
                fp_in_svl += 1
                fp_lat += [x[0] for x in lat[h] if x[1] == "200"]
            if true[h] >= 0.5 and tier != "SvL":
                mal_escaped += 1
        row = dict(tau_l=tau, fp_in_svl=fp_in_svl, mal_escaped=mal_escaped,
                   fp_rate=fp_in_svl / n_legit if n_legit else 0,
                   escape_rate=mal_escaped / n_mal if n_mal else 0,
                   mean_fp_latency_ms=(sum(fp_lat) / len(fp_lat)) if fp_lat else "")
        rows.append(row)
        print("tau_l=%.2f fp_in_svl=%d mal_escaped=%d fp_rate=%.2f escape_rate=%.2f"
              % (tau, fp_in_svl, mal_escaped, row["fp_rate"], row["escape_rate"]))

    if aproc:
        aproc.terminate()
        subprocess.run(["pkill", "-9", "hping3"], stderr=subprocess.DEVNULL)
    with open(os.path.join(args.out, "rq3.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    json.dump({"true_scores": {ips[h]: true[h] for h in hosts}}, open(os.path.join(args.out, "meta.json"), "w"))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
