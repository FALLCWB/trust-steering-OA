#!/usr/bin/env python3
"""
Shrew / low-rate (LDoS) attack experiment with the RIGHT metric: long-flow TCP throughput.
The shrew (Kuzmanovic & Knightly, SIGCOMM 2003) targets TCP's RTO via periodic on-off bursts;
its effect is on sustained TCP flows (throughput collapse), NOT on short HTTP requests. So a
legit client runs a sustained iperf3 transfer to the VIP (steered to SvH) while the attacker
fires shrew bursts. We compare legit throughput, baseline vs attack, for nodefense vs gradual.

Hypothesis: nodefense -> legit iperf3 and shrew share the same server/link -> bursts induce loss
-> TCP throttles -> throughput drops. gradual -> shrew isolated to SvL, legit on SvH -> throughput
preserved. (If the bursts don't induce loss at our link rate, the honest finding is that the shrew
is ineffective in this testbed; it remains a covered taxonomy cell and a usable attack tool.)

Starts iperf3 -s inside each tier server netns (self-contained). Runs once per defense config.
Usage: rq_shrew.py --out DIR --label gradual --legit c1 --attacker c3 --burst 400 --secs 30
"""
import argparse, json, os, re, subprocess, time

VIP = "10.0.0.100"
SERVERS = ["svh", "svc", "svl"]


def ns_pid(h):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % h], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def in_ns(pid, cmd, **kw):
    return subprocess.Popen(["nsenter", "-t", pid, "-n"] + cmd, **kw)


def post_score(ip, s):
    import urllib.request
    d = json.dumps({"ip": ip, "score": s}).encode()
    r = urllib.request.Request("http://127.0.0.1:8080/trust/score", data=d,
                               headers={"Content-Type": "application/json"})
    urllib.request.urlopen(r, timeout=3).read()


def iperf_throughput(pid, secs):
    """Run iperf3 client to the VIP, return receiver Mbit/s (0 on failure)."""
    p = subprocess.run(["nsenter", "-t", pid, "-n", "iperf3", "-c", VIP, "-t", str(secs),
                        "-J"], capture_output=True, text=True)
    try:
        j = json.loads(p.stdout)
        return j["end"]["sum_received"]["bits_per_second"] / 1e6
    except Exception:
        # fallback: parse human output
        m = re.findall(r"([\d.]+)\s+Mbits/sec", p.stdout)
        return float(m[-1]) if m else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--legit", default="c1")
    ap.add_argument("--attacker", default="c3")
    ap.add_argument("--burst", type=int, default=400)
    ap.add_argument("--secs", type=int, default=20)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    lpid = ns_pid(args.legit); apid = ns_pid(args.attacker)
    lip = "10.0.0.%d" % (11 + int(args.legit[1:]) - 1)
    aip = "10.0.0.%d" % (11 + int(args.attacker[1:]) - 1)

    # iperf3 server in each tier netns (the legit flow gets steered to one of them)
    iperf_srvs = []
    for s in SERVERS:
        sp = ns_pid(s)
        if sp:
            iperf_srvs.append(in_ns(sp, ["iperf3", "-s", "-1"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    # oracle: legit trusted, attacker malicious
    post_score(lip, 0.05); post_score(aip, 0.95)
    for h, ip in ((args.legit, lip), (args.attacker, aip)):
        subprocess.run(["nsenter", "-t", ns_pid(h), "-n", "ping", "-c1", "-W2", VIP],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)

    # baseline throughput (no attack)
    base = iperf_throughput(lpid, args.secs)
    # restart iperf3 -s (used -1 one-shot); relaunch for the attack measurement
    for s in SERVERS:
        sp = ns_pid(s)
        if sp:
            in_ns(sp, ["iperf3", "-s", "-1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    # shrew bursts during the attack measurement. start_new_session => own process group so we can
    # kill exactly the loop+hping3 children (NEVER a blanket `pkill bash`, which would also reap the
    # mininet host sentinels in this shared PID namespace and tear down the whole topology).
    shrew = in_ns(apid, ["bash", "-c",
                  "while true; do hping3 -S -p 80 -i u100 -c %d %s >/dev/null 2>&1; sleep 1; done"
                  % (args.burst, VIP)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  start_new_session=True)
    time.sleep(1)
    under = iperf_throughput(lpid, args.secs)
    try:
        os.killpg(os.getpgid(shrew.pid), 9)
    except Exception:
        shrew.kill()
    subprocess.run(["nsenter", "-t", apid, "-n", "pkill", "-9", "-f", "hping3 -S -p 80"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    for p in iperf_srvs:
        p.terminate()

    res = {"label": args.label, "baseline_mbps": round(base, 2), "under_shrew_mbps": round(under, 2),
           "throughput_retained_pct": round(100 * under / base, 1) if base > 0 else None}
    json.dump(res, open(os.path.join(args.out, "shrew_%s.json" % args.label), "w"), indent=2)
    print(res)


if __name__ == "__main__":
    main()
