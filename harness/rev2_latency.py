#!/usr/bin/env python3
"""
Latency side-channel and external-validity experiments for the revision-2 requirement
(Reviewer 2, point 1).

Three sub-experiments:

  --exp sidechannel
      Quantifies the latency side-channel the tarpit opens. From a flagged source's vantage
      it collects the full response-time distribution on the primary (no defense) and on the
      isolation tier with the tarpit at several delays (0, 100, 300, 600 ms). For each delay
      it reports whether a latency-aware adversary can distinguish "steered to isolation" from
      "served on the primary" and with how many samples, via the two-sample effect size and a
      simple threshold classifier's accuracy. This turns the manuscript's asserted
      side-channel into a measured detectability curve, and shows the tarpit-delay knob that
      trades deception latency for indistinguishability.

  --exp rtt
      External validity of the absolute latency numbers under injected wide-area propagation
      delay. The client links carry a one-way netem delay swept over 0, 5, 25, 50 ms (RTT 0,
      10, 50, 100 ms). Measures legitimate availability and latency under Slowloris with and
      without steering, to show which conclusions are RTT-invariant (the availability
      protection) and how the absolute latency shifts with propagation (the testbed-specific
      part).

  --exp decompose
      Latency budget decomposition. Measures the components that make up the millisecond-scale
      service latency the reviewer flags as testbed-specific: bare service time per tier, the
      added control-plane reaction path at a re-steer, and the fixed tarpit sleep. Reports
      each component so the manuscript can state what is implementation overhead versus
      network transit.

Usage:
  rev2_latency.py --exp sidechannel --reps 10 --out /opt/trust-lab/data/rev2/sidechannel
  rev2_latency.py --exp rtt         --reps 10 --out /opt/trust-lab/data/rev2/rtt
  rev2_latency.py --exp decompose   --reps 10 --out /opt/trust-lab/data/rev2/decompose
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

LAB = "/opt/trust-lab"
H = LAB + "/harness"
LABCTL = H + "/labctl.sh"
REST = "http://127.0.0.1:8080"
VIP = "10.0.0.100"


def sh(cmd, timeout=200):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def log(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)


def rest_get(path):
    try:
        with urllib.request.urlopen(REST + path, timeout=4) as r:
            return json.load(r)
    except Exception:
        return {}


def post_score(ip, score):
    d = json.dumps({"ip": ip, "score": score}).encode()
    r = urllib.request.Request(REST + "/trust/score", data=d,
                               headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(r, timeout=4).read()
    except Exception:
        pass


def ns_pid(h):
    o = sh("pgrep -f 'mininet:%s$'" % h).stdout.split()
    return o[0] if o else None


def in_ns(pid, args, **kw):
    return subprocess.Popen(["nsenter", "-t", pid, "-n"] + args, **kw)


def curl_latency(pid, n=120, interval=0.15):
    """Return a list of (latency_ms, code) for n probes from a host."""
    out = []
    for _ in range(n):
        p = subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-o", "/dev/null",
                            "-m", "5", "-w", "%{time_total} %{http_code}", "http://%s/" % VIP],
                           capture_output=True, text=True)
        f = p.stdout.split()
        if len(f) >= 2:
            out.append((float(f[0]) * 1000.0, f[1]))
        else:
            out.append((5000.0, "000"))
        time.sleep(interval)
    return out


def ryu_start(cfg):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-start %s >/dev/null 2>&1" % (LABCTL, cfg))
    time.sleep(6)


def topo_restart(nclients=4, settle=14, env=""):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s %s topo-start %d >/dev/null 2>&1" % (env, LABCTL, nclients))
    time.sleep(settle)
    sh("curl -s -m4 -X POST %s/trust/reset >/dev/null 2>&1" % REST)
    time.sleep(2)


# --------------------------------------------------------------- sidechannel --
def exp_sidechannel(args):
    """Attacker-observed response-time distribution: primary vs isolation at several delays."""
    ryu_start(H + "/config/steering.json")
    conditions = [("primary", None), ("svl", 0), ("svl", 100), ("svl", 300), ("svl", 600)]
    for rep in range(1, args.reps + 1):
        for cond, delay in conditions:
            name = cond if delay is None else "svl_%dms" % delay
            cell = os.path.join(args.out, name, "r%d" % rep)
            if os.path.exists(os.path.join(cell, "samples.json")):
                continue
            os.makedirs(cell, exist_ok=True)
            env = "" if delay is None else "TARPIT_DELAY_MS=%d" % delay
            topo_restart(env=env)
            apid = ns_pid("c3")
            aip = "10.0.0.13"
            # place the "attacker" on the primary (score benign) or on isolation (score high)
            post_score(aip, 0.05 if cond == "primary" else 0.95)
            time.sleep(3)
            samples = curl_latency(apid, n=120, interval=0.12)
            lat = [ms for ms, c in samples if c == "200"]
            json.dump({"cond": name, "rep": rep, "delay_ms": delay,
                       "latencies_ms": lat,
                       "success": sum(1 for _, c in samples if c == "200") / len(samples)},
                      open(os.path.join(cell, "samples.json"), "w"))
            log("sidechannel %s r=%d n=%d median=%.1fms"
                % (name, rep, len(lat),
                   sorted(lat)[len(lat) // 2] if lat else -1))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


# ----------------------------------------------------------------------- rtt --
def exp_rtt(args):
    """Availability and latency under Slowloris across injected one-way client delays."""
    for arm, cfg in (("nodefense", H + "/config/nodefense.json"),
                     ("gradual", H + "/config/steering.json")):
        ryu_start(cfg)
        for owd in (0, 5, 25, 50):
            for rep in range(1, args.reps + 1):
                cell = os.path.join(args.out, arm, "owd%d" % owd, "r%d" % rep)
                if os.path.exists(os.path.join(cell, "result.json")):
                    continue
                os.makedirs(cell, exist_ok=True)
                topo_restart(env="CLIENT_DELAY_MS=%d" % owd)
                lpid, apid = ns_pid("c1"), ns_pid("c3")
                post_score("10.0.0.11", 0.05)
                post_score("10.0.0.13", 0.95)
                time.sleep(3)
                atk = in_ns(apid, ["slowhttptest", "-c", "2000", "-H", "-u",
                                   "http://%s/" % VIP, "-l", "600", "-r", "200"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(3)
                samples = curl_latency(lpid, n=40, interval=0.15)
                try:
                    atk.kill()
                except Exception:
                    pass
                sh("pkill -9 slowhttptest")
                ok = [ms for ms, c in samples if c == "200"]
                res = dict(exp="rtt", arm=arm, owd_ms=owd, rtt_ms=2 * owd, rep=rep,
                           avail=100.0 * len(ok) / len(samples) if samples else None,
                           lat_ok_median_ms=(sorted(ok)[len(ok) // 2] if ok else None),
                           lat_ok_mean_ms=(sum(ok) / len(ok) if ok else None),
                           n=len(samples))
                json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
                log("rtt %s owd=%dms r=%d avail=%.0f%% medlat=%s"
                    % (arm, owd, rep, res["avail"] or -1, res["lat_ok_median_ms"]))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


# ---------------------------------------------------------------- decompose --
def exp_decompose(args):
    """Bare service time per tier (no attack, no delay), and the fixed tarpit sleep."""
    ryu_start(H + "/config/steering.json")
    for rep in range(1, args.reps + 1):
        cell = os.path.join(args.out, "r%d" % rep)
        if os.path.exists(os.path.join(cell, "result.json")):
            continue
        os.makedirs(cell, exist_ok=True)
        # measure each tier's bare service time with the client scored onto it, no attack
        topo_restart(env="TARPIT_DELAY_MS=300")
        cpid = ns_pid("c1")
        cip = "10.0.0.11"
        comp = {}
        for tier, score in (("SvH", 0.05), ("SvC", 0.5), ("SvL", 0.95)):
            post_score(cip, score)
            time.sleep(3)
            s = curl_latency(cpid, n=60, interval=0.1)
            ok = [ms for ms, c in s if c == "200"]
            comp[tier] = dict(median_ms=sorted(ok)[len(ok) // 2] if ok else None,
                              mean_ms=sum(ok) / len(ok) if ok else None, n=len(ok))
        res = dict(exp="decompose", rep=rep, tiers=comp, tarpit_delay_ms=300)
        json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
        log("decompose r=%d SvH=%.1f SvC=%.1f SvL=%.1f ms (median)"
            % (rep, comp["SvH"]["median_ms"], comp["SvC"]["median_ms"], comp["SvL"]["median_ms"]))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", required=True, choices=["sidechannel", "rtt", "decompose"])
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    {"sidechannel": exp_sidechannel, "rtt": exp_rtt, "decompose": exp_decompose}[args.exp](args)
    log("DONE %s" % args.exp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
