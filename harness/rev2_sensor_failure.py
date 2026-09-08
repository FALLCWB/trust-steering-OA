#!/usr/bin/env python3
"""
Sensor failure-mode study for the revision-2 single-point-of-failure requirement
(Reviewer 3, point 3).

The reviewer calls the Random Forest sensor a single point of failure. This study performs a
real fault-injection analysis of what happens to the steering policy when the scoring
component misbehaves, and measures the effect of a concrete fail-safe already implemented in
the controller (a score time-to-live that, once a score goes stale, keeps its suspicion but
drops its trust, so an unrefreshed source falls back to the default quarantine tier rather
than being admitted to the primary).

The score channel is the REST interface the sensor posts to; injecting through it reproduces
exactly the input path a real sensor uses, so the controller cannot tell an injected score
from a sensor-produced one. Each scenario runs ten repetitions, restarting the topology per
repetition, under Slowloris (the attack for which the detector matters most).

Scenarios (arm names in output):
  baseline_live      the sensor scores correctly throughout (reference; attacker isolated)
  outage_nottl       the sensor stops posting at attack onset (scores never arrive), TTL off
  outage_ttl         same outage, but the controller's score TTL is enabled (fail-safe)
  stale_nottl        the sensor scored the attacker benign once, then goes silent, TTL off
                     (the dangerous case: a stale benign verdict pins the attacker on SvH)
  stale_ttl          same stale benign verdict, TTL enabled (fail-safe demotes to quarantine)
  poisoned           the sensor is compromised and posts an inverted verdict (attacker benign,
                     clients malicious); measures the blast radius of a fully trusted-but-wrong
                     sensor, which no TTL can fix and which the paper must report honestly

Usage:
  rev2_sensor_failure.py --reps 10 --out /opt/trust-lab/data/rev2/sensor_failure
"""
import argparse
import json
import threading
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
TTL_S = 8.0                # score time-to-live for the fail-safe arms


def sh(cmd, timeout=180):
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


def write_ttl_config(ttl):
    src = json.load(open(H + "/config/steering.json"))
    src["score_ttl_s"] = ttl
    path = H + "/config/steering_ttl.json"
    json.dump(src, open(path, "w"), indent=2)
    return path


def ryu_start(cfg):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-start %s >/dev/null 2>&1" % (LABCTL, cfg))
    time.sleep(6)


def topo_restart(nclients=4, settle=14):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s topo-start %d >/dev/null 2>&1" % (LABCTL, nclients))
    time.sleep(settle)
    sh("curl -s -m4 -X POST %s/trust/reset >/dev/null 2>&1" % REST)
    time.sleep(2)


def measure(lpid, secs=40, interval=0.3):
    """Availability and latency of the probe client over the window and its steady tail."""
    ok = tot = 0
    ok_ss = tot_ss = 0
    lat_ss = []
    t0 = time.time()
    while time.time() - t0 < secs:
        p = subprocess.run(["nsenter", "-t", lpid, "-n", "curl", "-s", "-o", "/dev/null",
                            "-m", "4", "-w", "%{time_total} %{http_code}", "http://%s/" % VIP],
                           capture_output=True, text=True)
        f = p.stdout.split()
        ms = float(f[0]) * 1000.0 if len(f) >= 2 else 4000.0
        good = (len(f) >= 2 and f[1] == "200")
        tot += 1
        ok += good
        if time.time() - t0 >= 15.0:
            tot_ss += 1
            ok_ss += good
            if good:
                lat_ss.append(ms)
        time.sleep(interval)
    med = sorted(lat_ss)[len(lat_ss) // 2] if lat_ss else None
    return (100.0 * ok / tot if tot else None,
            100.0 * ok_ss / tot_ss if tot_ss else None,
            med)


def run_arm(arm, cfg, args, injector):
    ryu_start(cfg)
    for rep in range(1, args.reps + 1):
        cell = os.path.join(args.out, arm, "r%d" % rep)
        if os.path.exists(os.path.join(cell, "result.json")):
            continue
        os.makedirs(cell, exist_ok=True)
        topo_restart()
        lpid, apid = ns_pid("c1"), ns_pid("c3")
        aip = "10.0.0.13"
        # legitimate clients scored benign up front (as in the rest of the paper)
        post_score("10.0.0.11", 0.05)
        post_score("10.0.0.12", 0.05)
        time.sleep(2)
        # start the attack
        atk = in_ns(apid, ["slowhttptest", "-c", "2000", "-H", "-u", "http://%s/" % VIP,
                           "-l", "600", "-r", "200"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # scenario-specific score behaviour runs concurrently with the measurement,
        # since some arms keep re-posting scores across the attack window
        stop = threading.Event()
        th = threading.Thread(target=injector, args=(aip, stop), daemon=True)
        th.start()
        avail_all, avail_ss, med_lat = measure(lpid, secs=40)
        stop.set()
        th.join(timeout=3)
        try:
            atk.kill()
        except Exception:
            pass
        sh("pkill -9 slowhttptest")
        st = rest_get("/trust/stats")
        assigned = st.get("assigned", {})
        res = dict(exp="sensor_failure", arm=arm, rep=rep,
                   attacker_ip=aip, attacker_tier=assigned.get(aip),
                   legit_tier=assigned.get("10.0.0.11"),
                   stale_score_events=st.get("stale_score_events"),
                   legit_avail_window=avail_all, legit_avail_steady=avail_ss,
                   legit_median_lat_ms=med_lat)
        json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
        log("%s r=%d attacker_tier=%s steady=%.0f%%"
            % (arm, rep, res["attacker_tier"], avail_ss if avail_ss is not None else -1))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    steer = H + "/config/steering.json"
    ttl = write_ttl_config(TTL_S)

    # injectors: what the (mis)behaving sensor posts about the attacker
    def live(aip, stop):
        while not stop.is_set():                 # correct malicious verdict, kept fresh
            post_score(aip, 0.95)
            stop.wait(5)

    def outage(aip, stop):
        pass                                     # sensor never posts about the attacker

    def stale_benign(aip, stop):
        post_score(aip, 0.05)                    # one benign verdict, then silence

    def poisoned(aip, stop):
        while not stop.is_set():                 # compromised sensor inverts every verdict
            post_score(aip, 0.05)
            post_score("10.0.0.11", 0.95)
            post_score("10.0.0.12", 0.95)
            stop.wait(5)

    run_arm("baseline_live", steer, args, live)
    run_arm("outage_nottl", steer, args, outage)
    run_arm("outage_ttl", ttl, args, outage)
    run_arm("stale_nottl", steer, args, stale_benign)
    run_arm("stale_ttl", ttl, args, stale_benign)
    run_arm("poisoned", steer, args, poisoned)
    log("DONE sensor_failure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
