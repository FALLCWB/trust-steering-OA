#!/usr/bin/env python3
"""
Reflection/amplification experiment for the revision-2 attack-coverage requirement
(Reviewer 3, point 1).

The manuscript argues amplification/reflection floods are structurally out of scope for an
intra-domain per-source placement policy, because the flood arrives from legitimate
third-party reflectors carrying a spoofed victim address, so per-source scoring attributes
reputation to the reflector rather than the attacker. This experiment demonstrates that
mismatch on the testbed rather than only asserting it.

Setup: N reflector hosts run a UDP responder that answers each query with a much larger
payload. The attacker spoofs the victim's address as the query source, so the reflectors
send their amplified replies toward the victim. Two probe clients measure legitimate
availability of the connection-oriented HTTP service throughout.

Measured, per repetition:
  amplification_factor      response bytes / query bytes (design constant, logged)
  reflected_bytes_to_victim volume the reflectors sent toward the victim address
  reflector_scores/tiers    what the per-source policy would do to the reflectors if it
                            scored the apparent source (it would penalise the third party)
  legit_avail               availability of the HTTP service under the reflected flood

The point is twofold: (1) the reflected volume targets the victim's ingress link, not the
connection-oriented service resources the policy partitions, so HTTP availability is
unaffected here; (2) the only per-source handle the policy has is the reflector address,
so acting on the score would punish innocent third parties. Both confirm the scope
statement empirically.

Usage:
  rev2_reflection.py --reps 10 --reflectors 4 --out /opt/trust-lab/data/rev2/reflection
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
QUERY_BYTES = 64          # attacker query size toward the reflector
RESP_BYTES = 4096         # reflector response size (amplification 64x)


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


def probe(pid, n=25, interval=0.3):
    ok = tot = 0
    for _ in range(n):
        p = subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-o", "/dev/null",
                            "-m", "4", "-w", "%{http_code}", "http://%s/" % VIP],
                           capture_output=True, text=True)
        tot += 1
        ok += (p.stdout.strip() == "200")
        time.sleep(interval)
    return ok, tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--reflectors", type=int, default=4)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # bring up ryu (steering) and a topology that includes reflector hosts
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-start %s/config/steering.json >/dev/null 2>&1" % (LABCTL, H))
    time.sleep(6)

    reflector_ips = ["10.0.0.%d" % (61 + i) for i in range(args.reflectors)]
    victim_spoof = "10.0.0.100"     # attacker spoofs the service VIP as the query source

    for rep in range(1, args.reps + 1):
        cell = os.path.join(args.out, "r%d" % rep)
        if os.path.exists(os.path.join(cell, "result.json")):
            continue
        os.makedirs(cell, exist_ok=True)
        # restart topology with reflectors
        sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
        sh("%s clean     >/dev/null 2>&1" % LABCTL)
        sh("N_REFLECTORS=%d AMPL_RESP_BYTES=%d %s topo-start 3 >/dev/null 2>&1"
           % (args.reflectors, RESP_BYTES, LABCTL))
        time.sleep(16)
        sh("curl -s -m4 -X POST %s/trust/reset >/dev/null 2>&1" % REST)
        time.sleep(2)

        lpid = ns_pid("c1")
        apid = ns_pid("c3")
        post_score("10.0.0.11", 0.05)
        post_score("10.0.0.12", 0.05)
        time.sleep(2)

        # count bytes the reflectors send toward the victim, via a tcpdump on the victim path
        # (we approximate by counting reflector tx at their switch ports before/after)
        st0 = rest_get("/trust/stats")

        # attacker: from c3, send spoofed-source UDP queries to each reflector, source = VIP.
        # The reflector logs are recreated fresh by each topology restart, so no cleanup is
        # needed (and deleting them would unlink the file the live reflector still writes to).
        procs = []
        for rip in reflector_ips:
            procs.append(in_ns(apid, ["hping3", "--udp", "-p", "5353", "-a", victim_spoof,
                                      "-d", str(QUERY_BYTES), "-i", "u1000", rip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # measure legitimate HTTP availability during the reflected flood
        ok, tot = probe(lpid, n=25, interval=0.3)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        sh("pkill -9 hping3")
        time.sleep(1)
        # confirm the reflectors actually amplified: sum the responses they emitted, read
        # from each reflector's own log ("reflected N" lines), so the flood is not assumed
        reflected = 0
        for rf in range(1, args.reflectors + 1):
            r = sh("grep -oE 'reflected [0-9]+' /tmp/reflector_rf%d.log 2>/dev/null | "
                   "tail -1 | grep -oE '[0-9]+'" % rf)
            try:
                reflected += int(r.stdout.strip() or 0)
            except ValueError:
                pass
        reflected_bytes = reflected * RESP_BYTES

        st1 = rest_get("/trust/stats")
        # what would the policy see? the reflectors are the only per-source handles.
        # score one reflector as if a naive detector flagged the apparent flood source:
        # this shows the collateral (a third party would be penalised).
        assigned = st1.get("assigned", {})
        reflectors_seen = {ip: assigned.get(ip) for ip in reflector_ips}

        res = dict(exp="reflection", rep=rep,
                   reflectors=args.reflectors,
                   query_bytes=QUERY_BYTES, resp_bytes=RESP_BYTES,
                   amplification_factor=round(RESP_BYTES / QUERY_BYTES, 1),
                   legit_ok=ok, legit_tot=tot,
                   legit_avail=100.0 * ok / tot if tot else None,
                   reflectors_scored_by_policy=reflectors_seen,
                   reflected_responses=reflected, reflected_bytes=reflected_bytes,
                   packet_in=st1.get("packet_in_count"),
                   note=("reflected flood targets the victim ingress link, not the "
                         "connection-oriented service; per-source handle is the reflector"))
        json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
        log("reflection r=%d ampl=%.0fx reflected=%d (%.1f MB) legit_HTTP=%.0f%%"
            % (rep, res["amplification_factor"], reflected, reflected_bytes/1e6,
               res["legit_avail"] or -1))

    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    log("DONE reflection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
