#!/usr/bin/env python3
"""
Spoofing experiments for the revision-2 attack-coverage requirement (Reviewer 3, point 1).

Terminology note. The policy does not classify attack families; it consumes a per-source score
and places the source on a tier. These experiments therefore measure what the per-source
enforcement and its aggregation mechanism do when the source identity is forged, which is the
concern behind "IP spoofing" and "MAC spoofing" for a per-source placement policy.

Three sub-experiments, each ten repetitions, each restarting the topology per repetition:

  --exp ip_inprefix
      A Slowloris source inside a flagged /24 rotates its source address within that /24.
      With subnet aggregation OFF each forged address arrives unscored at the default
      quarantine SvC; with subnet aggregation ON the forged addresses inherit the flagged
      prefix and land on SvL. Measures legitimate availability of a probe client, the tier
      each forged source reaches, and the control-plane state produced.

  --exp ip_random
      A flood spoofs a fresh, fully random source address per packet (hping3 --rand-source).
      Measures the Packet-In rate this induces at the controller, i.e. the control-plane
      saturation case the paper already names, now quantified as an attack in its own right,
      and confirms it is orthogonal to the steering policy (per-source caching cannot form).

  --exp mac_spoof
      A host claims a tier server's IP with its own MAC (gratuitous ARP), the ARP/L2
      integrity case behind "MAC spoofing". Measures whether the controller relearns the
      binding (steering traffic to the attacker) or refuses it (static_server_macs), reading
      the controller's arp_bind_rejected counter and the resulting ip_to_mac binding.

Usage:
  rev2_spoofing.py --exp ip_inprefix --reps 10 --out /opt/trust-lab/data/rev2/spoof_ip_inprefix
  rev2_spoofing.py --exp ip_random   --reps 10 --out /opt/trust-lab/data/rev2/spoof_ip_random
  rev2_spoofing.py --exp mac_spoof   --reps 10 --out /opt/trust-lab/data/rev2/spoof_mac
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
    except Exception as e:
        log("score post failed %s %s" % (ip, e))


def ns_pid(h):
    o = sh("pgrep -f 'mininet:%s$'" % h).stdout.split()
    return o[0] if o else None


def in_ns(pid, args, **kw):
    return subprocess.Popen(["nsenter", "-t", pid, "-n"] + args, **kw)


def ryu_start(cfg, extra_env=""):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s %s ryu-start %s >/dev/null 2>&1" % (extra_env, LABCTL, cfg))
    time.sleep(6)


def topo_restart(nclients, settle=14):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s topo-start %d >/dev/null 2>&1" % (LABCTL, nclients))
    time.sleep(settle)
    sh("curl -s -m4 -X POST %s/trust/reset >/dev/null 2>&1" % REST)
    time.sleep(2)


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


# ------------------------------------------------------------- experiments --
def exp_ip_inprefix(args):
    """Forged source addresses inside a flagged /24, aggregation OFF vs ON."""
    nclients = 4
    for agg in ("off", "on"):
        cfg = H + ("/config/mechanisms.json" if agg == "on" else "/config/steering.json")
        ryu_start(cfg)
        for rep in range(1, args.reps + 1):
            cell = os.path.join(args.out, "agg_%s" % agg, "r%d" % rep)
            if os.path.exists(os.path.join(cell, "result.json")):
                continue
            os.makedirs(cell, exist_ok=True)
            topo_restart(nclients)
            # c1 = legitimate probe (scored benign); c3 = attacker host inside 10.0.9.0/24
            lpid, apid = ns_pid("c1"), ns_pid("c3")
            post_score("10.0.0.11", 0.05)
            # flag the /24 by scoring one address in it malicious
            flagged_prefix_ip = "10.0.9.1"
            post_score(flagged_prefix_ip, 0.95)
            time.sleep(3)
            # attacker sends Slowloris-like connection holds from rotating source addresses
            # inside the flagged /24 (spoofed via hping3 -a), plus fresh probes to be scored
            forged = ["10.0.9.%d" % k for k in range(20, 28)]
            procs = []
            for src in forged:
                # a burst of SYNs to hold connections on whatever tier it reaches
                procs.append(in_ns(apid, ["hping3", "-S", "-p", "80", "-a", src,
                                          "-i", "u2000", "-c", "60", VIP],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            ok, tot = probe(lpid, n=25)
            for p in procs:
                try:
                    p.kill()
                except Exception:
                    pass
            sh("pkill -9 hping3")
            st = rest_get("/trust/stats")
            assigned = st.get("assigned", {})
            forged_tiers = {ip: assigned.get(ip) for ip in forged}
            # how many forged sources reached SvL (isolated) vs SvC (quarantine default)
            n_svl = sum(1 for t in forged_tiers.values() if t == "SvL")
            n_svc = sum(1 for t in forged_tiers.values() if t == "SvC")
            res = dict(exp="ip_inprefix", agg=agg, rep=rep,
                       legit_ok=ok, legit_tot=tot,
                       legit_avail=100.0 * ok / tot if tot else None,
                       forged_seen=sum(1 for t in forged_tiers.values() if t),
                       forged_on_svl=n_svl, forged_on_svc=n_svc,
                       flow_mod=st.get("flow_mod_count"), packet_in=st.get("packet_in_count"),
                       forged_tiers=forged_tiers)
            json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
            log("ip_inprefix agg=%s r=%d legit=%.0f%% forged->SvL=%d/SvC=%d"
                % (agg, rep, res["legit_avail"] or -1, n_svl, n_svc))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


def exp_ip_random(args):
    """Fully random source per packet: control-plane saturation, orthogonal to steering."""
    nclients = 4
    ryu_start(H + "/config/steering.json")
    for rep in range(1, args.reps + 1):
        cell = os.path.join(args.out, "r%d" % rep)
        if os.path.exists(os.path.join(cell, "result.json")):
            continue
        os.makedirs(cell, exist_ok=True)
        topo_restart(nclients)
        lpid, apid = ns_pid("c1"), ns_pid("c3")
        post_score("10.0.0.11", 0.05)
        time.sleep(2)
        # baseline packet-in rate
        st0 = rest_get("/trust/stats")
        p0 = st0.get("packet_in_count", 0)
        t0 = time.time()
        atk = in_ns(apid, ["hping3", "-S", "-p", "80", "--rand-source", "-i", "u1000", VIP],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok, tot = probe(lpid, n=20, interval=0.3)
        dur = time.time() - t0
        st1 = rest_get("/trust/stats")
        try:
            atk.kill()
        except Exception:
            pass
        sh("pkill -9 hping3")
        pin = st1.get("packet_in_count", 0) - p0
        res = dict(exp="ip_random", rep=rep, duration_s=round(dur, 1),
                   packet_in_delta=pin, packet_in_rate=round(pin / dur, 1) if dur else None,
                   flow_mod=st1.get("flow_mod_count"),
                   distinct_scored=len(st1.get("scores", {})),
                   legit_ok=ok, legit_tot=tot,
                   legit_avail=100.0 * ok / tot if tot else None)
        json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
        log("ip_random r=%d PI_rate=%.0f/s scored_srcs=%d legit=%.0f%%"
            % (rep, res["packet_in_rate"] or -1, res["distinct_scored"], res["legit_avail"] or -1))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


def exp_mac_spoof(args):
    """A host claims a server IP with its own MAC (gratuitous ARP); default = binding pinned."""
    nclients = 4
    for pin in ("on", "off"):
        # pin on  -> static_server_macs true (default steering.json)
        # pin off -> explicitly disable the protection to show the vulnerability it closes
        cfg = H + "/config/steering.json"
        env = "" if pin == "on" else "TRUST_STATIC_MACS=0"
        # steering.json has static_server_macs defaulting to true; the off arm patches config
        if pin == "off":
            cfg = _write_nopin_config()
        ryu_start(cfg)
        for rep in range(1, args.reps + 1):
            cell = os.path.join(args.out, "pin_%s" % pin, "r%d" % rep)
            if os.path.exists(os.path.join(cell, "result.json")):
                continue
            os.makedirs(cell, exist_ok=True)
            topo_restart(nclients)
            lpid, apid = ns_pid("c1"), ns_pid("c3")
            post_score("10.0.0.11", 0.05)
            post_score("10.0.0.13", 0.95)
            time.sleep(3)
            target_ip = "10.0.0.201"          # SvH primary
            attacker_mac = "00:00:00:00:01:0d"   # c3 mac (10.0.0.13)
            st_before = rest_get("/trust/stats")
            mac_before = st_before.get("ip_to_mac", {}).get(target_ip)
            rej_before = st_before.get("arp_bind_rejected", 0)
            # attacker forges a gratuitous ARP claiming the SvH IP with its own MAC (scapy,
            # since arping is not present in the emulated hosts). This is the L2 identity
            # forgery behind "MAC spoofing" for a controller that learns IP->MAC from the wire.
            spoof = (
                "from scapy.all import ARP, Ether, sendp\n"
                "sendp(Ether(src='%s', dst='ff:ff:ff:ff:ff:ff')/"
                "ARP(op=2, hwsrc='%s', psrc='%s', pdst='10.0.0.100'),"
                " iface='c3-eth0', count=5, verbose=False)\n"
                % (attacker_mac, attacker_mac, target_ip))
            in_ns(apid, ["/opt/trust-lab/sensor-venv/bin/python", "-c", spoof],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
            time.sleep(2)
            ok, tot = probe(lpid, n=20)
            st_after = rest_get("/trust/stats")
            mac_after = st_after.get("ip_to_mac", {}).get(target_ip)
            rej_after = st_after.get("arp_bind_rejected", 0)
            hijacked = (mac_after == attacker_mac)
            res = dict(exp="mac_spoof", pin=pin, rep=rep,
                       target_ip=target_ip, mac_before=mac_before, mac_after=mac_after,
                       attacker_mac=attacker_mac, binding_hijacked=hijacked,
                       arp_bind_rejected_delta=rej_after - rej_before,
                       legit_ok=ok, legit_tot=tot,
                       legit_avail=100.0 * ok / tot if tot else None)
            json.dump(res, open(os.path.join(cell, "result.json"), "w"), indent=2)
            log("mac_spoof pin=%s r=%d hijacked=%s rej=%d legit=%.0f%%"
                % (pin, rep, hijacked, res["arp_bind_rejected_delta"], res["legit_avail"] or -1))
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)


def _write_nopin_config():
    """Copy steering.json with static_server_macs disabled, for the vulnerable arm."""
    src = json.load(open(H + "/config/steering.json"))
    src["static_server_macs"] = False
    path = H + "/config/steering_nopin.json"
    json.dump(src, open(path, "w"), indent=2)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", required=True,
                    choices=["ip_inprefix", "ip_random", "mac_spoof"])
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    {"ip_inprefix": exp_ip_inprefix,
     "ip_random": exp_ip_random,
     "mac_spoof": exp_mac_spoof}[args.exp](args)
    log("DONE %s" % args.exp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
