#!/usr/bin/env python3
"""
Run one experiment cell on Platform A and collect metrics. Runs in the root namespace
on the experiment VM; enters client network namespaces with nsenter to drive traffic.

Assumes trust-ryu + trust-topo are up (labctl). A cell = (defense, attack, intensity,
score-mode, repetition). Phases: baseline (legit only) -> attack -> cease. Collects:
  - timeseries.csv : per-second controller stats (packet_in, flow_mod) + per-tier port
                     load (rx/tx pkts/bytes from OVS) + per-client assigned tier
  - latency_<ip>.csv : per-request HTTP latency for each legit client (time_total, code)
  - events.jsonl   : copy of the controller event log slice (Tmit decomposition)
  - manifest.json  : full config + timestamps + git-less provenance

Score modes:
  oracle : POST ground-truth scores (attackers -> --mal-score, legit -> --legit-score)
           at attack start. Isolates steering characterisation from detector noise.
  rf     : rely on the running trust-sensor (RF) to score; runner posts nothing.
  none   : post nothing (no-defense / drop baselines may ignore scores).

Defense is recorded for analysis; the controller behaviour itself is selected by its own
config/flags (baselines handled by variant configs). This runner is defense-agnostic.
"""
import argparse, json, os, signal, subprocess, threading, time
import urllib.request

ROOT = "/opt/trust-lab"
# tier -> switch iface, read from the authoritative portmap the topology writes at startup.
SERVER_PORTS = {}


def discover_server_ports():
    pm = os.path.join(ROOT, "runs", "portmap.json")
    if os.path.exists(pm):
        m = json.load(open(pm))
        return {t: m[t] for t in ("SvH", "SvC", "SvL") if t in m}
    return {}


def now():
    return time.time()


def ns_pid(host):
    out = subprocess.run(["pgrep", "-f", "mininet:%s$" % host],
                         capture_output=True, text=True).stdout.split()
    return out[0] if out else None


def in_ns(pid, cmd, **kw):
    return subprocess.Popen(["nsenter", "-t", pid, "-n"] + cmd, **kw)


def rest_get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.load(r)
    except Exception:
        return {}


def rest_post_score(rest, ip, score):
    data = json.dumps({"ip": ip, "score": score}).encode()
    req = urllib.request.Request(rest + "/trust/score", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:
        print("score post failed", ip, e)


def ovs_port_counters():
    """Return {iface: (rx_pkts, tx_pkts, rx_bytes, tx_bytes)} for server ports."""
    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports", "s1"],
                         capture_output=True, text=True).stdout
    res = {}
    cur = None
    # map port-no -> iface once
    show = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "show", "s1"],
                          capture_output=True, text=True).stdout
    p2i = {}
    for line in show.splitlines():
        line = line.strip()
        if "(" in line and "):" in line and line[0].isdigit():
            pno = line.split("(")[0].strip()
            iface = line.split("(")[1].split(")")[0]
            p2i[pno] = iface
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("port"):
            pno = line.split("port")[1].split(":")[0].strip().lstrip('"').rstrip('"')
            cur = p2i.get(pno)
            if cur:
                res.setdefault(cur, [0, 0, 0, 0])
            # rx line may be on same or next line
        if cur and "rx pkts=" in line:
            try:
                rxp = line.split("rx pkts=")[1].split(",")[0]
                rxb = line.split("bytes=")[1].split(",")[0]
                res[cur][0] = int(rxp) if rxp != "?" else 0
                res[cur][2] = int(rxb) if rxb != "?" else 0
            except Exception:
                pass
        if cur and "tx pkts=" in line:
            try:
                txp = line.split("tx pkts=")[1].split(",")[0]
                txb = line.split("bytes=")[1].split(",")[0]
                res[cur][1] = int(txp) if txp != "?" else 0
                res[cur][3] = int(txb) if txb != "?" else 0
            except Exception:
                pass
    return res


class Poller(threading.Thread):
    def __init__(self, rest, outdir, t0):
        super().__init__(daemon=True)
        self.rest, self.outdir, self.t0 = rest, outdir, t0
        self.stop = threading.Event()

    def run(self):
        f = open(os.path.join(self.outdir, "timeseries.csv"), "w")
        f.write("t,packet_in,flow_mod," +
                ",".join("%s_rxpkts,%s_txpkts,%s_rxbytes,%s_txbytes" % (t, t, t, t)
                         for t in SERVER_PORTS) +
                ",assigned\n")
        while not self.stop.is_set():
            t = round(now() - self.t0, 2)
            st = rest_get(self.rest + "/trust/stats")
            ctr = ovs_port_counters()
            row = [t, st.get("packet_in_count", ""), st.get("flow_mod_count", "")]
            for tier, iface in SERVER_PORTS.items():
                c = ctr.get(iface, [0, 0, 0, 0])
                row += c
            row.append(json.dumps(st.get("assigned", {})).replace(",", ";"))
            f.write(",".join(map(str, row)) + "\n")
            f.flush()
            self.stop.wait(1.0)
        f.close()


def legit_loop(pid, vip, ip, outdir, stop):
    f = open(os.path.join(outdir, "latency_%s.csv" % ip), "w")
    f.write("t,time_total,http_code\n")
    while not stop.is_set():
        t = now()
        p = in_ns(pid, ["curl", "-s", "-o", "/dev/null", "-m", "5",
                        "-w", "%{time_total} %{http_code}", "http://%s/" % vip],
                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out = p.communicate()[0].decode().strip().split()
        tt = out[0] if out else "5.0"
        code = out[1] if len(out) > 1 else "000"
        f.write("%.3f,%s,%s\n" % (t, tt, code))
        f.flush()
        stop.wait(0.3)
    f.close()


def start_attack(pid, atype, intensity, vip):
    if atype == "synflood":
        # intensity = pps approx via interval; --flood ignores rate, so use -i for control
        if intensity >= 100000:
            cmd = ["hping3", "-S", "-p", "80", "--flood", vip]
        else:
            us = max(1, int(1_000_000 / intensity))
            cmd = ["hping3", "-S", "-p", "80", "-i", "u%d" % us, vip]
    elif atype == "udpflood":
        us = max(1, int(1_000_000 / intensity))
        cmd = ["hping3", "--udp", "-p", "80", "-i", "u%d" % us, vip]
    elif atype == "icmpflood":
        us = max(1, int(1_000_000 / intensity))
        cmd = ["hping3", "-1", "-i", "u%d" % us, vip]
    elif atype == "slowloris":   # slow request headers (app-layer slow; worker pool)
        cmd = ["slowhttptest", "-c", str(intensity), "-H", "-u", "http://%s/" % vip,
               "-l", "600", "-r", "200"]
    elif atype == "slowpost":    # RUDY: slow request body (app-layer slow; worker pool)
        cmd = ["slowhttptest", "-c", str(intensity), "-B", "-u", "http://%s/" % vip,
               "-l", "600", "-r", "200", "-s", "8192"]
    elif atype == "slowread":    # slow response read via small recv window (worker pool)
        cmd = ["slowhttptest", "-c", str(intensity), "-X", "-u", "http://%s/" % vip,
               "-l", "600", "-r", "200", "-k", "3", "-n", "2", "-w", "512", "-y", "1024"]
    elif atype == "httpflood":   # application-layer high-rate GET flood (worker pool, valid reqs)
        cmd = ["ab", "-t", "600", "-n", "100000000", "-c", str(intensity),
               "http://%s/" % vip]
    elif atype == "shrew":       # low-rate / shrew LDoS: periodic on-off SYN bursts (TCP RTO)
        burst = max(50, intensity)
        cmd = ["bash", "-c",
               "while true; do hping3 -S -p 80 -i u200 -c %d %s >/dev/null 2>&1; sleep 1; done"
               % (burst, vip)]
    else:
        raise SystemExit("unknown attack %s" % atype)
    return in_ns(pid, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--defense", default="gradual")
    ap.add_argument("--attack", default="synflood")
    ap.add_argument("--intensity", type=int, default=2000)
    ap.add_argument("--legit", default="c1,c3")
    ap.add_argument("--attackers", default="c2")
    ap.add_argument("--baseline", type=float, default=10)
    ap.add_argument("--attack-dur", type=float, default=30)
    ap.add_argument("--cooldown", type=float, default=5)
    ap.add_argument("--score-mode", default="oracle", choices=["oracle", "rf", "none"])
    ap.add_argument("--mal-score", type=float, default=0.9)
    ap.add_argument("--legit-score", type=float, default=0.1)
    ap.add_argument("--vip", default="10.0.0.100")
    ap.add_argument("--rest", default="http://127.0.0.1:8080")
    ap.add_argument("--rep", type=int, default=0)
    ap.add_argument("--nclients", type=int, default=0,
                    help="total clients in topo (for server port mapping); 0=auto")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    global SERVER_PORTS
    SERVER_PORTS = discover_server_ports()
    if len(SERVER_PORTS) != 3:
        print("WARN: could not map all server ports via FDB:", SERVER_PORTS)

    legit = [h for h in args.legit.split(",") if h]
    attackers = [h for h in args.attackers.split(",") if h]
    pids = {h: ns_pid(h) for h in legit + attackers}
    ips = {h: "10.0.0.%d" % (11 + int(h[1:]) - 1) for h in legit + attackers}
    missing = [h for h, p in pids.items() if p is None]
    if missing:
        raise SystemExit("hosts not found: %s" % missing)

    # record event-log offset so we copy only THIS run's controller events
    ev_src = os.path.join(ROOT, "runs", "controller_events.jsonl")
    ev_offset = sum(1 for _ in open(ev_src)) if os.path.exists(ev_src) else 0

    t0 = now()
    manifest = {"args": vars(args), "ips": ips, "t0": t0, "phases": {}}
    poller = Poller(args.rest, args.out, t0)
    poller.start()

    stop_legit = threading.Event()
    threads = []
    for h in legit:
        th = threading.Thread(target=legit_loop,
                              args=(pids[h], args.vip, ips[h], args.out, stop_legit),
                              daemon=True)
        th.start(); threads.append(th)

    # warm-up ARP so the first requests are not lost
    for h in legit + attackers:
        in_ns(pids[h], ["ping", "-c1", "-W2", args.vip],
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()

    # known-good clients settle on SvH during baseline (scored before the attack)
    if args.score_mode == "oracle":
        for h in legit:
            rest_post_score(args.rest, ips[h], args.legit_score)
    print("[run] baseline %ss" % args.baseline); manifest["phases"]["baseline_start"] = now() - t0
    time.sleep(args.baseline)

    # attack phase: attackers get flagged now (measures mitigation from here)
    manifest["phases"]["attack_start"] = now() - t0
    if args.score_mode == "oracle":
        for h in attackers:
            rest_post_score(args.rest, ips[h], args.mal_score)
    print("[run] attack %s intensity=%d for %ss" % (args.attack, args.intensity, args.attack_dur))
    aprocs = [start_attack(pids[h], args.attack, args.intensity, args.vip) for h in attackers]
    time.sleep(args.attack_dur)

    # cease
    manifest["phases"]["attack_stop"] = now() - t0
    for p in aprocs:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    for tool in ("hping3", "slowhttptest", "ab"):
        subprocess.run(["pkill", "-9", tool], stderr=subprocess.DEVNULL)
    print("[run] cooldown %ss" % args.cooldown)
    time.sleep(args.cooldown)

    stop_legit.set()
    for th in threads:
        th.join(timeout=5)
    poller.stop.set()
    poller.join(timeout=5)
    manifest["phases"]["end"] = now() - t0

    # snapshot only THIS run's controller events (from recorded offset)
    if os.path.exists(ev_src):
        lines = open(ev_src).read().splitlines()
        open(os.path.join(args.out, "events.jsonl"), "w").write("\n".join(lines[ev_offset:]))
    manifest["final_stats"] = rest_get(args.rest + "/trust/stats")
    json.dump(manifest, open(os.path.join(args.out, "manifest.json"), "w"), indent=2)
    print("[run] done ->", args.out)


if __name__ == "__main__":
    main()
