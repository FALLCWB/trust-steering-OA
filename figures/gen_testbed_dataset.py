#!/usr/bin/env python3
"""
Generate a labelled in-domain dataset from testbed traffic (for RQ8: cross-dataset vs
in-domain detector accuracy). Runs legit + several attack types simultaneously, captures
each client's switch-side port, extracts flows with CICFlowMeter, and labels by ground
truth (attacker source IPs -> ddos, legit source IPs -> benign).

Output: <out>/testbed_flows.csv  (CICFlowMeter 84-col format + correct Label column)

Assumes trust-topo is up. Independent of the controller (captures raw client traffic).
Usage: gen_testbed_dataset.py --out DIR --legit c1,c2 --attackers c3,c4,c5,c6 --dur 40
"""
import argparse, glob, os, subprocess, time

CFM = "/opt/trust-lab/code/PrototypeControllerWithRFSensor/sensor/files/external/CICFlowMeter-4.0/bin"
VIP = "10.0.0.100"


def ns_pid(h):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % h], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def in_ns(pid, cmd, **kw):
    return subprocess.Popen(["nsenter", "-t", pid, "-n"] + cmd, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--legit", default="c1,c2")
    ap.add_argument("--attackers", default="c3,c4,c5,c6")
    ap.add_argument("--dur", type=float, default=40)
    ap.add_argument("--mode", default="mixed", choices=["mixed", "legit", "attack"])
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    legit = [h for h in args.legit.split(",") if h]
    attackers = [h for h in args.attackers.split(",") if h]
    allh = legit + attackers
    pids = {h: ns_pid(h) for h in allh}
    ips = {h: "10.0.0.%d" % (11 + int(h[1:]) - 1) for h in allh}

    pcap_dir = os.path.join(args.out, "pcap")
    os.makedirs(pcap_dir, exist_ok=True)
    # capture each host's port (root-ns switch iface s1-eth<idx>)
    caps = []
    for h in allh:
        idx = int(h[1:])
        iface = "s1-eth%d" % idx
        out = os.path.join(pcap_dir, "%s.pcap" % ips[h])
        caps.append(subprocess.Popen(["tcpdump", "-i", iface, "-s", "0", "-w", out, "ip"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1)

    # In 'legit' mode ALL hosts do benign HTTP (balanced benign capture); in 'attack' mode
    # only attackers attack; 'mixed' runs both at once (realistic but benign-starved).
    procs = []
    legit_hosts = allh if args.mode == "legit" else legit
    if args.mode in ("mixed", "legit"):
        for h in legit_hosts:
            procs.append(in_ns(pids[h], ["bash", "-c",
                "for i in $(seq 1 100000); do curl -s -o /dev/null -m3 http://%s/; sleep 0.15; done" % VIP],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    atk_cmds = [["hping3", "-S", "-p", "80", "-i", "u300", VIP],     # syn
                ["hping3", "--udp", "-p", "80", "-i", "u300", VIP],  # udp
                ["hping3", "-1", "-i", "u300", VIP],                 # icmp
                ["hping3", "-S", "-p", "80", "-i", "u150", VIP]]     # faster syn
    if args.mode in ("mixed", "attack"):
        for i, h in enumerate(attackers):
            procs.append(in_ns(pids[h], atk_cmds[i % len(atk_cmds)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    time.sleep(args.dur)
    for p in procs:
        p.terminate()
    subprocess.run(["pkill", "-9", "hping3"], stderr=subprocess.DEVNULL)
    for h in legit:
        in_ns(pids[h], ["pkill", "-9", "curl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
    time.sleep(1)
    for c in caps:
        c.terminate()
    for c in caps:
        try:
            c.wait(timeout=3)
        except Exception:
            c.kill()

    # CICFlowMeter on the pcap dir
    flow_dir = os.path.join(args.out, "flow")
    os.makedirs(flow_dir, exist_ok=True)
    subprocess.run(["sh", "cfm", pcap_dir, flow_dir], cwd=CFM,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)

    # merge + label by ground truth (Src IP)
    import pandas as pd
    attacker_ips = set(ips[h] for h in attackers)
    legit_ips = set(ips[h] for h in legit)
    frames = []
    for f in glob.glob(os.path.join(flow_dir, "*_Flow.csv")):
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        # keep only client->VIP flows (Src = our hosts); drop return traffic
        df = df[df["Src IP"].astype(str).isin(attacker_ips | legit_ips)]
        if df.empty:
            continue
        if args.mode == "legit":
            df["Label"] = "Normal"
        else:
            df["Label"] = df["Src IP"].astype(str).apply(lambda s: "DDoS" if s in attacker_ips else "Normal")
        frames.append(df)
    if not frames:
        print("no flows captured")
        return
    out = pd.concat(frames, ignore_index=True)
    out.to_csv(os.path.join(args.out, "testbed_flows.csv"), index=False)
    print("wrote %d flows (%s)" % (len(out), out["Label"].value_counts().to_dict()))


if __name__ == "__main__":
    main()
