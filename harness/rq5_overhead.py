#!/usr/bin/env python3
"""
RQ5 host overhead: controller CPU and memory, idle baseline vs under attack.
Samples the Ryu controller process (and the sensor process if present) via /proc, during a quiet
baseline and during a SYN flood (the attack that maximizes Packet-In pressure on the controller).
Reports mean/peak CPU% and peak RSS for each phase. Assumes topo+ryu are up (labctl).

Usage: rq5_overhead.py --out DIR --attacker c3 --intensity 100000 --baseline 12 --attack 20
"""
import argparse, json, os, subprocess, time

CLK = os.sysconf("SC_CLK_TCK")
VIP = "10.0.0.100"


def ryu_pid():
    o = subprocess.run(["pgrep", "-f", "ryu-manager"], capture_output=True, text=True).stdout.split()
    return int(o[0]) if o else None


def sensor_pid():
    o = subprocess.run(["pgrep", "-f", "sensor_service"], capture_output=True, text=True).stdout.split()
    return int(o[0]) if o else None


def jiffies(pid):
    with open("/proc/%d/stat" % pid) as f:
        p = f.read().split()
    return int(p[13]) + int(p[14])  # utime + stime


def rss_kb(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except FileNotFoundError:
        return 0
    return 0


def ns_pid(h):
    o = subprocess.run(["pgrep", "-f", "mininet:%s$" % h], capture_output=True, text=True).stdout.split()
    return o[0] if o else None


def sample_phase(pids, secs, interval=0.5):
    """Sample CPU% and RSS for each pid over secs; return per-pid {cpu_mean,cpu_peak,rss_peak_mb}."""
    acc = {p: {"cpu": [], "rss": []} for p in pids}
    prev = {p: jiffies(p) for p in pids}
    t_prev = time.time()
    n = int(secs / interval)
    for _ in range(n):
        time.sleep(interval)
        now = time.time(); dt = now - t_prev; t_prev = now
        for p in pids:
            j = jiffies(p)
            cpu = 100.0 * (j - prev[p]) / CLK / dt
            prev[p] = j
            acc[p]["cpu"].append(cpu)
            acc[p]["rss"].append(rss_kb(p) / 1024.0)
    out = {}
    for p in pids:
        c = acc[p]["cpu"]; r = acc[p]["rss"]
        out[p] = dict(cpu_mean=round(sum(c) / len(c), 1), cpu_peak=round(max(c), 1),
                      rss_peak_mb=round(max(r), 1))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--attacker", default="c3")
    ap.add_argument("--intensity", type=int, default=100000)
    ap.add_argument("--baseline", type=float, default=12)
    ap.add_argument("--attack", type=float, default=20)
    ap.add_argument("--rep", type=int, default=0)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    rp = ryu_pid()
    if not rp:
        raise SystemExit("ryu-manager not running")
    sp = sensor_pid()
    pids = [rp] + ([sp] if sp else [])
    labels = {rp: "controller"}
    if sp:
        labels[sp] = "sensor"

    base = sample_phase(pids, args.baseline)

    apid = ns_pid(args.attacker)
    # High-rate SYN flood from a single (real) source: the steering policy installs one rule and the
    # switch then absorbs the flood, so this measures the policy's steady-state control-plane cost.
    # (A spoofed random-source flood is a separate control-plane-saturation attack, discussed as a
    # limitation rather than measured here, since it pollutes per-source state by construction.)
    atk = subprocess.Popen(["nsenter", "-t", apid, "-n", "hping3", "-S", "-p", "80", "--flood", VIP],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    under = sample_phase(pids, args.attack)
    atk.terminate()
    subprocess.run(["nsenter", "-t", apid, "-n", "pkill", "-9", "hping3"], stderr=subprocess.DEVNULL)

    res = {"rep": args.rep, "intensity": args.intensity,
           "baseline": {labels[p]: base[p] for p in pids},
           "under_attack": {labels[p]: under[p] for p in pids}}
    json.dump(res, open(os.path.join(args.out, "overhead_r%d.json" % args.rep), "w"), indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
