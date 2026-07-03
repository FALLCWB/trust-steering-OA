#!/usr/bin/env python3
"""
Sidecar score injector for the detector-quality sweep.

run_experiment.py is launched with --score-mode none (it posts nothing); this
driver posts the maliciousness scores instead, so the score signal can be
controlled independently of the steering policy. It models an imperfect
detector by sampling each attacker score from N(mean, std) once per window,
reproducing the mean-separation and stability that a live classifier delivers.

Legit clients are pinned to a clean low score (they are not the variable here);
the attacker mean/std are swept. Timing mirrors run_experiment: legit scored at
launch (settle on the primary during baseline), attacker scored every --interval
seconds for --attack-dur seconds, starting after --baseline.
"""
import argparse, json, random, time, urllib.request


def post(rest, ip, score):
    data = json.dumps({"ip": ip, "score": score}).encode()
    req = urllib.request.Request(rest + "/trust/score", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:
        print("score post failed", ip, e, flush=True)


def clamp01(x):
    return min(1.0, max(0.0, x))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacker-ips", required=True, help="csv of attacker IPs")
    ap.add_argument("--legit-ips", required=True, help="csv of legit IPs")
    ap.add_argument("--mal-mean", type=float, required=True)
    ap.add_argument("--mal-std", type=float, default=0.0)
    ap.add_argument("--legit-mean", type=float, default=0.10)
    ap.add_argument("--legit-std", type=float, default=0.0)
    ap.add_argument("--interval", type=float, default=5.0, help="window length (s)")
    ap.add_argument("--baseline", type=float, default=8.0)
    ap.add_argument("--attack-dur", type=float, default=25.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--rest", default="http://127.0.0.1:8080")
    ap.add_argument("--log", default="")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    attackers = [s for s in args.attacker_ips.split(",") if s]
    legit = [s for s in args.legit_ips.split(",") if s]
    logf = open(args.log, "a") if args.log else None

    def emit(tag, ip, s):
        if logf:
            logf.write("%.3f,%s,%s,%.4f\n" % (time.time(), tag, ip, s)); logf.flush()

    # legit settle clean on the primary during baseline
    for ip in legit:
        post(args.rest, ip, clamp01(rng.gauss(args.legit_mean, args.legit_std)))
        emit("legit", ip, args.legit_mean)

    time.sleep(args.baseline)

    # attack window: post one sampled score per window, like a per-window classifier
    t_end = time.time() + args.attack_dur
    while time.time() < t_end:
        for ip in attackers:
            s = clamp01(rng.gauss(args.mal_mean, args.mal_std))
            post(args.rest, ip, s); emit("attacker", ip, s)
        for ip in legit:
            s = clamp01(rng.gauss(args.legit_mean, args.legit_std))
            post(args.rest, ip, s); emit("legit", ip, s)
        time.sleep(args.interval)

    if logf:
        logf.close()


if __name__ == "__main__":
    main()
