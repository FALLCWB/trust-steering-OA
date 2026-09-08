#!/usr/bin/env python3
"""
Scale sweeps for the revision-2 empirical-rigour requirement.

Two independent scale axes, each swept over several levels with ten repetitions so the
between-repetition variance is reported, not assumed:

  --mode legit
      Legitimate-workload scale. Two curl probe clients keep the availability metric
      identical to the rest of the paper; the offered legitimate load is raised by a
      benign Apache Bench background of B concurrent connections spread over four
      loader hosts, all scored benign. A single Slowloris attacker runs throughout.
      Levels are values of B.

  --mode threat
      Threat scale. Two probe clients, one benign background level, and A independent
      Slowloris attacker sources. Levels are values of A. Three arms separate the
      regimes: attackers correctly scored (isolated on SvL), attackers not yet scored
      (they arrive at the default quarantine SvC, the pre-classification window), and
      no defense.

The topology is restarted for every repetition so that availability reflects the level
under test and not connections held over from the previous run.

Usage:
  rev2_scale.py --mode legit  --levels 0,50,100,200,400 --reps 10 --out /opt/trust-lab/data/rev2/scale_legit
  rev2_scale.py --mode threat --levels 1,2,4,8,16       --reps 10 --out /opt/trust-lab/data/rev2/scale_threat
"""
import argparse
import json
import os
import subprocess
import sys
import time

LAB = "/opt/trust-lab"
H = LAB + "/harness"
LABCTL = H + "/labctl.sh"
REST = "http://127.0.0.1:8080"

# arm -> controller config
CONFIGS = {
    "gradual": H + "/config/steering.json",
    "gradual_unscored": H + "/config/steering.json",
    "nodefense": H + "/config/nodefense.json",
}


def sh(cmd, timeout=180, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError("cmd failed: %s\n%s\n%s" % (cmd, r.stdout, r.stderr))
    return r


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def ryu_start(cfg):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-start %s >/dev/null 2>&1" % (LABCTL, cfg))
    time.sleep(6)


def topo_restart(nclients, settle=14):
    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s clean     >/dev/null 2>&1" % LABCTL)
    sh("%s topo-start %d >/dev/null 2>&1" % (LABCTL, nclients))
    time.sleep(settle)
    # clear per-run controller state only after the switch has reconnected
    sh("curl -s -m4 -X POST %s/trust/reset >/dev/null 2>&1" % REST)
    time.sleep(2)


def run_cell(outdir, **kw):
    args = ["python3", H + "/run_experiment.py", "--out", outdir]
    for k, v in kw.items():
        if v is None or v == "":
            continue
        args += ["--" + k.replace("_", "-"), str(v)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=600)
    ok = os.path.exists(os.path.join(outdir, "manifest.json"))
    if not ok:
        log("  RUN FAILED: %s\n%s\n%s" % (" ".join(args), r.stdout[-800:], r.stderr[-800:]))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["legit", "threat"])
    ap.add_argument("--levels", required=True)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", required=True)
    ap.add_argument("--attack-dur", type=float, default=50.0)
    ap.add_argument("--intensity", type=int, default=2000,
                    help="Slowloris connections per attacker source")
    args = ap.parse_args()

    levels = [int(x) for x in args.levels.split(",")]
    os.makedirs(args.out, exist_ok=True)
    status_path = os.path.join(args.out, "status.jsonl")
    status = open(status_path, "a")

    if args.mode == "legit":
        nclients = 7
        probes = "c1,c2"
        attackers = "c3"
        bg_hosts = "c4,c5,c6,c7"
        arms = ["nodefense", "gradual"]
    else:
        nclients = 18
        probes = "c1,c2"
        bg_hosts = ""
        arms = ["nodefense", "gradual", "gradual_unscored"]

    json.dump({"mode": args.mode, "levels": levels, "reps": args.reps, "arms": arms,
               "nclients": nclients, "intensity": args.intensity,
               "attack_dur": args.attack_dur,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S")},
              open(os.path.join(args.out, "sweep_config.json"), "w"), indent=2)

    total = len(arms) * len(levels) * args.reps
    done = failed = 0
    t_start = time.time()

    for arm in arms:
        log("=== arm %s : ryu %s" % (arm, os.path.basename(CONFIGS[arm])))
        ryu_start(CONFIGS[arm])
        for lvl in levels:
            for rep in range(1, args.reps + 1):
                cell = os.path.join(args.out, arm, "L%d" % lvl, "r%d" % rep)
                if os.path.exists(os.path.join(cell, "manifest.json")):
                    done += 1
                    continue
                topo_restart(nclients)
                if args.mode == "legit":
                    kw = dict(defense=arm, attack="slowloris", intensity=args.intensity,
                              legit=probes, attackers=attackers,
                              bg_hosts=bg_hosts, bg_conc=lvl,
                              attack_dur=args.attack_dur, score_mode="oracle",
                              score_attackers="yes", rep=rep, nclients=nclients,
                              tag="scale_legit_B%d_%s" % (lvl, arm))
                else:
                    atk = ",".join("c%d" % (3 + i) for i in range(lvl))
                    kw = dict(defense=arm, attack="slowloris", intensity=args.intensity,
                              legit=probes, attackers=atk,
                              attack_dur=args.attack_dur, score_mode="oracle",
                              score_attackers=("no" if arm == "gradual_unscored" else "yes"),
                              rep=rep, nclients=nclients,
                              tag="scale_threat_A%d_%s" % (lvl, arm))
                ok = run_cell(cell, **kw)
                done += 1
                failed += (0 if ok else 1)
                rec = {"arm": arm, "level": lvl, "rep": rep, "ok": ok,
                       "t": time.strftime("%Y-%m-%dT%H:%M:%S")}
                status.write(json.dumps(rec) + "\n")
                status.flush()
                el = time.time() - t_start
                log("%s L=%d r=%d  %s  [%d/%d, %.0f min elapsed, ~%.0f min left]"
                    % (arm, lvl, rep, "ok" if ok else "FAIL", done, total, el / 60,
                       (el / max(done, 1)) * (total - done) / 60))

    sh("%s topo-stop >/dev/null 2>&1" % LABCTL)
    sh("%s ryu-stop  >/dev/null 2>&1" % LABCTL)
    log("SWEEP DONE mode=%s  cells=%d  failed=%d  (%.1f h)"
        % (args.mode, done, failed, (time.time() - t_start) / 3600))
    status.close()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
