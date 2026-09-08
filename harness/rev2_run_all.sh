#!/usr/bin/env bash
# Master runner for every revision-2 experiment, in one serialized queue.
# Resume-safe: each sub-experiment skips cells that already have their result file.
set -u
H=/opt/trust-lab/harness
L=/opt/trust-lab/logs
D=/opt/trust-lab/data/rev2
mkdir -p "$L" "$D"

run() {   # run <logname> <cmd...>
  local name="$1"; shift
  echo "=== START $name $(date) ===" | tee -a "$L/rev2_all.log"
  "$@" >> "$L/$name.log" 2>&1
  echo "=== END   $name rc=$? $(date) ===" | tee -a "$L/rev2_all.log"
}

# 1) scale sweeps (Reviewer 3.2)
run scale_legit   python3 "$H/rev2_scale.py" --mode legit  --levels 0,50,100,200,400 --reps 10 --attack-dur 45 --out "$D/scale_legit"
run scale_threat  python3 "$H/rev2_scale.py" --mode threat --levels 1,2,4,8,16       --reps 10 --attack-dur 45 --out "$D/scale_threat"

# 2) attack coverage (Reviewer 3.1)
run spoof_ipprefix python3 "$H/rev2_spoofing.py" --exp ip_inprefix --reps 10 --out "$D/spoof_ip_inprefix"
run spoof_iprandom python3 "$H/rev2_spoofing.py" --exp ip_random   --reps 10 --out "$D/spoof_ip_random"
run spoof_mac      python3 "$H/rev2_spoofing.py" --exp mac_spoof    --reps 10 --out "$D/spoof_mac"
run reflection     python3 "$H/rev2_reflection.py" --reps 10 --reflectors 4 --out "$D/reflection"

# 3) sensor failure modes (Reviewer 3.3)
run sensor_failure python3 "$H/rev2_sensor_failure.py" --reps 10 --out "$D/sensor_failure"

# 4) latency side-channel + external validity (Reviewer 2.1)
run sidechannel    python3 "$H/rev2_latency.py" --exp sidechannel --reps 10 --out "$D/sidechannel"
run rtt            python3 "$H/rev2_latency.py" --exp rtt         --reps 10 --out "$D/rtt"
run decompose      python3 "$H/rev2_latency.py" --exp decompose   --reps 10 --out "$D/decompose"

echo "ALL-REV2-EXPERIMENTS-DONE $(date)" | tee -a "$L/rev2_all.log"
