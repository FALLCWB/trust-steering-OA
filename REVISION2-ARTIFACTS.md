# Revision-2 artifacts (Access-2026-33694)

New experiments added for the IEEE Access resubmission. All run on the same Mininet/Ryu
testbed; each restarts the topology per repetition and uses the shared metric definitions in
`harness/rev2_lib.py` (identical to the definitions used for the original figures).

## Harness
- `rev2_scale.py`       — legitimate-workload and threat scale sweeps (Fig. 6).
- `rev2_spoofing.py`    — in-prefix IP spoofing, randomized-source flood, MAC/ARP forgery (Sec. V-G).
- `rev2_reflection.py`  — third-party UDP reflectors, amplification (Sec. V-G); `udp_reflector.py` is the responder.
- `rev2_sensor_failure.py` — sensor fault injection: outage, stale, poisoned, with/without score-TTL (Fig. 12).
- `rev2_latency.py`     — latency side-channel, injected-RTT external validity, latency decomposition (Figs. 14-15).
- `rev2_run_all.sh`, `rev2_rerun.sh` — batch runners.
- Additive changes to `topo.py` (client netem delay, reflector hosts), `trust_steering_app.py`
  (pinned server IP->MAC bindings, score time-to-live fail-safe, extra stat counters),
  `run_experiment.py` (benign background load), `labctl.sh` (forwards the new env vars).

## Analysis and figures
- `scripts/rev2_analyze.py` — aggregates every experiment into `data/rev2_stats.json`
  (mean, 95% normal and bootstrap CIs, n, collapse rates).
- `scripts/gen_rev2_{scale,sensor,sidechannel,rtt}.py`, `scripts/gen_arch.py` — figure generators.

## Data
- `data/rev2_stats.json` — aggregated statistics behind every new number.
- `data/rev2-raw-measurements.tar.gz` — per-repetition raw outputs for all new cells.
