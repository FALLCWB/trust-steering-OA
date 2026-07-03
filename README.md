# trust-steering-OA

Reproducibility artifact (code only) for the paper *Resource-Aware Elastic Defense in SDN: Empirical Characterization of Score-Based Traffic Steering*.

A score-based traffic-steering DoS-defense policy for SDN, evaluated on a Mininet/Ryu/Open vSwitch testbed. This repository contains the testbed and experiment code only; it contains no manuscript text and no measurement data.

## Dependencies

- Mininet 2.3.0, Open vSwitch 2.17.9, Ryu 4.34
- Python 3 with `matplotlib`, `numpy`, `pandas` (figures) and `scikit-learn` (detector)
- `CICFlowMeter` (flow-feature extraction), `hping3`, `slowhttptest`, `apache2-utils` (`ab`)

## Layout

- `harness/` — controller policy (`trust_steering_app.py`), topology (`topo.py`), tier servers (`slow_server.py`), Random Forest sensor (`sensor_service.py`), score driver (`score_driver.py`), experiment drivers (`run_experiment.py`, `rq*.py`, `*.sh`), lab control (`labctl.sh`), and controller configs (`config/*.json`).
- `figures/` — figure-generation scripts (`gen_*.py`, `analyze_reset.py`).

The `config/*.json` files select the policy variant: `steering.json` (three-tier), `twotier.json` (binary baseline), `droponly_q.json` (drop-only), `nodefense.json`, `mechanisms.json` (hysteresis + subnet aggregation), `hyst_only.json`, etc.

## Running an experiment

Start the controller and topology, then run a driver. Example (oracle-score Slowloris):

```
harness/labctl.sh ryu-start  harness/config/steering.json
harness/labctl.sh topo-start 3
python3 harness/run_experiment.py --out out/ --attack slowloris --intensity 2000 \
        --legit c1,c2 --attackers c3 --score-mode oracle
```

The `*.sh` drivers in `harness/` run the full experiment batches used in the paper (baselines, ablations, threshold sweep, live-detector runs, binary comparison, subnet-collateral, overhead). Figures are regenerated from the per-run output with the scripts in `figures/`.

## Raw measurement data

`data/raw-measurements.tar.gz` contains the per-repetition measurements behind every reported figure and statistic: per-client HTTP latency logs (`latency_*.csv`), run manifests (`manifest.json`, phase timestamps), per-tier time series, the live-sensor score log (`sensor_live.log`), and the detector metric summaries. Extract with `tar xzf data/raw-measurements.tar.gz`; each experiment directory matches a `harness/` driver. Packet captures, the flow-feature dataset, and trained detector models are excluded for size and are available from the authors on request.
