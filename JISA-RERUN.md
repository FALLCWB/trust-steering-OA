# Re-run of November 2026 (JISA version of the manuscript)

The live-detector, hysteresis, default-tier ablation, drop-only top-up and provisioning-test series were re-run with every repetition on a fresh topology (and, for the live series, a fresh sensor), because the earlier drivers reset only the controller's scores between repetitions and held Slowloris connections carried over.

| File | Content |
|---|---|
| `harness/rerun_restart.sh` | Driver (`MODE=sanity|full`), run on the lab VM |
| `data/rerun-2026-11-fresh-topology.tar.gz` | Raw runs: `full/e2e/<class>/rN`, `e2e_hyst`, `abl_deftier`, `nodef_live`, `droponly_q` r6-r10, `model_cH2` r4-r10; each run has `manifest.json`, `latency_*.csv`, `timeseries.csv`, `events.jsonl`, `controller-config.json` and, for live runs, `sensor.log` |
| `data/rerun-2026-11-analysis.json` | Every reported number of the re-run (`scripts/jisa/analyze_rerun.py`) |
| `data/sweeps-attack-window.json` | Detector-quality and legitimate-noise sweeps on the whole run, attack window and steady state (`scripts/jisa/sweep_windows.py`) |
| `scripts/jisa/floor_scan.py` | Finds the floor of the issue-time availability metric in every series |
| `scripts/jisa/gen_*.py` | Figure generators used for the JISA version (escape fix, attack-window Fig. 10, re-run Figs. 8, 9 and 17) |

Merged series: drop-only r1-r5 and provisioning r1-r3 come from `data/raw-measurements.tar.gz`; `analyze_rerun.py` refuses a merge when the run settings differ or run names overlap.
