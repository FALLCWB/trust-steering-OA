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
| `harness/rerun_r1r2.sh` | Driver of the live-detector baselines (`MODE=sanity|full`), same fresh-topology procedure |
| `harness/config/droponly_q_hyst.json` | Drop-only with the quarantine default plus the 5 s promotion stabilization of `hyst_only.json` (the driver writes it if missing) |
| `data/r1r2-2026-11-live-baselines.tar.gz` | Raw runs: `r1r2-full/hyst/{slowpost,slowread}`, `dq_live/<class>`, `dq_live_hyst/<class>`, `reconn_nohyst`, `reconn_hyst`, ten repetitions each, same files per run as above |
| `data/r1r2-2026-11-analysis.json` | Every reported number of those runs, with first-promotion times (`scripts/jisa/analyze_r1r2.py`, which reuses the definitions of `analyze_rerun.py`) |

The field `p_leak` in both analysis files is the per-window miss rate of the live sensor (the share of scoring windows below tau_c), not the leaked share of attack load P_leak of the analytical model; the paper keeps the two apart (Section 6).

Merged series: drop-only r1-r5 and provisioning r1-r3 come from `data/raw-measurements.tar.gz`; `analyze_rerun.py` refuses a merge when the run settings differ or run names overlap.

## Live-detector baselines (Table 6 of the JISA version)

Ten repetitions per cell on the live-run schedule (baseline 10 s, attack 30 s), each on a fresh topology with a fresh sensor:

- steering with asymmetric hysteresis on Slow POST and Slow Read (Slowloris is `e2e_hyst` of the re-run);
- drop-only with the quarantine default (`droponly_q.json`) without and with hysteresis (`droponly_q_hyst.json`) on Slowloris, Slow POST and Slow Read;
- an attacker that keeps opening connections: Slowloris at the same 200 connections per second configured for 6,000 connections (`--intensity 6000`), so it opens connections for the whole attack, with steering without (`reconn_nohyst`) and with hysteresis (`reconn_hyst`).

Reproduce the numbers: extract both tarballs, then `python3 scripts/jisa/analyze_r1r2.py r1r2-full full out.json`.
