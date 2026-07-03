#!/usr/bin/env bash
# Final, uniform publication dataset: all 7 sweepable attacks on the SAME (final) server,
# 4 defenses x 5 intensities x 10 repetitions = 200 cells/attack, with 95% CI in analysis.
# (Shrew/LDoS is measured separately via rq_shrew.py: long-flow throughput.)
# Server is the bounded-worker pool with do_POST + 64KB response (RUDY & slow-read effective).
# Justification + citations per attack: notes/attack_justification.md.
set -u
H=/opt/trust-lab/harness
export DEFENSES="nodefense droponly binary gradual" REPS=10 COOL=3 NCLIENTS=6

# --- Volumetric / protocol floods: 4 attackers (DDoS), pps intensities ---
LEGIT="c1,c2" ATTACKERS="c3,c4,c5,c6" ATTACK=synflood  INTENS="1000 5000 10000 50000 100000" BASE=6 ADUR=20 "$H/sweep.sh" final_synflood
LEGIT="c1,c2" ATTACKERS="c3,c4,c5,c6" ATTACK=udpflood  INTENS="1000 5000 10000 50000 100000" BASE=6 ADUR=20 "$H/sweep.sh" final_udpflood
LEGIT="c1,c2" ATTACKERS="c3,c4,c5,c6" ATTACK=icmpflood INTENS="1000 5000 10000 50000 100000" BASE=6 ADUR=20 "$H/sweep.sh" final_icmpflood

# --- Slow / application-layer: single attacker, connection/concurrency intensities ---
LEGIT="c1,c2" ATTACKERS="c3" ATTACK=slowloris INTENS="200 500 1000 1500 2000" BASE=8 ADUR=25 "$H/sweep.sh" final_slowloris
LEGIT="c1,c2" ATTACKERS="c3" ATTACK=slowpost  INTENS="200 500 1000 1500 2000" BASE=8 ADUR=25 "$H/sweep.sh" final_slowpost
LEGIT="c1,c2" ATTACKERS="c3" ATTACK=slowread  INTENS="200 500 1000 1500 2000" BASE=8 ADUR=25 "$H/sweep.sh" final_slowread
LEGIT="c1,c2" ATTACKERS="c3" ATTACK=httpflood INTENS="50 100 150 200 250"     BASE=6 ADUR=20 "$H/sweep.sh" final_httpflood

echo "FINAL DATASET (7 sweeps x 200 cells) DONE $(date)"
