#!/usr/bin/env bash
# Master sweep for the 3 new literature-justified HTTP attacks (each 100 cells:
# 4 defenses x 5 intensities x 5 reps). Runs sequentially; persists via systemd-run.
# Justification + citations: notes/attack_justification.md.
set -u
H=/opt/trust-lab/harness
export DEFENSES="nodefense droponly binary gradual" REPS=5 COOL=3 \
       LEGIT="c1,c2" ATTACKERS="c3" NCLIENTS=6

# Slow POST / RUDY (slow request body -> worker pool). intensity = connections.
ATTACK=slowpost  INTENS="200 500 1000 1500 2000" BASE=8 ADUR=25 "$H/sweep.sh" sweep6_slowpost

# Slow Read (slow response consumption -> worker pool). intensity = connections.
ATTACK=slowread  INTENS="200 500 1000 1500 2000" BASE=8 ADUR=25 "$H/sweep.sh" sweep7_slowread

# HTTP GET flood (application-layer high-rate valid requests -> worker pool). intensity = ab concurrency.
ATTACK=httpflood INTENS="50 100 150 200 250"     BASE=6 ADUR=20 "$H/sweep.sh" sweep8_httpflood

echo "ALL NEW-ATTACK SWEEPS DONE $(date)"
