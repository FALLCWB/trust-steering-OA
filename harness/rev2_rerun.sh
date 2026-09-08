#!/usr/bin/env bash
set -u
H=/opt/trust-lab/harness; L=/opt/trust-lab/logs; D=/opt/trust-lab/data/rev2
rm -rf $D/rtt $D/reflection
python3 $H/rev2_latency.py --exp rtt --reps 10 --out $D/rtt >> $L/rtt2.log 2>&1
echo "RTT-REDONE $(date)" >> $L/rtt2.log
python3 $H/rev2_reflection.py --reps 10 --reflectors 4 --out $D/reflection >> $L/reflection2.log 2>&1
echo "REFLECTION-REDONE $(date)" >> $L/reflection2.log
# high legit-load sweep to expose the steered primary's saturation knee
python3 $H/rev2_scale.py --mode legit --levels 400,800,1600,3200,6400 --reps 8 --attack-dur 45 \
   --out $D/scale_legit_hi >> $L/scale_legit_hi.log 2>&1
echo "SCALE-HI-DONE $(date)" >> $L/scale_legit_hi.log
echo "RERUN-ALL-DONE $(date)" >> $L/rerun.log
