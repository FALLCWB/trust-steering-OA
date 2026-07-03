#!/usr/bin/env bash
while ! grep -q "BASELINES DONE" /opt/trust-lab/data/steady_baselines/driver.log 2>/dev/null; do sleep 60; done
sleep 5; bash /opt/trust-lab/harness/src_scale.sh > /opt/trust-lab/data/src_scale/run.log 2>&1
sleep 5; bash /opt/trust-lab/harness/model_cH.sh > /opt/trust-lab/data/model_cH/driver.log 2>&1
echo "ALLEXP DONE $(date)" >> /opt/trust-lab/data/src_scale/run.log
