#!/usr/bin/env bash
# Wait for the detector sweep to finish, then run the subnet demonstration.
set -u
SW=/opt/trust-lab/data/detector_sweep/driver.log
while ! grep -q "DETECTOR SWEEP DONE" "$SW" 2>/dev/null; do sleep 60; done
sleep 5
bash /opt/trust-lab/harness/subnet_demo.sh > /opt/trust-lab/data/subnet_demo/demo.log 2>&1
echo "CHAIN SUBNET DONE $(date)" >> /opt/trust-lab/data/subnet_demo/demo.log
