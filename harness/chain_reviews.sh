#!/usr/bin/env bash
set -u
bash /opt/trust-lab/harness/e2e_hyst.sh
bash /opt/trust-lab/harness/subnet_collateral.sh
echo "CHAIN DONE $(date)"
