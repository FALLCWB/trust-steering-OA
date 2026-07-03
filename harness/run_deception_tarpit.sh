#!/usr/bin/env bash
# Deception measurement + SvL tarpit mechanism (closes the elastic-defense story: absorb + protect +
# graceful-degrade + DECEIVE, all measured). Design + rationale: notes/deception_tarpit_design.md.
# Runs after the main dataset. ~10 reps each for statistics (IC95).
set -u
H=/opt/trust-lab/harness
REPS="${REPS:-10}"
declare -A CFG=( [nodefense]=nodefense.json [droponly]=droponly.json [gradual]=steering.json )

echo "DECEPTION+TARPIT start $(date)"

# ===== 1) DECEPTION: attacker success-signal + primary protection, per defense =====
# elastic(gradual): attacker steered to SvL, SvL responds -> attacker deceived (high success signal),
#                   legit protected. drop: attacker gets nothing -> knows blocked. nodefense: both on primary.
"$H/labctl.sh" topo-stop >/dev/null 2>&1; export TARPIT_DELAY_MS=0
"$H/labctl.sh" clean >/dev/null 2>&1; "$H/labctl.sh" topo-start 6 >/dev/null 2>&1; sleep 18
for d in nodefense droponly gradual; do
  "$H/labctl.sh" ryu-stop >/dev/null 2>&1
  "$H/labctl.sh" ryu-start "$H/config/${CFG[$d]}" >/dev/null 2>&1; sleep 7
  for r in $(seq 1 "$REPS"); do
    "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
    python3 "$H/rq_deception.py" --out "/opt/trust-lab/data/deception/$d" --label "$d" \
      --attacker c3 --legit c1 --secs 25 --detect-k 3 --rep "$r" >> /opt/trust-lab/data/deception/log 2>&1
    echo "[$(date +%H:%M:%S)] deception $d r$r"
  done
done

# ===== 2) TARPIT: gradual, attacker bg-flood ramp, tarpit OFF vs ON =====
# without tarpit: SvL saturates at high load -> attacker success-signal -> 0 (deception BREAKS).
# with tarpit (SvL slow-but-alive, bounded): success-signal maintained (deception HOLDS) + bounded cost.
for tp in off on; do
  if [ "$tp" = on ]; then export TARPIT_DELAY_MS=300; else export TARPIT_DELAY_MS=0; fi
  "$H/labctl.sh" ryu-stop >/dev/null 2>&1
  "$H/labctl.sh" topo-stop >/dev/null 2>&1; "$H/labctl.sh" clean >/dev/null 2>&1
  "$H/labctl.sh" topo-start 6 >/dev/null 2>&1; sleep 18           # topo reads TARPIT_DELAY_MS
  "$H/labctl.sh" ryu-start "$H/config/steering.json" >/dev/null 2>&1; sleep 7
  for I in 50 150 300; do
    for r in $(seq 1 "$REPS"); do
      "$H/labctl.sh" reset >/dev/null 2>&1; sleep 2
      python3 "$H/rq_deception.py" --out "/opt/trust-lab/data/tarpit/$tp/i$I" --label "tarpit_${tp}_i$I" \
        --attacker c3 --legit c1 --secs 25 --detect-k 3 --bg-intensity "$I" --rep "$r" >> /opt/trust-lab/data/tarpit/log 2>&1
      echo "[$(date +%H:%M:%S)] tarpit $tp i$I r$r"
    done
  done
done
export TARPIT_DELAY_MS=0
echo "DECEPTION+TARPIT DONE $(date)"
