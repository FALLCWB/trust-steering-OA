#!/usr/bin/env python3
"""
Analytical model of the tiered elastic defense as a loss network, and the sensitivity
figure f13. Each tier is an M/G/c/c loss system (Erlang-B, insensitive to the holding-time
distribution beyond its mean, which is what makes it valid for the long-held Slowloris
connections). A maliciousness score thresholded at tau_c/tau_l splits the offered load
across tiers; legitimate availability follows from the blocking at the tier each legitimate
client lands on.

Central relation: a legitimate client is served on the primary tier SvH, which also receives
the share of attacker load placed on it. With P_leak that share (equal to the probability that the
attacker scores below tau_c only when its load follows its per-window score) and a_A the attacker
offered load, the legitimate availability is

    A_legit = 1 - ErlangB(a_L + P_leak * a_A, c_H),

tying detector quality (P_leak) and provisioning (c_H) to availability in one expression.
Run with the sensor-venv python (numpy/matplotlib).
"""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def erlangB(a, c):
    """Blocking probability of an M/G/c/c loss system, offered load a Erlangs, c servers."""
    B = 1.0
    for n in range(1, c + 1):
        B = a * B / (n + a * B)
    return B


# Testbed parameters (Table of parameters): worker pools per tier.
C_H, C_C, C_L = 32, 12, 4
# Offered loads (Erlangs). Legit: 2 clients, ~3.3 req/s each, 5 ms service.
a_L = (2 / 0.305) * 0.005
# Attacker offered load: an illustrative parameter set so that the model reproduces ONE measured value,
# the steady-state no-defense availability under sustained Slowloris (the full attacker load on the
# primary). That value is the issue-time floor of the availability metric, so it does not identify the
# load (paper, Section 6); the parameter only fixes the scale of the illustration.
MEAS_NODEF = 0.083  # measured steady-state legit availability, no defense (Slowloris, n=5)
def _calib(c, target_avail):
    lo, hi = 1.0, 1e5
    for _ in range(80):
        mid = (lo + hi) / 2
        if (1 - erlangB(a_L + mid, c)) > target_avail:
            lo = mid
        else:
            hi = mid
    return lo
a_A_sat = _calib(32, MEAS_NODEF)

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f13_model.pdf"

# ---- validation at the measured steady-state operating points ----
def avail(load, c):
    return 100 * (1 - erlangB(load, c))

print("=== model vs measured (steady-state) ===")
print("no-defense  (legit+full attacker on SvH): model %.1f%%   measured 8.3%% (floor of Eq. 4)"
      % avail(a_L + a_A_sat, C_H))
print("steering    (attacker isolated; legit alone on SvH): model %.1f%%   measured 100%%"
      % avail(a_L, C_H))
print("default-quarantine (attacker load on SvC; SvH free): model %.1f%%   measured 100%%"
      % avail(a_L, C_H))
print("a_L = %.4f Erlangs" % a_L)

# SLA-based requirement: B(a_L + P_leak*a_A, c_H) <= eps  ->  largest tolerable P_leak
import numpy as np
def pleak_star(c, eps):
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if erlangB(a_L + mid * a_A_sat, c) < eps:
            lo = mid
        else:
            hi = mid
    return lo
EPS = 0.01  # target availability 99%
print("\n=== SLA requirement B(a_L+P_leak*a_A, c_H) <= eps ===")
for c in (16, 32, 64, 128):
    print("  c_H=%3d -> P_leak* (99%% avail) = %.4f (%.2f%%) | load-capacity c/a_A = %.2f%%"
          % (c, pleak_star(c, EPS), 100 * pleak_star(c, EPS), 100 * c / a_A_sat))

# ---- f13: the detector-quality / provisioning requirement ----
fig, ax = plt.subplots(1, 2, figsize=(7, 3.0))

# Panel A: availability vs P_leak (log axis) for three provisioning levels of the primary tier
P = np.logspace(-4, 0, 200)
for c, style in [(16, "--"), (32, "-"), (64, ":")]:
    y = [avail(a_L + p * a_A_sat, c) for p in P]
    ax[0].plot(P, y, style, lw=1.8, label="$c_H=%d$" % c)
ax[0].axhline(99, ls="--", color="#888", lw=0.8)
ax[0].text(1.1e-4, 94, "99% target", fontsize=7, color="#555")
# The live detector's per-window miss rate is not drawn: it is not the leaked share of attack load (paper,
# Section 6), so it does not belong on this axis.
ax[0].set_xscale("log")
ax[0].set_xlabel("leaked share of attack load $P_{\\mathrm{leak}}$")
ax[0].set_ylabel("legitimate availability (%)")
ax[0].set_ylim(-3, 103)
ax[0].legend(fontsize=8, loc="lower left", title="primary pool")
ax[0].grid(alpha=0.3, which="both")

# Panel B: provisioning test -- the model predicts availability rises with c_H, the
# measurement stays at the floor of Eq. 4 (2 of 24 requests, each client's last one, answered after the attack
# stops) and no request is answered during the attack at any pool size (re-run, n=10 per size).
cH_test = [16, 32, 64]
model_av = [100 * (1 - erlangB(a_L + a_A_sat, c)) for c in cH_test]
meas_av = [8.3, 8.3, 8.3]
ax[1].plot(cH_test, model_av, "o-", color="#1f77b4", ms=6, label="model")
ax[1].plot(cH_test, meas_av, "s--", color="#d62728", ms=6, label="measured, Eq. 4 (floor)")
ax[1].plot(cH_test, [0, 0, 0], "v:", color="#7f0000", ms=6, label="measured, answered during attack")
ax[1].set_xlabel("primary-tier worker pool $c_H$")
ax[1].set_ylabel("no-defense availability (%)")
ax[1].set_xticks(cH_test)
ax[1].set_ylim(-1.5, 20)
ax[1].legend(fontsize=8, loc="upper left")
ax[1].grid(alpha=0.3)
ax[1].text(0.97, 0.12, "no request answered during\nthe attack at any pool size",
           transform=ax[1].transAxes, fontsize=6.5, ha="right", va="bottom", color="#a00")

plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
