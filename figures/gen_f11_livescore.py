#!/usr/bin/env python3
"""Plot the live posted-score time series (attacker vs legitimate) from the sensor log, to show the
narrow, threshold-crossing separation that makes the live detector the binding constraint."""
import re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({"font.size": 11})

atk, leg = [], []
for line in open("/opt/trust-lab/data/sensor_live.log"):
    m = re.search(r"win#(\d+).*scored=\{([^}]*)\}", line)
    if not m:
        continue
    d = {}
    for ip, sc in re.findall(r"'(10\.0\.0\.\d+)':\s*([0-9.]+)", m.group(2)):
        d[ip] = float(sc)
    a = d.get("10.0.0.13")
    ls = [d[k] for k in ("10.0.0.11", "10.0.0.12") if k in d]
    if a is None and not ls:
        continue
    atk.append(a)
    leg.append(sum(ls) / len(ls) if ls else None)

# representative contiguous slice (last ~45 windows, where the attack is active)
sl = slice(max(0, len(atk) - 45), len(atk))
A, L = atk[sl], leg[sl]
w = list(range(1, len(A) + 1))
plt.figure(figsize=(7, 3.2))
plt.plot(w, [x if x is not None else float("nan") for x in A], "o-", color="#d62728", ms=4,
         label="attacker (flagged) score")
plt.plot(w, [x if x is not None else float("nan") for x in L], "s-", color="#2ca02c", ms=4,
         label="legitimate client score")
plt.axhline(0.4, ls="--", color="#888", label=r"$\tau_c=0.4$ (SvH/SvC boundary)")
plt.axhline(0.7, ls=":", color="#bbb", label=r"$\tau_l=0.7$")
plt.xlabel("sensor window (5 s each)")
plt.ylabel("posted maliciousness score")
plt.ylim(0, 1)
plt.legend(fontsize=8, ncol=2, loc="upper center")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("/opt/trust-lab/figures/final_synthesis/f11_livescore.pdf")
plt.savefig("/opt/trust-lab/figures/final_synthesis/f11_livescore.png", dpi=130)
am = [x for x in A if x is not None]
crosses = sum(1 for i in range(1, len(am)) if (am[i - 1] < 0.4) != (am[i] < 0.4))
print("windows=%d attacker range %.2f-%.2f mean %.2f tau_c crossings=%d"
      % (len(w), min(am), max(am), sum(am) / len(am), crosses))
