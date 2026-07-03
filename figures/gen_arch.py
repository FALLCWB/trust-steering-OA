#!/usr/bin/env python3
"""
f_arch: architecture block diagram. Client traffic to the VIP hits the OpenFlow switch, which rewrites
the destination to a server tier chosen by the controller from the per-source score; a mirror feeds the
Random Forest sensor whose score m drives the tier mapping, hysteresis, and aggregation; the rule is
installed over an out-of-band control channel. Laid out to avoid crossing arrows. Run with matplotlib.
"""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f_arch.pdf"

fig, ax = plt.subplots(figsize=(7.0, 3.4))
ax.set_xlim(0, 10); ax.set_ylim(0, 6.2); ax.axis("off")


def box(x, y, w, h, text, fc="#f2f2f2", ec="#333", fs=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                linewidth=1.0, edgecolor=ec, facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs)


def arrow(p0, p1, style="-", color="#333", rad=0.0, lw=1.1, double=False):
    ax.add_patch(FancyArrowPatch(p0, p1,
                 arrowstyle="<|-|>" if double else "-|>", mutation_scale=10, lw=lw,
                 color=color, linestyle=style, connectionstyle="arc3,rad=%g" % rad,
                 shrinkA=1, shrinkB=1))


def lab(x, y, t, fs=7, color="#555"):
    ax.text(x, y, t, ha="center", va="center", fontsize=fs, color=color)


# --- top row: RF sensor (far left) + controller (right of it) ---
box(0.35, 4.75, 1.7, 0.85, "RF sensor")
box(3.15, 4.65, 6.65, 1.05,
    "Ryu controller  (out-of-band control plane)\n"
    r"$m\in[0,1]\rightarrow$ tier map (Eq. 1, $\tau_c,\tau_l$)"
    "\n" r"$\rightarrow$ hysteresis + host/subnet aggregation",
    fc="#e8eef7")
# --- middle row: clients -> switch -> tiers ---
box(0.2, 2.35, 1.55, 0.95, "Clients\n(to VIP)")
box(2.45, 2.2, 1.75, 1.3, "OpenFlow\nswitch (OVS)")
box(6.5, 3.55, 3.3, 0.78, "SvH  primary (32 workers)", fc="#e7f4e7")
box(6.5, 2.46, 3.3, 0.78, "SvC  quarantine (12)", fc="#fbf4e0")
box(6.5, 1.37, 3.3, 0.78, "SvL  isolation (4) + tarpit", fc="#f7e7e7")

# data path (solid)
arrow((1.75, 2.82), (2.45, 2.82)); lab(2.1, 3.04, "to VIP")
arrow((4.2, 3.0), (6.5, 3.95), rad=-0.12)
arrow((4.2, 2.85), (6.5, 2.85))
arrow((4.2, 2.7), (6.5, 1.78), rad=0.12)
lab(5.45, 3.18, "rewrite VIP$\\rightarrow$tier", fs=6.5)

# mirror: switch -> sensor (up-left, dashed), clear of everything
arrow((2.85, 3.5), (1.6, 4.75), style=(0, (4, 2))); lab(2.78, 4.22, "mirror")
# score m: sensor -> controller (now a longer arrow with room for the label)
arrow((2.05, 5.12), (3.15, 5.12), style=(0, (4, 2))); lab(2.6, 5.4, "score $m$")
# control channel: switch <-> controller (single dashed double-headed arrow)
arrow((3.55, 3.5), (3.55, 4.65), style=(0, (4, 2)), double=True)
lab(4.5, 4.08, "Packet-In / Flow-Mod")

plt.tight_layout()
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
