#!/usr/bin/env python3
"""
f_arch (Figure 1): architecture block diagram.

Client traffic to the service VIP reaches the OpenFlow switch, which rewrites the
destination to the server tier chosen by the controller from the per-source score; a port
mirror feeds the Random Forest sensor whose score m drives the tier mapping, the asymmetric
hysteresis, and the host/subnet aggregation; the resulting rule is installed over an
out-of-band control channel.

Drawn at the IEEE Access two-column text width (505.12 pt = 7.01 in) and included as a
full-width figure*, so the diagram is reproduced at 1:1 and its labels keep their nominal
point size in the final PDF instead of being scaled down by a factor of two.
"""
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/trust-lab/data/f_arch.pdf"

TEXTWIDTH_IN = 7.01          # IEEE Access \textwidth
FS_BOX = 10.0                # box titles
FS_SUB = 8.5                 # secondary lines inside boxes
FS_LAB = 8.5                 # arrow labels
EDGE = "#2b2b2b"

fig, ax = plt.subplots(figsize=(TEXTWIDTH_IN, 3.30))
ax.set_xlim(0, 20)
ax.set_ylim(0, 8.9)
ax.axis("off")


def box(x, y, w, h, title, sub=None, fc="#f4f4f4", ec=EDGE, lw=1.2):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.03,rounding_size=0.16",
                                linewidth=lw, edgecolor=ec, facecolor=fc))
    if sub is None:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center",
                fontsize=FS_BOX, color="#111")
    else:
        ax.text(x + w / 2, y + h * 0.70, title, ha="center", va="center",
                fontsize=FS_BOX, color="#111")
        ax.text(x + w / 2, y + h * 0.29, sub, ha="center", va="center",
                fontsize=FS_SUB, color="#333", linespacing=1.35)


def arrow(p0, p1, dashed=False, rad=0.0, lw=1.5, double=False, color=EDGE):
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle="<|-|>" if double else "-|>", mutation_scale=13, lw=lw,
        color=color, linestyle=(0, (4.5, 2.5)) if dashed else "-",
        connectionstyle="arc3,rad=%g" % rad, shrinkA=2, shrinkB=2))


def lab(x, y, t, fs=FS_LAB, color="#333", ha="center", va="center"):
    ax.text(x, y, t, ha=ha, va=va, fontsize=fs, color=color)


# ---------------------------------------------------------------- top row --
box(0.10, 6.55, 5.25, 2.00, "Random Forest sensor",
    "per-source score $m \\in [0,1]$\nreplaceable component",
    fc="#eef1f6")
box(7.05, 6.55, 12.85, 2.00, "Ryu controller (out-of-band control plane)",
    "tier map, Eq. (1), thresholds $\\tau_c < \\tau_l$\n"
    "asymmetric hysteresis  $\\cdot$  host / subnet score aggregation",
    fc="#e6edf8")

arrow((5.45, 7.55), (7.05, 7.55), dashed=True)
lab(6.25, 8.15, "score $m$")

# ------------------------------------------------------------- middle row --
box(0.10, 2.30, 3.25, 2.00, "Clients", "traffic to the\nservice VIP", fc="#f4f4f4")
box(5.20, 2.20, 3.60, 2.20, "OpenFlow switch",
    "Open vSwitch\nVIP $\\rightarrow$ tier rewrite", fc="#f4f4f4")

box(12.30, 4.55, 7.60, 1.40, "SvH  primary tier", "backlog 256, 32 workers", fc="#e6f3e6")
box(12.30, 2.80, 7.60, 1.40, "SvC  quarantine tier (default)", "backlog 128, 12 workers",
    fc="#fbf3dd")
box(12.30, 1.05, 7.60, 1.40, "SvL  isolation tier + tarpit", "backlog 32, 4 workers",
    fc="#f6e4e4")

# ------------------------------------------------------------- data plane --
arrow((3.45, 3.30), (5.20, 3.30))
lab(4.32, 3.72, "to VIP")

arrow((8.80, 3.85), (12.30, 5.25), rad=-0.10)
arrow((8.80, 3.30), (12.30, 3.50))
arrow((8.80, 2.75), (12.30, 1.75), rad=0.10)
lab(9.95, 1.20, "one rule pair per source")

# ---------------------------------------------------------- control plane --
arrow((5.45, 4.40), (3.35, 6.55), dashed=True)
lab(5.05, 5.55, "port mirror", ha="left")

arrow((7.70, 4.40), (7.70, 6.55), dashed=True, double=True)
lab(8.10, 5.55, "Packet-In / Flow-Mod", ha="left")

# --------------------------------------------------------------- legend ----
ax.plot([12.30, 13.30], [0.30, 0.30], "-", color=EDGE, lw=1.5)
lab(13.50, 0.30, "data plane", ha="left", fs=8.0)
ax.plot([16.15, 17.15], [0.30, 0.30], linestyle=(0, (4.5, 2.5)), color=EDGE, lw=1.5)
lab(17.35, 0.30, "control plane", ha="left", fs=8.0)

plt.tight_layout(pad=0.12)
plt.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
