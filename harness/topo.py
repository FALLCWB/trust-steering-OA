#!/usr/bin/env python3
"""
Platform A topology: clients + 3 server tiers + sensor, single L2 subnet, remote Ryu.

All hosts share 10.0.0.0/24 so steering is pure L2 (no router needed). Clients target the
service VIP (10.0.0.100, answered by the controller). Each tier server serves an
identifiable page so a curl from a client reveals which tier handled it -- used to verify
score-based steering end to end.

Servers: SvH=10.0.0.201, SvC=10.0.0.202, SvL=10.0.0.203. Sensor=10.0.0.50 gets a mirror
of the switch's client-facing traffic (port mirror set up here). Clients=10.0.0.11..

Usage:
  sudo python3 topo.py --clients 3 --controller-ip 127.0.0.1 [--cli]
Drops to the Mininet CLI unless --no-cli; with --cli runs an interactive session.
"""
import argparse
import os
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Heterogeneous tiers: (ip, mac, link_bw_mbit, syn_backlog). SvL is intentionally the
# low-capacity isolation tier (small SYN backlog + narrow link -> saturates first); SvH is
# high-capacity. Capacity is modelled via the kernel SYN backlog (the real bottleneck under
# a SYN flood) and link bandwidth, avoiding cgroups (CPULimitedHost needs cgroups v1).
# (ip, mac, link_bw_mbit, syn_backlog, http_workers). http_workers = bounded HTTP pool
# (Apache MaxClients-style): caps concurrent requests, so a Slowloris that exhausts the pool
# blocks new (legit) requests. SvL is the low-capacity isolation tier.
TIERS = {"SvH": ("10.0.0.201", "00:00:00:00:02:01", 100, 256, int(os.getenv("SVH_WORKERS","32"))),
         "SvC": ("10.0.0.202", "00:00:00:00:02:02", 50, 128, int(os.getenv("SVC_WORKERS","12"))),
         "SvL": ("10.0.0.203", "00:00:00:00:02:03", 10, 32, 4)}
SENSOR = ("10.0.0.50", "00:00:00:00:00:50")


def build(n_clients, c_ip, c_port, link_bw):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    c0 = net.addController("c0", controller=RemoteController, ip=c_ip, port=c_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    clients = []
    for i in range(n_clients):
        ip = "10.0.0.%d" % (11 + i)
        mac = "00:00:00:00:01:%02x" % (11 + i)
        h = net.addHost("c%d" % (i + 1), ip=ip + "/24", mac=mac)
        clients.append(h)
        net.addLink(h, s1, bw=link_bw)

    servers = {}
    for tier, (ip, mac, bw, backlog, workers) in TIERS.items():
        h = net.addHost(tier.lower(), ip=ip + "/24", mac=mac)
        servers[tier] = h
        net.addLink(h, s1, bw=bw)

    sensor = net.addHost("sensor", ip=SENSOR[0] + "/24", mac=SENSOR[1])
    net.addLink(sensor, s1, bw=link_bw)

    net.build()
    c0.start()
    s1.start([c0])
    return net, s1, clients, servers, sensor


def setup_mirror(s1, sensor):
    """Mirror all client-facing traffic to the sensor port (SPAN)."""
    sensor_intf = sensor.connectionsTo(s1)[0][1].name  # switch-side port to sensor
    s1.cmd("ovs-vsctl -- --id=@p get port %s "
           "-- --id=@m create mirror name=msensor select-all=true output-port=@p "
           "-- set bridge s1 mirrors=@m" % sensor_intf)
    info("*** Mirror to sensor on %s\n" % sensor_intf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=3)
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6653)
    ap.add_argument("--link-bw", type=int, default=100)  # Mbit/s
    ap.add_argument("--no-cli", action="store_true")
    args = ap.parse_args()
    setLogLevel("info")

    net, s1, clients, servers, sensor = build(args.clients, args.controller_ip,
                                              args.controller_port, args.link_bw)
    # Per-tier capacity: small SYN backlog + syncookies OFF make the low tier saturate
    # first under a SYN flood (the real bottleneck). These sysctls are per-netns.
    for tier, h in servers.items():
        backlog = TIERS[tier][3]
        h.cmd("sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1")
        h.cmd("sysctl -w net.ipv4.tcp_max_syn_backlog=%d >/dev/null 2>&1" % backlog)
        h.cmd("sysctl -w net.core.somaxconn=%d >/dev/null 2>&1" % backlog)
        h.cmd("sysctl -w net.ipv4.tcp_synack_retries=2 >/dev/null 2>&1")
    # Each tier server runs the bounded-pool HTTP server (workers = tier HTTP capacity),
    # serving an identifiable page so a client curl reveals which tier handled it.
    here = os.path.dirname(os.path.abspath(__file__))
    # tarpit: when TARPIT_DELAY_MS is set, SvL responds slowly on purpose (bounded, alive-but-slow)
    tarpit_ms = int(os.environ.get("TARPIT_DELAY_MS", "0"))
    for tier, h in servers.items():
        workers = TIERS[tier][4]
        delay = tarpit_ms if tier == "SvL" else 0
        h.cmd("python3 %s/slow_server.py --bind %s --port 80 --workers %d --page 'served-by %s' "
              "--page-bytes 65536 --delay-ms %d > /tmp/http_%s.log 2>&1 &"
              % (here, h.IP(), workers, tier, delay, tier))

    # Write the authoritative tier -> switch-port mapping for the runner's collectors.
    import json as _json
    portmap = {tier: h.connectionsTo(s1)[0][1].name for tier, h in servers.items()}
    portmap["sensor"] = sensor.connectionsTo(s1)[0][1].name
    os.makedirs("/opt/trust-lab/runs", exist_ok=True)
    _json.dump(portmap, open("/opt/trust-lab/runs/portmap.json", "w"))
    info("*** portmap: %s\n" % portmap)

    setup_mirror(s1, sensor)

    # Announce server MACs so the controller learns ip->mac (gratuitous ARP).
    time.sleep(1)
    for tier, h in servers.items():
        h.cmd("arping -c 2 -A -I %s-eth0 %s >/dev/null 2>&1 &" % (h.name, h.IP()))
    # Clients pre-resolve the VIP (controller answers).
    for h in clients:
        h.cmd("arping -c 1 -I %s-eth0 10.0.0.100 >/dev/null 2>&1 &" % h.name)
    time.sleep(2)
    info("*** Topology up: %d clients, tiers SvH/SvC/SvL, sensor mirror active.\n"
         % len(clients))
    info("*** VIP=10.0.0.100  servers=%s\n" % {k: v[0] for k, v in TIERS.items()})

    if not args.no_cli:
        CLI(net)
        net.stop()
    else:
        # keep running for the harness; block until killed
        info("*** Running headless; Ctrl-C / kill to stop.\n")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            net.stop()


if __name__ == "__main__":
    main()
