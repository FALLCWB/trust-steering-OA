"""
Trust-aware traffic steering controller (clean, instrumented) for Platform A.

A purpose-built Ryu app that reproduces the score-based steering of the original
Scenario-2 Controller.py but is (a) clean, (b) instrumented for the metrics the paper
needs (Tmit decomposition, Packet-In rate, flow-rule count), and (c) structured so the
new mechanisms (asymmetric hysteresis, host-level scoring, SvL tarpit, dynamic sampling)
plug in behind flags in later phases.

Steering model. The sensor reports a continuous *malicious probability* m in [0,1] per
source. Two thresholds map m to a server tier:
    m <  tau_c          -> SvH  (trusted, high resource)
    tau_c <= m < tau_l  -> SvC  (moderate; also the DEFAULT for unknown flows)
    m >= tau_l          -> SvL  (isolation)
Unknown flows default to SvC (fixes the original code's unknown->SvH behaviour).

Clients target a single service VIP; the controller rewrites the destination to the
chosen tier server, keeping redirection transparent. REST: POST /trust/score
{"ip": "...", "score": <float>} updates a source's score; the monitor loop re-evaluates
and re-steers affected flows, logging timestamps for Tmit decomposition.

Config via env TRUST_CONFIG (JSON path). See harness/config/controller.json.
"""
import json
import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

INSTANCE_NAME = "trust_steering_app"
DEFAULT_CONFIG = {
    "vip": "10.0.2.100",
    "vip_mac": "0a:00:00:00:02:64",
    "tiers": {  # tier -> server ip
        "SvH": "10.0.2.1",
        "SvC": "10.0.2.2",
        "SvL": "10.0.2.3",
    },
    "tau_c": 0.4,          # m < tau_c -> SvH
    "tau_l": 0.7,          # m >= tau_l -> SvL
    "default_tier": "SvC",  # unknown flow
    "flow_idle_timeout": 30,
    "monitor_interval": 1.0,
    "event_log": "/opt/trust-lab/runs/controller_events.jsonl",
}


def now():
    return time.monotonic()


class TrustSteering(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg_path = os.environ.get("TRUST_CONFIG")
        self.cfg = dict(DEFAULT_CONFIG)
        if cfg_path and os.path.exists(cfg_path):
            self.cfg.update(json.load(open(cfg_path)))
        self.tiers = self.cfg["tiers"]
        self.vip = self.cfg["vip"]
        self.vip_mac = self.cfg["vip_mac"]
        # state
        self.scores = {}          # src_ip -> malicious prob
        self.subnet_scores = {}   # /24 -> aggregated malicious prob (host-score mechanism)
        self.assigned = {}        # src_ip -> tier currently installed
        self.dirty = set()        # src_ips whose score changed, pending re-steer
        self.promote_pending = {}  # src_ip -> (target_tier, since_ts) for asymmetric hysteresis
        # tier severity (higher = more isolation): used by asymmetric hysteresis
        self.SEV = {"SvH": 0, "SvC": 1, "SvL": 2, "DROP": 3}
        self.mac_to_port = {}     # (dpid, mac) -> port
        self.ip_to_mac = {}       # learned host ip -> mac
        self.ip_to_mac.update(self.cfg.get("server_macs", {}))  # static server MACs
        self.datapath = None
        # instrumentation
        self.packet_in_count = 0
        self.flow_mod_count = 0
        self.score_event_ts = {}  # src_ip -> monotonic ts of last score update (for Tmit)
        os.makedirs(os.path.dirname(self.cfg["event_log"]), exist_ok=True)
        self._evlog = open(self.cfg["event_log"], "a")
        wsgi = kwargs["wsgi"]
        wsgi.register(TrustRestController, {INSTANCE_NAME: self})
        self.monitor_thread = hub.spawn(self._monitor)
        self.log_event("controller_start", cfg=self.cfg)

    # ---------- helpers ----------
    def log_event(self, kind, **kw):
        rec = {"t": now(), "kind": kind, **kw}
        self._evlog.write(json.dumps(rec) + "\n")
        self._evlog.flush()

    def tier_for_score(self, m):
        if m < self.cfg["tau_c"]:
            return "SvH"
        if m >= self.cfg["tau_l"]:
            return "SvL"
        return "SvC"

    def tier_for_ip(self, src_ip):
        if src_ip in self.scores:
            return self.tier_for_score(self.scores[src_ip])
        # host-score mechanism: a new/unknown host inherits its /24 subnet reputation
        if self.cfg.get("subnet_scoring"):
            subnet = src_ip.rsplit(".", 1)[0]
            if subnet in self.subnet_scores:
                return self.tier_for_score(self.subnet_scores[subnet])
        return self.cfg["default_tier"]

    # ---------- OpenFlow ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapath = dp
        ofp, psr = dp.ofproto, dp.ofproto_parser
        # table-miss -> controller
        self.add_flow(dp, 0, psr.OFPMatch(),
                      [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.log_event("switch_connect", dpid=dp.id)
        # proactively ARP every tier server so mac->port is learned without manual warm-up
        hub.spawn_after(1.0, self._arp_servers, dp)

    def _arp_servers(self, dp):
        for server_ip in self.tiers.values():
            self._send_arp_request(dp, server_ip)

    def _send_arp_request(self, dp, target_ip):
        psr = dp.ofproto_parser
        e = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=self.vip_mac,
                              ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST, src_mac=self.vip_mac, src_ip=self.vip,
                    dst_mac="00:00:00:00:00:00", dst_ip=target_ip)
        p = packet.Packet()
        p.add_protocol(e); p.add_protocol(a); p.serialize()
        dp.send_msg(psr.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=[psr.OFPActionOutput(dp.ofproto.OFPP_FLOOD)], data=p.data))

    def add_flow(self, dp, priority, match, actions, idle=0):
        ofp, psr = dp.ofproto, dp.ofproto_parser
        inst = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(psr.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                   idle_timeout=idle, instructions=inst))
        self.flow_mod_count += 1

    def del_flow(self, dp, match):
        ofp, psr = dp.ofproto, dp.ofproto_parser
        dp.send_msg(psr.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                   out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                   match=match))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.packet_in_count += 1
        msg = ev.msg
        dp = msg.datapath
        self.datapath = dp
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.mac_to_port[(dp.id, eth.src)] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(dp, in_port, eth, pkt.get_protocol(arp.arp))
            return
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self._handle_ip(dp, in_port, eth, pkt.get_protocol(ipv4.ipv4), msg)

    def _handle_arp(self, dp, in_port, eth, arp_pkt):
        if arp_pkt is None:
            return
        self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
        # answer ARP for the VIP with the virtual MAC
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.vip:
            self._send_arp_reply(dp, in_port, self.vip, self.vip_mac,
                                 arp_pkt.src_ip, arp_pkt.src_mac)
            return
        # otherwise flood (learning the topology); simple L2 flood
        self._flood(dp, in_port, eth, arp_pkt)

    def _send_arp_reply(self, dp, port, src_ip, src_mac, dst_ip, dst_mac):
        psr = dp.ofproto_parser
        e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,
                    dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e); p.add_protocol(a); p.serialize()
        dp.send_msg(psr.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=[psr.OFPActionOutput(port)], data=p.data))

    def _flood(self, dp, in_port, eth, l3):
        psr = dp.ofproto_parser
        p = packet.Packet()
        p.add_protocol(eth)
        if l3 is not None:
            p.add_protocol(l3)
        p.serialize()
        dp.send_msg(psr.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=[psr.OFPActionOutput(dp.ofproto.OFPP_FLOOD)],
                    data=p.data))

    def _handle_ip(self, dp, in_port, eth, ip, msg):
        if ip is None:
            return
        # Client -> VIP: steer to a tier server
        if ip.dst == self.vip:
            src_ip = ip.src
            tier = self.tier_for_ip(src_ip)
            # drop-only baseline: chosen tier is a drop tier -> install drop flow
            if tier in self.cfg.get("drop_tiers", []):
                self.assigned[src_ip] = "DROP"
                psr = dp.ofproto_parser
                m = psr.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip,
                                 ipv4_dst=self.vip)
                self.add_flow(dp, 10, m, [], idle=self.cfg["flow_idle_timeout"])  # no actions = drop
                self.log_event("drop", src=src_ip, score=self.scores.get(src_ip),
                               tmit_since_score=(now() - self.score_event_ts[src_ip])
                               if src_ip in self.score_event_ts else None)
                return
            server_ip = self.tiers[tier]
            server_mac = self.ip_to_mac.get(server_ip)
            if server_mac is None:
                return  # not learned yet; packet dropped, client will retransmit
            out_port = self.mac_to_port.get((dp.id, server_mac))
            if out_port is None:
                return
            self.assigned[src_ip] = tier
            self._install_steer(dp, in_port, src_ip, eth.src, server_ip, server_mac, out_port)
            self.log_event("steer", src=src_ip, tier=tier,
                           score=self.scores.get(src_ip), server=server_ip,
                           tmit_since_score=(now() - self.score_event_ts[src_ip])
                           if src_ip in self.score_event_ts else None)
            self._resend(dp, msg, out_port, rewrite=(server_ip, server_mac))
        else:
            # server -> client (return path) or other: learn & forward
            self._forward_learned(dp, in_port, eth, msg)

    def _install_steer(self, dp, in_port, src_ip, src_mac, server_ip, server_mac, out_port):
        psr = dp.ofproto_parser
        idle = self.cfg["flow_idle_timeout"]
        # client -> server (rewrite dst VIP->server)
        m1 = psr.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=self.vip)
        a1 = [psr.OFPActionSetField(eth_dst=server_mac),
              psr.OFPActionSetField(ipv4_dst=server_ip),
              psr.OFPActionOutput(out_port)]
        self.add_flow(dp, 10, m1, a1, idle=idle)
        # server -> client (rewrite src server->VIP)
        m2 = psr.OFPMatch(eth_type=0x0800, ipv4_src=server_ip, ipv4_dst=src_ip)
        a2 = [psr.OFPActionSetField(eth_src=self.vip_mac),
              psr.OFPActionSetField(ipv4_src=self.vip),
              psr.OFPActionOutput(in_port)]
        self.add_flow(dp, 10, m2, a2, idle=idle)

    def _resend(self, dp, msg, out_port, rewrite):
        psr = dp.ofproto_parser
        server_ip, server_mac = rewrite
        acts = [psr.OFPActionSetField(eth_dst=server_mac),
                psr.OFPActionSetField(ipv4_dst=server_ip),
                psr.OFPActionOutput(out_port)]
        dp.send_msg(psr.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=msg.match["in_port"], actions=acts, data=msg.data))

    def _forward_learned(self, dp, in_port, eth, msg):
        psr = dp.ofproto_parser
        out = self.mac_to_port.get((dp.id, eth.dst))
        port = out if out is not None else dp.ofproto.OFPP_FLOOD
        dp.send_msg(psr.OFPPacketOut(datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=[psr.OFPActionOutput(port)], data=msg.data))

    # ---------- re-steering on score change ----------
    def _monitor(self):
        while True:
            hub.sleep(self.cfg["monitor_interval"])
            if not self.dirty or self.datapath is None:
                continue
            dp = self.datapath
            psr = dp.ofproto_parser
            for src_ip in list(self.dirty):
                new_tier = self.tier_for_ip(src_ip)
                cur = self.assigned.get(src_ip)
                if new_tier == cur:
                    self.promote_pending.pop(src_ip, None)
                    self.dirty.discard(src_ip)
                    continue
                # Asymmetric hysteresis: demotion (toward isolation) is immediate;
                # promotion (toward SvH) requires the better tier to hold for promote_stab_s.
                stab = self.cfg.get("promote_stab_s", 0)
                if stab > 0 and self.SEV.get(new_tier, 0) < self.SEV.get(cur, 99):
                    pend = self.promote_pending.get(src_ip)
                    if pend is None or pend[0] != new_tier:
                        self.promote_pending[src_ip] = (new_tier, now())
                        continue  # start stabilization window; keep dirty, re-check next tick
                    if now() - pend[1] < stab:
                        continue  # not stable long enough yet
                    self.promote_pending.pop(src_ip, None)
                else:
                    self.promote_pending.pop(src_ip, None)  # demotion / hysteresis off
                # apply re-steer: delete both directions; next packet-in reinstalls
                server_ip_old = self.tiers.get(cur or "", None)
                self.del_flow(dp, psr.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=self.vip))
                if server_ip_old:
                    self.del_flow(dp, psr.OFPMatch(eth_type=0x0800, ipv4_src=server_ip_old, ipv4_dst=src_ip))
                self.log_event("resteer_trigger", src=src_ip, old=cur, new=new_tier,
                               tmit_since_score=(now() - self.score_event_ts[src_ip])
                               if src_ip in self.score_event_ts else None)
                self.dirty.discard(src_ip)

    # called by REST
    def update_score(self, ip, score):
        score = float(score)
        self.scores[ip] = score
        self.score_event_ts[ip] = now()
        self.dirty.add(ip)
        # host-score mechanism: aggregate per /24 subnet (max = worst host sets reputation)
        if self.cfg.get("subnet_scoring"):
            subnet = ip.rsplit(".", 1)[0]
            self.subnet_scores[subnet] = max(self.subnet_scores.get(subnet, 0.0), score)
        self.log_event("score_update", src=ip, score=score)

    def reset(self):
        """Clear per-experiment state and flow rules for a clean next cell."""
        self.scores.clear(); self.assigned.clear(); self.dirty.clear()
        self.score_event_ts.clear(); self.subnet_scores.clear()
        self.promote_pending.clear()
        self.packet_in_count = 0; self.flow_mod_count = 0
        dp = self.datapath
        if dp is not None:
            ofp, psr = dp.ofproto, dp.ofproto_parser
            dp.send_msg(psr.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                        out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=psr.OFPMatch()))
            self.add_flow(dp, 0, psr.OFPMatch(),
                          [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
            hub.spawn_after(0.5, self._arp_servers, dp)
        self.log_event("reset")


class TrustRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[INSTANCE_NAME]

    @route("trust", "/trust/score", methods=["POST"])
    def post_score(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
            self.app.update_score(body["ip"], body["score"])
            return Response(content_type="application/json",
                            body=json.dumps({"ok": True}).encode("utf-8"))
        except Exception as e:
            return Response(status=400, body=json.dumps({"error": str(e)}).encode("utf-8"))

    @route("trust", "/trust/reset", methods=["POST"])
    def post_reset(self, req, **kwargs):
        self.app.reset()
        return Response(content_type="application/json", body=b'{"ok": true}')

    @route("trust", "/trust/config", methods=["POST"])
    def post_config(self, req, **kwargs):
        # live-update thresholds (tau_c/tau_l) and re-evaluate all known sources
        try:
            body = req.json if req.body else {}
            for k in ("tau_c", "tau_l"):
                if k in body:
                    self.app.cfg[k] = float(body[k])
            self.app.dirty.update(self.app.scores.keys())
            return Response(content_type="application/json", body=b'{"ok": true}')
        except Exception as e:
            return Response(status=400, body=json.dumps({"error": str(e)}).encode("utf-8"))

    @route("trust", "/trust/stats", methods=["GET"])
    def get_stats(self, req, **kwargs):
        a = self.app
        return Response(content_type="application/json", body=json.dumps({
            "packet_in_count": a.packet_in_count,
            "flow_mod_count": a.flow_mod_count,
            "assigned": a.assigned,
            "scores": a.scores,
        }).encode("utf-8"))
