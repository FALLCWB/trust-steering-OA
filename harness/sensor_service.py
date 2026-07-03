#!/usr/bin/env python3
"""
Sensor-in-the-loop: closes the detection->steering loop on Platform A.

Runs in the root namespace, capturing client-facing switch ports (s1-eth1..N), where
each port carries one client's traffic (client -> VIP, before the switch rewrites it).
Every window it: captures a pcap per interface, runs CICFlowMeter to extract flows,
scores each flow with the retrained RF (malicious probability), aggregates per source IP,
and POSTs the score to the controller's REST endpoint. The controller then steers.

Per-host aggregation = max malicious probability across the source's flows in the window
(responsive to attacks; matches the host-level trust the paper argues for). An optional
EWMA smooths scores for hysteresis experiments.

Usage:
  sensor_service.py --interfaces s1-eth1,s1-eth2,s1-eth3 --window 5 \
      --controller http://127.0.0.1:8080 \
      --model /opt/trust-lab/sensor-retrain/RF_model_insdn.pck \
      --features /opt/trust-lab/sensor-retrain/features.json
"""
import argparse
import glob
import json
import os
import pickle
import shutil
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import requests

CFM_BIN = "/opt/trust-lab/code/PrototypeControllerWithRFSensor/sensor/files/external/CICFlowMeter-4.0/bin"


def log(msg):
    print("[sensor %s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


class Sensor:
    def __init__(self, args):
        self.args = args
        self.feats = json.load(open(args.features))
        name, self.clf = pickle.load(open(args.model, "rb"))
        log("model=%s n_features=%d" % (name, getattr(self.clf, "n_features_in_", -1)))
        self.ewma = {}  # src_ip -> smoothed score
        self.workdir = "/tmp/sensor_work"

    def capture(self, pcap_dir):
        os.makedirs(pcap_dir, exist_ok=True)
        procs = []
        for i, iface in enumerate(self.args.interfaces):
            out = os.path.join(pcap_dir, "i%d.pcap" % i)
            p = subprocess.Popen(["tcpdump", "-i", iface, "-s", "0", "-w", out,
                                  "ip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)
        time.sleep(self.args.window)
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()

    def extract_flows(self, pcap_dir, flow_dir):
        os.makedirs(flow_dir, exist_ok=True)
        # CICFlowMeter processes every pcap in pcap_dir, writes *_Flow.csv to flow_dir
        subprocess.run(["sh", "cfm", pcap_dir, flow_dir], cwd=CFM_BIN,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        frames = []
        for f in glob.glob(os.path.join(flow_dir, "*_Flow.csv")):
            try:
                df = pd.read_csv(f, low_memory=False)
                df.columns = [c.strip() for c in df.columns]
                frames.append(df)
            except Exception:
                pass
        if not frames:
            return None
        return pd.concat(frames, ignore_index=True)

    def score_flows(self, df):
        # only score client->service flows (Dst == VIP); avoids scoring return traffic
        if self.args.vip and "Dst IP" in df.columns:
            df = df[df["Dst IP"].astype(str) == self.args.vip]
        if df.empty:
            return {}
        X = (df.reindex(columns=self.feats).apply(pd.to_numeric, errors="coerce")
             .replace([np.inf, -np.inf], np.nan).fillna(0).to_numpy(np.float32))
        proba = self.clf.predict_proba(X)[:, 1]
        # aggregate per source IP -> max malicious prob in window
        per_src = {}
        srcs = df["Src IP"].astype(str).values if "Src IP" in df.columns else [None] * len(df)
        for src, m in zip(srcs, proba):
            if src is None or src == "nan":
                continue
            per_src[src] = max(per_src.get(src, 0.0), float(m))
        return per_src

    def smooth(self, src, m):
        a = self.args.ewma
        if a <= 0:
            return m
        prev = self.ewma.get(src, m)
        s = a * m + (1 - a) * prev
        self.ewma[src] = s
        return s

    def post(self, src, score):
        try:
            requests.post(self.args.controller + "/trust/score",
                          json={"ip": src, "score": score}, timeout=3)
        except Exception as e:
            log("POST failed for %s: %s" % (src, e))

    def loop(self):
        log("interfaces=%s window=%ds controller=%s"
            % (self.args.interfaces, self.args.window, self.args.controller))
        n = 0
        while True:
            n += 1
            pcap_dir = os.path.join(self.workdir, "pcap")
            flow_dir = os.path.join(self.workdir, "flow")
            shutil.rmtree(pcap_dir, ignore_errors=True)
            shutil.rmtree(flow_dir, ignore_errors=True)
            self.capture(pcap_dir)
            try:
                df = self.extract_flows(pcap_dir, flow_dir)
            except subprocess.TimeoutExpired:
                log("CICFlowMeter timeout, skipping window")
                continue
            if df is None or df.empty:
                continue
            per_src = self.score_flows(df)
            for src, m in sorted(per_src.items()):
                s = self.smooth(src, m)
                self.post(src, s)
            if per_src:
                log("win#%d flows=%d scored=%s" % (n, len(df),
                    {k: round(v, 2) for k, v in per_src.items()}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interfaces", default="s1-eth1,s1-eth2,s1-eth3")
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--controller", default="http://127.0.0.1:8080")
    ap.add_argument("--model", default="/opt/trust-lab/sensor-retrain/RF_model_insdn.pck")
    ap.add_argument("--features", default="/opt/trust-lab/sensor-retrain/features.json")
    ap.add_argument("--ewma", type=float, default=0.0, help="EWMA alpha (0=off)")
    ap.add_argument("--vip", default="10.0.0.100", help="only score flows to this dst")
    args = ap.parse_args()
    args.interfaces = [s for s in args.interfaces.split(",") if s]
    Sensor(args).loop()


if __name__ == "__main__":
    main()
