#!/usr/bin/env python3
"""
Third-party UDP reflector with a fixed response size.

Models the class of open UDP services (DNS resolvers, NTP monlist, Memcached) that an
attacker abuses in a reflection/amplification flood: the service answers every query to
the query's *source address*, so an attacker that spoofs the victim's address makes the
reflector send a much larger payload to the victim. The reflector itself is an ordinary
third party; it never contacts the victim on its own behalf.

The amplification factor is (response bytes / query bytes) and is reported by the client
side of the experiment, not asserted here.

Usage: udp_reflector.py --bind 10.0.0.61 --port 5353 --resp-bytes 4096
"""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--resp-bytes", type=int, default=4096)
    ap.add_argument("--rate-cap", type=int, default=0,
                    help="max responses per second (0 = uncapped)")
    args = ap.parse_args()

    payload = b"A" * args.resp_bytes
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    s.bind((args.bind, args.port))
    print("reflector on %s:%d, response %d bytes" % (args.bind, args.port, args.resp_bytes),
          flush=True)

    sent = 0
    window_start = time.time()
    window_sent = 0
    while True:
        try:
            _, addr = s.recvfrom(2048)
        except OSError:
            continue
        if args.rate_cap:
            now = time.time()
            if now - window_start >= 1.0:
                window_start, window_sent = now, 0
            if window_sent >= args.rate_cap:
                continue
            window_sent += 1
        try:
            s.sendto(payload, addr)
            sent += 1
        except OSError:
            pass
        if sent % 500 == 0:
            print("reflected %d" % sent, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
