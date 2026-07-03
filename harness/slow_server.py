#!/usr/bin/env python3
"""
HTTP server with a BOUNDED worker pool (models Apache-style MaxClients). Unlike Python's
default ThreadingHTTPServer (unbounded threads, immune to Slowloris), this caps concurrent
request handling at --workers; slow connections (Slowloris) occupy workers and, once the
pool is exhausted, legitimate requests queue and time out. The worker cap doubles as the
tier's HTTP capacity (SvH high, SvL low).

Usage: slow_server.py --bind IP --port 80 --workers N --page TEXT
"""
import argparse
import socketserver
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler


class PoolServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, workers):
        self.pool = ThreadPoolExecutor(max_workers=workers)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        self.pool.submit(self._handle, request, client_address)

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            pass
        finally:
            self.shutdown_request(request)


def make_handler(page, page_bytes, delay_ms):
    # Pad the response so a slow-reading client can fill the send buffer (slow-read attack).
    body = page.encode()
    if page_bytes > len(body):
        body = body + b" " * (page_bytes - len(body))

    class H(BaseHTTPRequestHandler):
        def _respond(self):
            # tarpit: respond slowly on purpose (looks overloaded-but-alive, preserves deception)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._respond()

        def do_POST(self):
            # Read the full request body (blocks on a slow body -> holds the worker: RUDY).
            length = int(self.headers.get("Content-Length", 0) or 0)
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(4096, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._respond()

        def log_message(self, *a):
            pass
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--page", default="served")
    ap.add_argument("--page-bytes", type=int, default=65536,
                    help="pad response to this size (lets slow-read fill the send buffer)")
    ap.add_argument("--delay-ms", type=int, default=0,
                    help="tarpit: delay each response by N ms (slow-but-alive)")
    args = ap.parse_args()
    srv = PoolServer((args.bind, args.port),
                     make_handler(args.page, args.page_bytes, args.delay_ms), args.workers)
    srv.serve_forever()


if __name__ == "__main__":
    main()
