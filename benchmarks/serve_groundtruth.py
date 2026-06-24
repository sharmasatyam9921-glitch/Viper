"""Serve the deliberately-vulnerable ground-truth app on a FIXED port (authorized
local target for end-to-end dashboard-scan testing). Usage: python -m
benchmarks.serve_groundtruth [port]"""
import sys
import time
from http.server import ThreadingHTTPServer

from benchmarks.ground_truth import _Handler

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"ground-truth target on http://127.0.0.1:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
