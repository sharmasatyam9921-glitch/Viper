"""`viper.py oob` — run the out-of-band interaction listener, or self-demo it.

    viper.py oob start [--http-port 8080] [--dns-port 53] [--base-domain oob.example] [--public-host 1.2.3.4]
    viper.py oob demo                       # localhost end-to-end proof (no network)
"""
from __future__ import annotations

import argparse
import time
from typing import List


def run_oob_cli(argv: List[str]) -> int:
    from core.oob import OOBServer
    from core.oob.canary import payloads_for

    p = argparse.ArgumentParser(prog="viper.py oob",
                                description="Out-of-band interaction listener")
    sub = p.add_subparsers(dest="cmd")
    ps = sub.add_parser("start", help="run the listener (blocks until Ctrl-C)")
    ps.add_argument("--http-port", type=int, default=8080)
    ps.add_argument("--dns-port", type=int, default=0,
                    help="0 disables DNS; 53 needs privilege")
    ps.add_argument("--base-domain", default="oob.local")
    ps.add_argument("--public-host", default=None,
                    help="public hostname/IP the target can reach")
    ps.add_argument("--http-host", default="0.0.0.0")
    sub.add_parser("demo", help="localhost end-to-end self-test")

    args = p.parse_args(argv)

    if args.cmd == "demo":
        return _demo()

    if args.cmd == "start":
        srv = OOBServer(base_domain=args.base_domain, http_host=args.http_host,
                        http_port=args.http_port, dns_port=args.dns_port,
                        enable_dns=bool(args.dns_port),
                        public_host=args.public_host).start()
        print(f"OOB listener up: HTTP :{srv.http_port}"
              + (f"  DNS :{srv.dns_port}" if srv.dns_port else "  (DNS disabled)"))
        print(f"canary base: <token>.{args.base_domain}  "
              f"(public host: {args.public_host or '<set --public-host>'})")
        print("waiting for interactions; Ctrl-C to stop.")
        seen = 0
        try:
            while True:
                time.sleep(1.0)
                cur = srv.store.count()
                for it in srv.store.all()[seen:]:
                    print(f"  [{it.protocol}] token={it.token} from={it.source_ip} "
                          f"{it.detail}")
                seen = cur
        except KeyboardInterrupt:
            print("\nstopping.")
        finally:
            srv.stop()
        return 0

    p.print_help()
    return 0


def _demo() -> int:
    """Prove the full loop on localhost: fire an HTTP callback at a canary and
    confirm the listener recorded it (no external network)."""
    import urllib.request
    from core.oob import OOBServer

    with OOBServer(base_domain="oob.local", enable_dns=False) as oob:
        c = oob.new_canary("ssrf")
        # Simulate a vulnerable backend fetching the canary URL (the SSRF target
        # would do this server-side). Use the loopback http_url.
        url = f"http://127.0.0.1:{oob.http_port}/{c.token}"
        print(f"canary token: {c.token}")
        print(f"sample SSRF payload: {payloads_demo(c)}")
        try:
            urllib.request.urlopen(url, timeout=5).read()
        except Exception as exc:
            print(f"callback failed: {exc}")
            return 1
        ok = oob.poll(c.token, timeout=5)
        print(f"interaction recorded: {ok}")
        print(f"was_hit({c.token}): {oob.was_hit(c.token)}")
        return 0 if ok else 1


def payloads_demo(c):
    from core.oob.canary import payloads_for
    return payloads_for(c)["ssrf"]
