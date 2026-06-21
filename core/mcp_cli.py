"""`viper.py mcp` — list and call MCP tools from configured servers.

    viper.py mcp servers                       # configured MCP servers
    viper.py mcp list [server]                 # tools (all servers, or one)
    viper.py mcp call <server> <tool> [-a k=v ...]
"""
from __future__ import annotations

import argparse
import json
from typing import List


def _parse_arg(kv: str):
    if "=" not in kv:
        k = kv.strip()
        if not k:
            raise ValueError("empty argument")
        return k, True
    k, v = kv.split("=", 1)
    k = k.strip()
    if not k:
        raise ValueError(f"empty parameter name in {kv!r}")
    try:
        return k, json.loads(v)          # int/float/bool/json
    except ValueError:
        return k, v                      # plain string


def run_mcp_cli(argv: List[str]) -> int:
    from core.mcp.registry import MCPRegistry

    p = argparse.ArgumentParser(prog="viper.py mcp",
                                description="List/call MCP tools")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("servers", help="list configured MCP servers")
    pl = sub.add_parser("list", help="list tools")
    pl.add_argument("server", nargs="?")
    pc = sub.add_parser("call", help="call a tool")
    pc.add_argument("server")
    pc.add_argument("tool")
    pc.add_argument("-a", "--arg", action="append", default=[],
                    metavar="k=v", help="tool argument (repeatable)")
    pa = sub.add_parser("add", help="register an external MCP server")
    pa.add_argument("name")
    pa.add_argument("command", nargs="+", help="server command (e.g. python -m x)")
    pa.add_argument("--cwd")
    pr = sub.add_parser("remove", help="remove an external MCP server")
    pr.add_argument("name")
    ps = sub.add_parser("scan", help="call a tool and show gate-bound findings")
    ps.add_argument("server")
    ps.add_argument("tool")
    ps.add_argument("-a", "--arg", action="append", default=[], metavar="k=v")
    ps.add_argument("--url", default="", help="default url for findings")

    args = p.parse_args(argv)

    # config edits don't need a live connection
    if args.cmd == "add":
        from core.mcp.config import add_server
        add_server(args.name, args.command, cwd=args.cwd)
        print(f"registered MCP server {args.name!r}: {' '.join(args.command)}")
        return 0
    if args.cmd == "remove":
        from core.mcp.config import remove_server
        print("removed" if remove_server(args.name) else "no such server",
              args.name)
        return 0

    reg = MCPRegistry.from_config()
    try:
        if args.cmd in (None, "servers"):
            print("configured MCP servers:")
            for name in reg.server_names:
                print(f"  {name}")
            return 0

        if args.cmd == "list":
            tools = reg.tools(args.server)
            print(f"{len(tools)} tool(s):")
            for t in tools:
                print(f"  {t.get('server','?'):<8} {t['name']:<24} "
                      f"{t.get('description','')[:50]}")
            return 0

        if args.cmd == "call":
            try:
                arguments = dict(_parse_arg(kv) for kv in args.arg)
            except ValueError as exc:
                print(f"[arg error] {exc}")
                return 1
            res = reg.call(args.server, args.tool, arguments)
            if res["is_error"]:
                print(f"[tool error] {res['text']}")
                return 1
            print(res["text"])
            return 0

        if args.cmd == "scan":
            from core.mcp_tool_bridge import call_to_findings
            try:
                arguments = dict(_parse_arg(kv) for kv in args.arg)
            except ValueError as exc:
                print(f"[arg error] {exc}")
                return 1
            findings = call_to_findings(reg, args.server, args.tool, arguments,
                                        default_url=args.url)
            print(f"{len(findings)} candidate finding(s) from "
                  f"{args.server}:{args.tool} (capped to leads until VIPER's gate "
                  f"re-confirms them):")
            for f in findings:
                print(f"  [{f['severity']:<8}] {f['vuln_type']:<28} "
                      f"conf<={f['confidence']} {f.get('url','')}")
            return 0

        p.print_help()
        return 0
    finally:
        reg.close_all()
