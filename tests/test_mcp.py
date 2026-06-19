"""MCP: server framework (in-process) + real client<->subprocess round-trip."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp import protocol as P  # noqa: E402
from core.mcp.server import MCPServer, ToolError  # noqa: E402
from core.mcp.registry import MCPRegistry  # noqa: E402
from core.mcp_client import MCPClient, MCPError  # noqa: E402

_ROOT = str(Path(__file__).resolve().parents[1])


# --- in-process server dispatch (fast, no subprocess) ----------------------

def _server():
    s = MCPServer(name="t", version="9.9")

    @s.tool("echo", "echo back", {"type": "object",
            "properties": {"msg": {"type": "string"}}})
    def _echo(args):
        return {"echoed": args.get("msg", "")}

    @s.tool("boom", "always fails")
    def _boom(_args):
        raise ToolError("kaboom")

    @s.tool("crash", "raises unexpectedly")
    def _crash(_args):
        raise ValueError("unexpected")
    return s


def test_initialize_reports_server_info():
    res = _server().handle(P.request(1, "initialize", {}))
    assert res["result"]["serverInfo"] == {"name": "t", "version": "9.9"}
    assert res["result"]["protocolVersion"] == P.PROTOCOL_VERSION


def test_tools_list():
    res = _server().handle(P.request(2, "tools/list"))
    names = {t["name"] for t in res["result"]["tools"]}
    assert names == {"echo", "boom", "crash"}


def test_tools_call_success():
    res = _server().handle(P.request(3, "tools/call",
                                     {"name": "echo", "arguments": {"msg": "hi"}}))
    assert '"echoed": "hi"' in res["result"]["content"][0]["text"]
    assert not res["result"].get("isError")


def test_tool_error_is_reported_not_raised():
    res = _server().handle(P.request(4, "tools/call", {"name": "boom"}))
    assert res["result"]["isError"] and "kaboom" in res["result"]["content"][0]["text"]


def test_unexpected_exception_becomes_tool_error():
    res = _server().handle(P.request(5, "tools/call", {"name": "crash"}))
    assert res["result"]["isError"] and "ValueError" in res["result"]["content"][0]["text"]


def test_unknown_tool_is_tool_error():
    res = _server().handle(P.request(6, "tools/call", {"name": "nope"}))
    assert res["result"]["isError"] and "unknown tool" in res["result"]["content"][0]["text"]


def test_unknown_method_is_jsonrpc_error():
    res = _server().handle(P.request(7, "frobnicate"))
    assert res["error"]["code"] == P.METHOD_NOT_FOUND


def test_initialized_notification_has_no_reply():
    assert _server().handle(P.notification("notifications/initialized")) is None


# --- real subprocess round-trip (network-free via the mitre server) --------

def _mitre_client():
    return MCPClient([sys.executable, "-m", "core.mcp.servers.mitre_mcp"],
                     cwd=_ROOT, timeout=30.0)


def test_subprocess_handshake_and_list_tools():
    with _mitre_client() as c:
        assert c.server_info.get("name") == "viper-mitre"
        names = {t["name"] for t in c.list_tools()}
        assert {"mitre_stats", "mitre_capec_for_cwe"} <= names


def test_subprocess_call_tool_returns_offline_data():
    with _mitre_client() as c:
        stats = c.call_tool("mitre_stats")
        assert not stats["is_error"] and "cwe_entries" in stats["text"]
        # CWE-79 (XSS) -> CAPEC patterns, deterministic from vendored data
        capec = c.call_tool("mitre_capec_for_cwe", {"cwe_id": "79"})
        assert not capec["is_error"] and "CAPEC" in capec["text"]


def test_subprocess_unknown_tool_does_not_raise():
    with _mitre_client() as c:
        r = c.call_tool("does_not_exist")
        assert r["is_error"] and "unknown tool" in r["text"]


def test_client_bad_command_raises_or_skips():
    # A non-existent server command must fail cleanly, not hang.
    with pytest.raises(Exception):
        MCPClient([sys.executable, "-c", "import sys; sys.exit(1)"],
                  cwd=_ROOT, timeout=10.0).start()


# --- registry --------------------------------------------------------------

def test_registry_aggregates_tools_across_servers():
    with MCPRegistry() as reg:
        assert set(reg.server_names) >= {"mitre", "cve"}
        tagged = reg.tools()
        servers = {t["server"] for t in tagged}
        assert "mitre" in servers
        names = {(t["server"], t["name"]) for t in tagged}
        assert ("mitre", "mitre_stats") in names


def test_registry_call_routes_and_cve_build_cpe_is_offline():
    with MCPRegistry() as reg:
        r = reg.call("cve", "cve_build_cpe", {"tech": "apache", "version": "2.4.49"})
        assert not r["is_error"] and "cpe:2.3:a:apache" in r["text"]


def test_registry_unknown_server_raises():
    with MCPRegistry() as reg:
        with pytest.raises(KeyError):
            reg.call("nope", "x")


def test_registry_skips_failing_server_in_tools():
    reg = MCPRegistry(servers={"bad": [sys.executable, "-c", "import sys; sys.exit(1)"]},
                      cwd=_ROOT, timeout=8.0)
    try:
        assert reg.tools() == []         # failing server skipped, not fatal
    finally:
        reg.close_all()


# --- run_stdio loop (in-process via StringIO) ------------------------------

def test_run_stdio_loop_handles_frames_and_parse_errors():
    import io
    s = _server()
    inp = io.StringIO("".join([
        P.encode(P.request(1, "initialize", {})),
        "this is not json\n",
        P.encode(P.request(2, "tools/list")),
        P.encode(P.notification("notifications/initialized")),   # no reply
        P.encode(P.request(3, "tools/call", {"name": "echo", "arguments": {"msg": "y"}})),
    ]))
    out = io.StringIO()
    s.run_stdio(stdin=inp, stdout=out)
    msgs = [P.decode(l) for l in out.getvalue().splitlines() if l.strip()]
    # initialize result, parse error, tools/list result, tools/call result (4 total)
    assert len(msgs) == 4
    assert msgs[0]["result"]["serverInfo"]["name"] == "t"
    assert msgs[1]["error"]["code"] == P.PARSE_ERROR
    assert "echoed" in msgs[3]["result"]["content"][0]["text"]


# --- servers built in-process (covers the wrapped handlers) -----------------

def test_mitre_server_build_handlers_offline():
    from core.mcp.servers.mitre_mcp import build
    s = build()
    r = s.handle(P.request(1, "tools/call", {"name": "mitre_stats"}))
    assert "cwe_entries" in r["result"]["content"][0]["text"]
    r2 = s.handle(P.request(2, "tools/call",
                            {"name": "mitre_capec_for_cwe", "arguments": {"cwe_id": "79"}}))
    assert "CAPEC" in r2["result"]["content"][0]["text"]


def test_cve_server_build_handler_offline():
    from core.mcp.servers.cve_mcp import build
    s = build()
    r = s.handle(P.request(1, "tools/call",
                           {"name": "cve_build_cpe",
                            "arguments": {"tech": "nginx", "version": "1.18.0"}}))
    assert "cpe:2.3:a" in r["result"]["content"][0]["text"]


# --- client extras ---------------------------------------------------------

def test_client_acall_tool_async_and_server_info():
    import asyncio
    with _mitre_client() as c:
        assert c.server_info.get("version")
        r = asyncio.run(c.acall_tool("mitre_stats"))
        assert not r["is_error"] and "cwe_entries" in r["text"]
        c.start()                        # double start is a no-op


# --- CLI -------------------------------------------------------------------

def test_cli_servers(capsys):
    from core.mcp_cli import run_mcp_cli
    assert run_mcp_cli(["servers"]) == 0
    assert "mitre" in capsys.readouterr().out


def test_cli_list_and_call(capsys):
    from core.mcp_cli import run_mcp_cli
    assert run_mcp_cli(["list", "mitre"]) == 0
    assert "mitre_stats" in capsys.readouterr().out
    rc = run_mcp_cli(["call", "mitre", "mitre_capec_for_cwe", "-a", "cwe_id=89"])
    assert rc == 0 and "CAPEC" in capsys.readouterr().out


def test_cli_call_tool_error_returns_1(capsys):
    from core.mcp_cli import run_mcp_cli
    rc = run_mcp_cli(["call", "mitre", "no_such_tool"])
    assert rc == 1 and "tool error" in capsys.readouterr().out


def test_cli_empty_arg_key_is_rejected(capsys):
    from core.mcp_cli import run_mcp_cli
    rc = run_mcp_cli(["call", "mitre", "mitre_stats", "-a", "=oops"])
    assert rc == 1 and "arg error" in capsys.readouterr().out


# --- review-hardening regressions ------------------------------------------

def test_server_does_not_crash_on_null_or_nonobject():
    s = _server()
    assert s.handle(None)["error"]["code"] == P.INVALID_REQUEST
    assert s.handle([1, 2])["error"]["code"] == P.INVALID_REQUEST
    assert s.handle("string")["error"]["code"] == P.INVALID_REQUEST


def test_unknown_notification_or_null_id_gets_no_error_reply():
    # An unknown method with no id (or id:null) is a notification: silently
    # ignored, never a method-not-found error. A known method still replies.
    s = _server()
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/progress"}) is None
    assert s.handle({"jsonrpc": "2.0", "id": None, "method": "some/unknown"}) is None
    assert s.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})["id"] == 5


def test_run_stdio_survives_a_null_line():
    import io
    s = _server()
    inp = io.StringIO("null\n" + P.encode(P.request(1, "tools/list")))
    out = io.StringIO()
    s.run_stdio(stdin=inp, stdout=out)              # must not raise
    msgs = [P.decode(l) for l in out.getvalue().splitlines() if l.strip()]
    assert msgs[0]["error"]["code"] == P.INVALID_REQUEST
    assert "tools" in msgs[1]["result"]


def test_encode_rejects_nan_to_protect_the_wire():
    import pytest as _pt
    with _pt.raises(ValueError):
        P.encode({"jsonrpc": "2.0", "id": 1, "result": {"x": float("nan")}})


def test_tool_returning_nan_is_reported_not_crashed():
    s = MCPServer("t")

    @s.tool("nan", "returns NaN")
    def _n(_a):
        return {"v": float("inf")}
    res = s.handle(P.request(1, "tools/call", {"name": "nan"}))
    assert res["result"]["isError"] and "serializable" in res["result"]["content"][0]["text"]


def test_start_failure_does_not_leak_subprocess():
    # A process that exits immediately can't complete the handshake; start() must
    # reap it and raise rather than leave a child or a live _proc handle.
    c = MCPClient([sys.executable, "-c", "import sys; sys.exit(0)"],
                  cwd=_ROOT, timeout=8.0)
    with pytest.raises(MCPError):
        c.start()
    assert c._proc is None              # reaped


def test_registry_caches_failed_server(monkeypatch):
    reg = MCPRegistry(servers={"bad": [sys.executable, "-c", "import sys; sys.exit(1)"]},
                      cwd=_ROOT, timeout=8.0)
    try:
        assert reg.tools() == []
        assert "bad" in reg._failed
        # second access must NOT respawn — it raises straight from the cache
        with pytest.raises(MCPError):
            reg.client("bad")
    finally:
        reg.close_all()


def test_close_all_is_resilient_to_a_bad_client():
    reg = MCPRegistry(cwd=_ROOT)

    class _BadClient:
        def close(self):
            raise RuntimeError("boom")
    reg._clients["x"] = _BadClient()
    reg.close_all()                     # must not raise
    assert reg._clients == {}
