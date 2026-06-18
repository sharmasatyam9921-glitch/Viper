"""Tests for the BOLA/IDOR CLI wiring → worker payload threading.

Covers the thin layer that makes two-account BOLA usable end-to-end via
`viper.py hack`:
  * hack_cli flag parsing (--cookie-b / --owner-marker / ...).
  * _build_bola_config: full config, partial-config guard, no-request silence.
  * VulnSwarmCoordinator threads context["bola"] into every worker payload so
    bola_multi actually receives it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.hack_cli as hack_cli  # noqa: E402
from core.hack_cli import _build_bola_config, build_parser, run_hack_cli  # noqa: E402
from core.swarm_coordinator import VulnSwarmCoordinator  # noqa: E402
from core.agent_bus import AgentBus  # noqa: E402


# ----- flag parsing ---------------------------------------------------------

def test_parser_accepts_bola_flags():
    args = build_parser().parse_args([
        "https://t", "--cookie", "s=alice", "--owner-marker", "alice@victim.io",
        "--cookie-b", "s=bob", "--auth-header-b", "X-Tenant: b",
        "--attacker-marker", "bob@x.io",
    ])
    assert args.cookie_b == "s=bob"
    assert args.owner_marker == ["alice@victim.io"]
    assert args.auth_header_b == ["X-Tenant: b"]
    assert args.attacker_marker == ["bob@x.io"]


# ----- _build_bola_config ---------------------------------------------------

def _args(**kw):
    base = dict(cookie_b=None, auth_bearer_b=None, auth_header_b=[],
                owner_marker=[], attacker_marker=[], bola_no_unauth_control=False)
    base.update(kw)
    return type("A", (), base)()


def test_no_bola_request_returns_none():
    # Normal hunt: no -b flags, no markers → stay quiet, no config.
    assert _build_bola_config(_args(), {"Cookie": "s=alice"}) is None


def test_full_config_shape_matches_worker():
    owner = {"Cookie": "s=alice"}
    cfg = _build_bola_config(
        _args(cookie_b="s=bob", owner_marker=["alice@victim.io", "user-1001"],
              auth_header_b=["X-Tenant: b"], attacker_marker=["bob@x.io"]),
        owner,
    )
    assert cfg is not None
    # Exact keys the bola_multi worker reads.
    assert cfg["owner_headers"] == owner
    assert cfg["owner_markers"] == ["alice@victim.io", "user-1001"]
    assert cfg["attacker_headers"]["Cookie"] == "s=bob"
    assert cfg["attacker_headers"]["X-Tenant"] == "b"
    assert cfg["attacker_markers"] == ["bob@x.io"]
    assert cfg["unauth_control"] is True
    assert cfg["owner_name"] == "A" and cfg["attacker_name"] == "B"


def test_bearer_b_builds_authorization_header():
    cfg = _build_bola_config(
        _args(auth_bearer_b="TOKB", owner_marker=["alice@victim.io"]),
        {"Authorization": "Bearer TOKA"},
    )
    assert cfg["attacker_headers"]["Authorization"] == "Bearer TOKB"


def test_partial_missing_markers_disables(capsys):
    # B session but no markers → cannot confirm leaks → disabled + warning.
    cfg = _build_bola_config(_args(cookie_b="s=bob"), {"Cookie": "s=alice"})
    assert cfg is None
    assert "owner-marker" in capsys.readouterr().err


def test_partial_missing_attacker_disables(capsys):
    # Markers but no identity B → nothing to replay as → disabled + warning.
    cfg = _build_bola_config(_args(owner_marker=["alice@victim.io"]),
                             {"Cookie": "s=alice"})
    assert cfg is None
    assert "identity B" in capsys.readouterr().err


def test_missing_owner_session_disables(capsys):
    # B + markers but A is unauthenticated → can't prove A owns private data.
    cfg = _build_bola_config(
        _args(cookie_b="s=bob", owner_marker=["alice@victim.io"]), {},
    )
    assert cfg is None
    assert "identity A" in capsys.readouterr().err


def test_no_unauth_control_flag_propagates():
    cfg = _build_bola_config(
        _args(cookie_b="s=bob", owner_marker=["alice@victim.io"],
              bola_no_unauth_control=True),
        {"Cookie": "s=alice"},
    )
    assert cfg["unauth_control"] is False


# ----- coordinator threading ------------------------------------------------

def test_vuln_coordinator_threads_bola_into_worker_payload():
    coord = VulnSwarmCoordinator(bus=AgentBus(max_queue_size=100))
    bola = {"owner_headers": {"Cookie": "s=a"}, "owner_markers": ["alice@victim.io"],
            "attacker_headers": {"Cookie": "s=b"}}
    manifest = coord.build_manifest("https://t", {
        "assets": ["https://t/api/orders/1001"],
        "techniques": ["bola_multi"],
        "bola": bola,
    })
    assert manifest, "expected at least one bola_multi worker spec"
    for spec in manifest:
        assert spec.payload.get("bola") == bola


# ----- full CLI plumbing: run_hack_cli → HackMode(bola_config=...) ----------

class _FakeResult:
    hunt_id = "h_test"
    audit_path = "audit.jsonl"
    findings_count = 0
    submittable_count = 0
    surface_count = 0
    iterations = 0
    stop_reason = "done"
    timed_out = False

    def to_dict(self):
        return {"hunt_id": self.hunt_id}


def _run_cli_capturing_hackmode(monkeypatch, tmp_path, extra_args):
    """Invoke the real run_hack_cli with HackMode faked; return its init kwargs."""
    captured = {}

    class _FakeHM:
        def __init__(self, **kw):
            captured.update(kw)

        async def run(self):
            return _FakeResult()

    monkeypatch.setattr(hack_cli, "HackMode", _FakeHM)
    rc = run_hack_cli([
        "127.0.0.1", "--profile", "lab", "--no-dashboard", "--quiet",
        "--hunts-dir", str(tmp_path / "hunts"),
        "--db-path", str(tmp_path / "v.db"),
        "--output", str(tmp_path / "summary.json"),
        *extra_args,
    ])
    return rc, captured


def test_run_hack_cli_threads_bola_config_to_hackmode(monkeypatch, tmp_path):
    rc, captured = _run_cli_capturing_hackmode(monkeypatch, tmp_path, [
        "--cookie", "s=alice",
        "--owner-marker", "alice@victim.io",
        "--cookie-b", "s=bob",
    ])
    assert rc == 0
    cfg = captured.get("bola_config")
    assert cfg is not None, "run_hack_cli did not deliver bola_config to HackMode"
    assert cfg["owner_headers"] == {"Cookie": "s=alice"}
    assert cfg["owner_markers"] == ["alice@victim.io"]
    assert cfg["attacker_headers"] == {"Cookie": "s=bob"}
    # Identity A's session is still applied to every worker too.
    assert captured["auth_headers"] == {"Cookie": "s=alice"}


def test_run_hack_cli_normal_hunt_has_no_bola_config(monkeypatch, tmp_path):
    rc, captured = _run_cli_capturing_hackmode(monkeypatch, tmp_path, [
        "--cookie", "s=alice",
    ])
    assert rc == 0
    assert captured.get("bola_config") is None
