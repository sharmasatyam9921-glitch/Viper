"""`viper.py hack --oob / --mcp-plan` wiring helpers."""
from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hack_cli import _build_oob, _load_mcp_plan  # noqa: E402


def _ns(**kw):
    base = dict(oob=False, oob_domain="oob.local", oob_public_host=None,
                oob_http_port=0, oob_dns_port=0, oob_no_dns=True, mcp_plan=None)
    base.update(kw)
    return Namespace(**base)


def test_build_oob_disabled_by_default():
    assert _build_oob(_ns()) is None


def test_build_oob_starts_listener():
    srv = _build_oob(_ns(oob=True))
    try:
        assert srv is not None and srv.http_port > 0
        c = srv.new_canary("ssrf")           # usable: mints issued canaries
        assert c.token and c.token in srv._issued
    finally:
        if srv:
            srv.stop()


def test_load_mcp_plan_inline_array():
    plan = _load_mcp_plan(_ns(mcp_plan='[{"server":"a","tool":"scan"}]'))
    assert plan == [{"server": "a", "tool": "scan"}]


def test_load_mcp_plan_single_object_wrapped():
    plan = _load_mcp_plan(_ns(mcp_plan='{"server":"a","tool":"t"}'))
    assert plan == [{"server": "a", "tool": "t"}]


def test_load_mcp_plan_from_file(tmp_path):
    f = tmp_path / "plan.json"
    f.write_text('[{"server":"a","tool":"t","arguments":{"x":1}}]', encoding="utf-8")
    plan = _load_mcp_plan(_ns(mcp_plan=str(f)))
    assert plan[0]["arguments"] == {"x": 1}


def test_load_mcp_plan_none_and_invalid():
    assert _load_mcp_plan(_ns(mcp_plan=None)) is None
    assert _load_mcp_plan(_ns(mcp_plan="{not json")) is None
    assert _load_mcp_plan(_ns(mcp_plan='"a string"')) is None   # not array/object
