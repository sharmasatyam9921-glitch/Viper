"""#5 progressive escalation: a barren iteration raises agent.payload['escalation_level'],
and injection workers WIDEN their probed-parameter set on that later pass instead of
re-running the identical top-5. Pre-gate widening only — confirmation is unchanged."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_workers.vuln import sqli_probe as sqli_mod  # noqa: E402
from core.swarm_workers.vuln import xss_probe as xss_mod  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.payload_library import clear_discovered_params  # noqa: E402

# A URL with many params so the [:5] vs [:5+lvl*6] cap is observable.
_URL = "http://t/x?" + "&".join(f"p{i}=1" for i in range(20))


def _agent(level: int, technique: str) -> SwarmAgent:
    return SwarmAgent(agent_id="t", objective="x", target=_URL, technique=technique,
                      payload={"escalation_level": level}, timeout_s=6.0)


def _probed_params(worker_mod, level: int) -> set:
    seen: set[str] = set()

    async def fake(method, url, timeout=10, **kw):
        for k, v in parse_qs(urlsplit(url).query).items():
            if v and v[0] not in ("", "1"):     # the injected (non-benign) value marks the probed param
                seen.add(k)
        return HttpResp(200, {"content-type": "text/html"}, "<html>ok</html>", url)

    with patch.object(worker_mod, "fetch", fake):
        asyncio.run(worker_mod.run(_agent(level, worker_mod.TECHNIQUE)))
    return seen


def test_sqli_widens_with_escalation_level():
    lo = _probed_params(sqli_mod, 0)
    hi = _probed_params(sqli_mod, 2)
    assert len(lo) <= 5
    assert len(hi) > len(lo), "escalation level 2 must probe more params than level 0"


def test_xss_widens_with_escalation_level():
    clear_discovered_params()
    lo = _probed_params(xss_mod, 0)
    hi = _probed_params(xss_mod, 2)
    assert len(lo) <= 5
    assert len(hi) > len(lo), "escalation level 2 must probe more params than level 0"


def test_default_level_zero_is_unchanged():
    # No escalation_level in the payload behaves exactly like level 0 (no regression).
    a = SwarmAgent(agent_id="t", objective="x", target=_URL, technique="sqli_probe",
                   payload={}, timeout_s=6.0)
    seen: set[str] = set()

    async def fake(method, url, timeout=10, **kw):
        for k, v in parse_qs(urlsplit(url).query).items():
            if v and v[0] not in ("", "1"):
                seen.add(k)
        return HttpResp(200, {"content-type": "text/html"}, "ok", url)

    with patch.object(sqli_mod, "fetch", fake):
        asyncio.run(sqli_mod.run(a))
    assert len(seen) <= 5
