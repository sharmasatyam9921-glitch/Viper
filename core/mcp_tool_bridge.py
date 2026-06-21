"""Turn external MCP tool output into gate-bound candidate findings.

VIPER can *call* an external MCP tool (e.g. a scanner in an offensive-tool
arsenal), but it does NOT trust the result: each reported issue becomes a
candidate finding with capped confidence, tagged ``source=mcp:<server>:<tool>``,
which the independent validation gate then re-confirms with its own probes. So an
external tool's false positives are filtered out before anything is submittable —
VIPER's gate is the trust layer on top of borrowed breadth.
"""
from __future__ import annotations

import asyncio
import json
from typing import List, Optional

# External output is never trusted above a lead until the gate re-confirms it.
_EXTERNAL_CONFIDENCE_CAP = 0.5
_ITEM_KEYS = ("findings", "vulnerabilities", "results", "issues", "alerts")


def _coerce_items(text: str) -> list:
    """Pull a list of issue dicts out of a tool's text result, if any."""
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in _ITEM_KEYS:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        if data.get("vuln_type") or data.get("type"):
            return [data]
    return []


def normalize_tool_result(server: str, tool: str, result: dict,
                          *, default_url: str = "") -> List[dict]:
    """Map one MCP tool result ({text, is_error, raw}) to candidate findings.

    Recognizes a structured issue array (findings/vulnerabilities/results/...);
    each item -> a VIPER finding with confidence capped (external = lead until the
    gate confirms). Unstructured/empty/error results yield no findings.
    """
    if not isinstance(result, dict) or result.get("is_error"):
        return []
    src = f"mcp:{server}:{tool}"
    out: List[dict] = []
    for it in _coerce_items(result.get("text", "") or ""):
        vt = str(it.get("vuln_type") or it.get("type") or it.get("name") or "info")
        try:
            conf = float(it.get("confidence"))
        except (TypeError, ValueError):
            conf = 0.4
        out.append({
            "type": vt.split(":")[0],
            "vuln_type": vt,
            "title": str(it.get("title") or f"{vt} (reported by {src})"),
            "url": str(it.get("url") or it.get("endpoint") or default_url or ""),
            "parameter": it.get("parameter") or it.get("param"),
            "payload": it.get("payload"),
            "severity": str(it.get("severity") or "info").lower(),
            "evidence": str(it.get("evidence") or it.get("detail")
                            or it.get("description") or ""),
            "confidence": min(_EXTERNAL_CONFIDENCE_CAP, max(0.0, conf)),
            "cwe": it.get("cwe"),
            "source": src,
            "needs_manual_verification": True,
        })
    return out


def call_to_findings(registry, server: str, tool: str,
                     arguments: Optional[dict] = None, *,
                     default_url: str = "") -> List[dict]:
    """Call an external MCP tool and return normalized candidate findings (sync)."""
    res = registry.call(server, tool, arguments or {})
    return normalize_tool_result(server, tool, res, default_url=default_url)


async def acall_to_findings(registry, server: str, tool: str,
                            arguments: Optional[dict] = None, *,
                            default_url: str = "") -> List[dict]:
    return await asyncio.to_thread(call_to_findings, registry, server, tool,
                                   arguments, default_url=default_url)
