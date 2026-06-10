"""HTTP plumbing for chat-style AI endpoints.

The ``ChatTarget`` describes how to talk to a target's AI endpoint. The
two configurable bits are:

  * ``request_template`` — a JSON-shaped object with ``{prompt}`` markers
    that get substituted with the test payload.
  * ``response_path`` — dotted path to the assistant's text inside the
    JSON response (e.g. ``choices.0.message.content`` for OpenAI-shaped
    APIs, ``response`` for simple chatbots).

Both are blackbox-discoverable; ``detector.py`` has heuristics that try a
few common shapes when the user passes ``None``.

This module is stdlib-only and async-friendly via ``asyncio.to_thread``,
so it slots into the swarm worker model without pulling extra deps.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

logger = logging.getLogger("viper.ai_hunter.probes")

# Match prior worker user-agents so the AI hunter is consistent with the
# rest of VIPER's traffic fingerprint.
USER_AGENT = "viper-ai-hunter/1.0"


@dataclasses.dataclass
class ChatTarget:
    """Describes how to talk to a target chat / LLM endpoint."""

    url: str
    method: str = "POST"
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    # JSON-shaped object (dict/list/str) with one or more "{prompt}" tokens.
    # ``None`` means: send the prompt as raw text body.
    request_template: Any = None
    # Dotted path into the response JSON. ``None`` means: use the whole body.
    response_path: Optional[str] = None
    # Header name carrying the conversation/session id. Used for multi-turn
    # testing (memory poisoning, HITL).
    session_header: Optional[str] = None
    # Auth bearer (optional)
    auth_token: Optional[str] = None
    # Sane default for one round-trip
    timeout_s: float = 15.0


@dataclasses.dataclass
class ProbeResult:
    """One round-trip's worth of evidence."""
    status: int
    elapsed_s: float
    raw_body: str
    answer: str
    response_tokens: Optional[int] = None  # if the API echoes a usage block
    error: Optional[str] = None


def _dig(obj: Any, path: str) -> Any:
    """Navigate `obj` via a dotted path. ``0`` indexes into lists."""
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        try:
            idx = int(part)
            cur = cur[idx]
        except (ValueError, TypeError):
            try:
                cur = cur[part]
            except (KeyError, TypeError):
                return None
        except IndexError:
            return None
    return cur


def _fill_template(tpl: Any, prompt: str) -> Any:
    """Recursively replace the literal token ``{prompt}`` in any string
    inside ``tpl``. Other Python format markers are left alone — we do
    NOT use ``.format()`` because real templates contain ``{`` brackets
    in JSON code blocks that would otherwise blow up.
    """
    if isinstance(tpl, str):
        return tpl.replace("{prompt}", prompt)
    if isinstance(tpl, list):
        return [_fill_template(x, prompt) for x in tpl]
    if isinstance(tpl, dict):
        return {k: _fill_template(v, prompt) for k, v in tpl.items()}
    return tpl


def _build_body(target: ChatTarget, prompt: str) -> tuple[Optional[bytes], str]:
    """Returns (body, content_type)."""
    if target.request_template is None:
        return prompt.encode("utf-8"), "text/plain; charset=utf-8"
    payload = _fill_template(target.request_template, prompt)
    return json.dumps(payload).encode("utf-8"), "application/json"


def _extract_answer(target: ChatTarget, raw_body: str) -> str:
    if not target.response_path:
        return raw_body
    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError:
        return raw_body
    val = _dig(data, target.response_path)
    if val is None:
        return raw_body
    if isinstance(val, (dict, list)):
        return json.dumps(val)
    return str(val)


def _count_response_tokens(raw_body: str) -> Optional[int]:
    """Best-effort: look for an OpenAI-style usage block in the response."""
    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError:
        return None
    usage = data.get("usage") if isinstance(data, dict) else None
    if isinstance(usage, dict):
        for k in ("completion_tokens", "output_tokens", "response_tokens"):
            if isinstance(usage.get(k), int):
                return usage[k]
    return None


def _send_sync(target: ChatTarget, prompt: str, *,
               extra_headers: Optional[dict[str, str]] = None) -> ProbeResult:
    body, ctype = _build_body(target, prompt)
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": ctype,
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.5",
        **target.headers,
        **(extra_headers or {}),
    }
    if target.auth_token and "authorization" not in {k.lower() for k in headers}:
        headers["Authorization"] = f"Bearer {target.auth_token}"

    req = urllib.request.Request(target.url, data=body,
                                  headers=headers, method=target.method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    started = time.time()
    try:
        with opener.open(req, timeout=target.timeout_s) as r:
            raw = r.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            status = getattr(r, "status", r.getcode())
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(256 * 1024).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            raw = ""
        status = e.code
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return ProbeResult(status=0, elapsed_s=time.time() - started,
                           raw_body="", answer="", error=str(e))
    elapsed = time.time() - started
    return ProbeResult(
        status=status,
        elapsed_s=elapsed,
        raw_body=raw,
        answer=_extract_answer(target, raw),
        response_tokens=_count_response_tokens(raw),
    )


async def send_prompt(target: ChatTarget, prompt: str, *,
                      extra_headers: Optional[dict[str, str]] = None) -> ProbeResult:
    """Async send of one prompt to ``target``. Never raises."""
    try:
        return await asyncio.to_thread(_send_sync, target, prompt,
                                       extra_headers=extra_headers)
    except Exception as e:  # noqa: BLE001
        logger.debug("send_prompt unexpected error: %s", e)
        return ProbeResult(status=0, elapsed_s=0.0, raw_body="", answer="",
                           error=str(e))


async def send_conversation(target: ChatTarget, prompts: list[str], *,
                            session_id: Optional[str] = None) -> list[ProbeResult]:
    """Sequential multi-turn conversation. Passes ``session_id`` via the
    configured ``session_header`` so the target can persist state. If the
    target doesn't support sessions, each turn is independent — that's
    still useful for testing turn-order assumptions.
    """
    out: list[ProbeResult] = []
    extra: dict[str, str] = {}
    if session_id and target.session_header:
        extra[target.session_header] = session_id
    for p in prompts:
        r = await send_prompt(target, p, extra_headers=extra)
        out.append(r)
        if r.error:
            break
    return out


# ── String helpers shared by testers ──────────────────────────────────────

_WS_RE = re.compile(r"\s+")


def normalize(s: str) -> str:
    """Lowercase + collapse whitespace. Useful for marker matching."""
    return _WS_RE.sub(" ", (s or "").lower()).strip()


def any_match(patterns: list[str], text: str) -> Optional[str]:
    """First pattern that matches ``text`` (case-insensitive). Returns the
    matched substring or ``None``.
    """
    if not text:
        return None
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            return m.group(0)
    return None
