"""Worker-facing adaptive WAF-bypass fetch.

`adaptive_fetch` sends an attack payload and, if the response looks WAF-blocked,
automatically retries encoding mutations until one gets through — then remembers
the winning mutation per host so subsequent probes skip straight to it. A process-
wide engine carries that learning across workers within a hunt. On total block it
returns the (blocked) result with ``blocked=True`` — never a fabricated success.
"""
from __future__ import annotations

from typing import Awaitable, Callable, Optional
from urllib.parse import urlsplit

from core.waf_bypass import AdaptiveBypass, BypassResult

from ._http import fetch

# Shared across workers in a process so a host's learned bypass is reused.
_ENGINE = AdaptiveBypass()


def reset_learning() -> None:
    _ENGINE._learned.clear()


async def adaptive_fetch(method: str,
                         build_url: Callable[[str], str],
                         payload: str,
                         *,
                         target: Optional[str] = None,
                         timeout: float = 10.0,
                         **fetch_kwargs) -> BypassResult:
    """Adaptively send `payload`. `build_url(variant)` embeds a payload variant
    into the request URL. Returns a BypassResult (response + which mutation won).
    """
    async def send(variant: str):
        return await fetch(method, build_url(variant), timeout=timeout, **fetch_kwargs)

    key = target or build_url(payload)
    host = urlsplit(key).netloc or key
    return await _ENGINE.run(send, payload, target=host)
