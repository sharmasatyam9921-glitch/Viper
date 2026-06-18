"""Authenticated / JS-aware capture support.

Pure-Python traffic processing (``proxy_pipeline``, ``session_capture``) works on
traffic captured by ANY means — a Burp/HAR export, manual capture, or the optional
Playwright driver (``viper_browser``). The Playwright driver is best-effort: if the
package is not installed, :func:`viper_browser.available` returns False and the
rest of the pipeline still functions. No hard browser dependency.
"""
from __future__ import annotations

from .proxy_pipeline import RequestCorpus, request_signature   # noqa: F401
from .session_capture import (   # noqa: F401
    bola_plan,
    build_session_context,
    role_diff_candidates,
    session_context_from_har,
)
