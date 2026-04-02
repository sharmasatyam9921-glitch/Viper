"""Shared utility functions for VIPER.

Canonical implementations of helpers used across multiple modules.
"""

import json
import re
import logging
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("viper.utils")


def extract_domain(url: str) -> str:
    """Extract the domain/hostname from a URL string.

    Handles URLs with or without scheme, ports, and paths.
    """
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url.split("/")[0]
    return host or ""


def extract_json(text: str) -> Optional[dict]:
    """Extract first JSON object from LLM response text.

    Tries in order:
    1. Raw JSON parse
    2. Markdown code fence extraction
    3. Bare JSON object search
    """
    if not text:
        return None
    # Try raw parse
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    # Find JSON in markdown code fence
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    # Find bare JSON object
    match = re.search(r'\{[^{}]*(?:"[^"]*"\s*:\s*[^{}]*)+\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None
