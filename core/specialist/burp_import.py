"""Import Burp Suite traffic into VIPER for two-account BOLA/IDOR.

The specialist BOLA workflow is *capture then replay*: you browse the target as
identity **A** with Burp in the loop, then replay A's object-referencing
requests as identity **B** and check for cross-user reads. Burp already holds
exactly what's needed — every request A made, with A's session headers. This
module ingests a Burp export so VIPER can drive ``find_bola`` from real,
observed object URLs instead of blind discovery.

Input: Burp's XML ("Proxy history -> Save items" or right-click -> "Save selected
items"). Each ``<item>`` carries the URL, method, status and the full raw
request (base64), from which we recover the request headers — including the
``Cookie`` / ``Authorization`` that identify A's session.

Output:
  * :func:`object_urls`     - id-bearing URLs (BOLA candidates) A actually hit.
  * :func:`session_headers` - A's dominant session auth headers (Cookie/Bearer).
  * :func:`load_burp`       - parse a file into ``BurpItem`` records.

Read-only: this only reads an export the operator produced; it sends nothing.
The XML is operator-supplied (their own Burp file), parsed with the stdlib.
"""

from __future__ import annotations

import base64
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional
from xml.etree import ElementTree as ET

from .bola_engine import id_bearing_urls

logger = logging.getLogger("viper.specialist.burp_import")

# Header names that carry a session/identity (lowercased for matching).
_AUTH_HEADERS = (
    "cookie", "authorization", "x-auth-token", "x-api-key", "x-access-token",
    "x-session-token", "x-csrf-token", "x-xsrf-token", "x-auth", "api-key",
)


@dataclass
class BurpItem:
    url: str
    method: str = "GET"
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)  # request headers, original case

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive request-header lookup."""
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


def _decode_request(node: Optional[ET.Element]) -> str:
    if node is None or node.text is None:
        return ""
    raw = node.text
    if (node.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""
    return raw


def _request_headers(raw_request: str) -> dict:
    """Parse 'Name: value' headers from a raw HTTP request (after the request line)."""
    headers: dict = {}
    if not raw_request:
        return headers
    # Headers end at the first blank line; tolerate \r\n or \n.
    lines = raw_request.replace("\r\n", "\n").split("\n")
    for line in lines[1:]:           # skip the request line
        if line == "":               # blank line -> body starts
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name:
            headers[name] = value.strip()
    return headers


def parse_burp_xml(xml: str) -> List[BurpItem]:
    """Parse a Burp items XML string into BurpItem records. Never raises."""
    if not xml or not xml.strip():
        return []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.warning("burp import: XML parse error: %s", e)
        return []
    items: List[BurpItem] = []
    for it in root.iter("item"):
        url = (it.findtext("url") or "").strip()
        if not url:
            continue
        method = (it.findtext("method") or "GET").strip() or "GET"
        status_txt = (it.findtext("status") or "").strip()
        try:
            status = int(status_txt) if status_txt and status_txt.lstrip("-").isdigit() else None
        except ValueError:
            status = None
        headers = _request_headers(_decode_request(it.find("request")))
        items.append(BurpItem(url=url, method=method, status=status, headers=headers))
    return items


def load_burp(path) -> List[BurpItem]:
    """Read a Burp XML export file into BurpItem records. Never raises."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_burp_xml(fh.read())
    except OSError as e:
        logger.warning("burp import: cannot read %s: %s", path, e)
        return []


def object_urls(items: List[BurpItem], *, only_success: bool = True) -> List[str]:
    """The id-bearing object URLs the captured identity actually requested.

    These are the BOLA candidates: GET requests to URLs carrying a numeric/UUID
    id or id-like query param. ``only_success`` keeps just 2xx responses (the
    objects the identity could actually read), de-duplicated, order-preserved.
    """
    urls: List[str] = []
    seen = set()
    for it in items:
        if it.method.upper() != "GET":
            continue
        if only_success and it.status is not None and not (200 <= it.status < 300):
            continue
        if it.url not in seen:
            seen.add(it.url)
            urls.append(it.url)
    return id_bearing_urls(urls)


def session_headers(items: List[BurpItem]) -> dict:
    """The dominant session/auth headers across the capture (identity's session).

    For each auth-ish header (Cookie, Authorization, X-Auth-Token, ...), pick the
    value seen most often — that's the session the identity browsed with. Returns
    a headers dict suitable for use as a BOLA Session's ``headers``.
    """
    buckets: dict = {}
    for it in items:
        for name, value in it.headers.items():
            if name.lower() in _AUTH_HEADERS and value:
                buckets.setdefault(name, Counter())[value] += 1
    out: dict = {}
    for name, counter in buckets.items():
        out[name] = counter.most_common(1)[0][0]
    return out
