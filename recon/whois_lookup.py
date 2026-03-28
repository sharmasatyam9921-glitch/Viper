"""
VIPER 4.0 - WHOIS Lookup with Caching
=======================================
WHOIS domain intelligence: registrar, creation/expiry dates, nameservers, org.

Strategy:
  1. Try ``python-whois`` library (pip install python-whois)
  2. Fall back to subprocess ``whois`` command
  3. Cache results in-memory to avoid repeated lookups

Stdlib + optional python-whois. No other dependencies.
"""

import json
import logging
import re
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger("viper.recon.whois")

# In-memory cache: domain -> (result_dict, timestamp)
_cache: Dict[str, tuple] = {}
_CACHE_TTL = 3600  # 1 hour


# =============================================================================
# Public API
# =============================================================================

def lookup(domain: str, max_retries: int = 3,
           use_cache: bool = True) -> dict:
    """
    WHOIS lookup with retry/backoff and caching.

    Args:
        domain: Domain to query (e.g. "example.com")
        max_retries: Retry attempts with exponential backoff
        use_cache: Whether to use in-memory cache

    Returns:
        {
            "domain": "example.com",
            "registrar": "...",
            "creation_date": "2000-01-01T00:00:00",
            "expiration_date": "2030-01-01T00:00:00",
            "updated_date": "2024-01-01T00:00:00",
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "org": "Example Inc.",
            "country": "US",
            "emails": ["admin@example.com"],
            "dnssec": "unsigned",
            "source": "python-whois" | "subprocess" | "cache",
            "error": None | "message"
        }
    """
    domain = domain.strip().lower()

    # Check cache
    if use_cache and domain in _cache:
        result, ts = _cache[domain]
        if time.time() - ts < _CACHE_TTL:
            cached = dict(result)
            cached["source"] = "cache"
            return cached

    # Try python-whois library first
    result = _lookup_python_whois(domain, max_retries)

    # Fall back to subprocess
    if result.get("error") or not result.get("registrar"):
        sub_result = _lookup_subprocess(domain, max_retries)
        if not sub_result.get("error") and sub_result.get("registrar"):
            result = sub_result

    # Cache the result
    if use_cache and not result.get("error"):
        _cache[domain] = (result, time.time())

    return result


def clear_cache():
    """Clear the in-memory WHOIS cache."""
    _cache.clear()


# =============================================================================
# python-whois backend
# =============================================================================

def _lookup_python_whois(domain: str, max_retries: int) -> dict:
    """Try lookup via python-whois library."""
    try:
        import whois
    except ImportError:
        logger.debug("python-whois not installed, skipping library lookup")
        return _empty_result(domain, error="python-whois not installed")

    last_error = None
    for attempt in range(max_retries):
        try:
            w = whois.whois(domain)
            if w and (w.domain_name or w.registrar or w.creation_date):
                return _parse_whois_obj(w, domain, source="python-whois")

            # Empty result — retry
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                logger.debug("WHOIS empty, retrying in %ds (%d/%d)",
                             delay, attempt + 1, max_retries)
                time.sleep(delay)
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                logger.debug("WHOIS error: %s, retrying in %ds", e, delay)
                time.sleep(delay)

    return _empty_result(domain, error=last_error or "Empty WHOIS response")


def _parse_whois_obj(w, domain: str, source: str) -> dict:
    """Convert python-whois result object to structured dict."""
    def _first(val):
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def _dt(val):
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        if isinstance(val, datetime):
            return val.isoformat()
        return str(val) if val else None

    def _ns_list(val):
        if val is None:
            return []
        if isinstance(val, str):
            return [val.lower()]
        return sorted(set(s.lower() for s in val if s))

    return {
        "domain": domain,
        "registrar": getattr(w, "registrar", None),
        "creation_date": _dt(getattr(w, "creation_date", None)),
        "expiration_date": _dt(getattr(w, "expiration_date", None)),
        "updated_date": _dt(getattr(w, "updated_date", None)),
        "nameservers": _ns_list(getattr(w, "name_servers", None)),
        "org": getattr(w, "org", None),
        "country": getattr(w, "country", None),
        "emails": _ns_list(getattr(w, "emails", None)),
        "dnssec": getattr(w, "dnssec", None),
        "source": source,
        "error": None,
    }


# =============================================================================
# Subprocess fallback
# =============================================================================

def _lookup_subprocess(domain: str, max_retries: int) -> dict:
    """Fall back to system ``whois`` command."""
    last_error = None
    for attempt in range(max_retries):
        try:
            proc = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_whois_text(proc.stdout, domain)

            last_error = proc.stderr.strip() or "Empty whois output"
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)

        except FileNotFoundError:
            return _empty_result(domain, error="whois command not found")
        except subprocess.TimeoutExpired:
            last_error = "whois command timed out"
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
        except Exception as e:
            last_error = str(e)
            break

    return _empty_result(domain, error=last_error)


def _parse_whois_text(text: str, domain: str) -> dict:
    """Parse raw WHOIS text output into structured dict."""
    result = _empty_result(domain)
    result["source"] = "subprocess"
    result["error"] = None

    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
        "expiration_date": r"(?:Expir(?:ation|y)|Registry Expiry)\s*Date:\s*(.+)",
        "updated_date": r"Updated?\s*Date:\s*(.+)",
        "org": r"(?:Registrant\s+)?Organi[sz]ation:\s*(.+)",
        "country": r"Registrant\s+Country:\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
    }

    for field, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result[field] = match.group(1).strip()

    # Nameservers
    ns_matches = re.findall(r"Name\s*Server:\s*(\S+)", text, re.IGNORECASE)
    if ns_matches:
        result["nameservers"] = sorted(set(s.lower().rstrip(".") for s in ns_matches))

    # Emails
    email_matches = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", text)
    if email_matches:
        result["emails"] = sorted(set(e.lower() for e in email_matches))

    return result


# =============================================================================
# Helpers
# =============================================================================

def _empty_result(domain: str = "", error: str = None) -> dict:
    return {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "nameservers": [],
        "org": None,
        "country": None,
        "emails": [],
        "dnssec": None,
        "source": None,
        "error": error,
    }


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"[*] WHOIS lookup for: {domain}\n")
    result = lookup(domain)

    for k, v in result.items():
        if v is not None and v != [] and v != "":
            print(f"  {k:20s}: {v}")
