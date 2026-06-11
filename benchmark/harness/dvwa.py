"""DVWA auth-setup adapter for the benchmark harness.

DVWA gates every vulnerable page behind a login and a per-request CSRF token,
and ships with an empty DB. Before VIPER can hunt it authenticated we must,
against a freshly-booted container:

  1. create/reset the database (/setup.php),
  2. log in as admin/password (/login.php — CSRF token required),
  3. drop the security level to "low" (/security.php — CSRF token required),

then hand VIPER the resulting session cookie via `viper.py hack --cookie`.

stdlib only (urllib + http.cookiejar), matching the rest of the harness.
"""

from __future__ import annotations

import http.cookiejar
import re
import urllib.parse
import urllib.request

_TOKEN_RE = re.compile(r"user_token'?\"?\s*value=['\"]([0-9a-f]+)", re.I)


class DvwaSetupError(RuntimeError):
    pass


def _token(html: str) -> str:
    m = _TOKEN_RE.search(html or "")
    if not m:
        raise DvwaSetupError("no user_token in page (DVWA layout changed?)")
    return m.group(1)


def setup_dvwa(base_url: str, *, user: str = "admin", password: str = "password",
               timeout: int = 20) -> str:
    """Run the create-db + login + security=low flow. Returns the Cookie header
    value (e.g. ``PHPSESSID=...; security=low``) for ``viper.py hack --cookie``."""
    base = base_url.rstrip("/")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def get(path: str) -> str:
        req = urllib.request.Request(base + path, headers={"User-Agent": "viper-bench"})
        return opener.open(req, timeout=timeout).read().decode("utf-8", "replace")

    def post(path: str, data: dict) -> str:
        req = urllib.request.Request(
            base + path, data=urllib.parse.urlencode(data).encode(),
            headers={"User-Agent": "viper-bench",
                     "Content-Type": "application/x-www-form-urlencoded"})
        return opener.open(req, timeout=timeout).read().decode("utf-8", "replace")

    try:
        post("/setup.php", {"create_db": "Create / Reset Database",
                            "user_token": _token(get("/setup.php"))})
        post("/login.php", {"username": user, "password": password, "Login": "Login",
                            "user_token": _token(get("/login.php"))})
        post("/security.php", {"security": "low", "seclev_submit": "Submit",
                               "user_token": _token(get("/security.php"))})
    except DvwaSetupError:
        raise
    except Exception as e:  # noqa: BLE001
        raise DvwaSetupError(f"DVWA setup failed: {e}") from e

    cookie = "; ".join(f"{c.name}={c.value}" for c in cj)
    if "PHPSESSID" not in cookie:
        raise DvwaSetupError(f"no session cookie after login (got {cookie!r})")
    if "security=low" not in cookie:
        cookie += "; security=low"  # belt-and-suspenders for the worker requests
    return cookie


# Registry of named auth-setup flows the orchestrator can invoke.
SETUPS = {"dvwa": setup_dvwa}
