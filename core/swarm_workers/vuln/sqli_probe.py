"""SQL injection probe worker (non-destructive).

Sends benign error-mode + boolean-mode payloads to each parameter on
the target URL. NEVER mutates data. Confirms via:
  - SQL error banners in response body
  - Boolean-true vs boolean-false response length divergence

If no parameters are visible, falls back to common parameter names
(id, user, page, q, name).
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import parse_qs, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.sqli_probe")

TECHNIQUE = "sqli_probe"

# High-specificity DB error banners. Each pattern is a phrase/structured token
# that virtually never appears in ordinary English prose or marketing copy.
# Bare keywords like "JDBC" / "psql" / "sqlite_master" were DROPPED — a tutorial
# page about connecting to a database legitimately contains those words, which
# produced false positives (audit: a static Postgres how-to flagged as sqli).
_ERR_BANNERS = re.compile(
    r"(you have an error in your SQL syntax|"
    r"warning:\s*mysql_fetch|"
    r"ORA-\d{5}|"
    r"sqlite3\.OperationalError|"
    r"PG::\w*Error|"
    r"unclosed quotation mark after the character string|"
    r"System\.Data\.SqlClient\.SqlException|"
    r"Microsoft.{0,40}ODBC.{0,40}SQL Server.{0,40}Driver|"
    r"SQLSTATE\[\w|"
    r"incorrect syntax near|"
    r"quoted string not properly terminated|"
    r"psycopg2\.\w*Error|"
    r"com\.mysql\.jdbc\.exceptions|"
    r"valid MySQL result)",
    re.IGNORECASE,
)
_DEFAULT_PARAMS = ["id", "user", "page", "q", "name", "search"]
_ERR_PAYLOAD = "1'"
_BENIGN_PAYLOAD = "1"
_TRUE_PAYLOAD = "1 AND 1=1"
_FALSE_PAYLOAD = "1 AND 1=2"


def _candidate_params(url: str) -> list[str]:
    qs = parse_qs(urlsplit(url).query)
    if qs:
        return list(qs.keys())
    # No params on the URL → defaults PLUS real-world parameter names mined from
    # 7,982 disclosed HackerOne reports (learned prior), deduped.
    params = list(_DEFAULT_PARAMS)
    try:
        from core.payload_library import get_param_hints
        for h in get_param_hints():
            if h not in params:
                params.append(h)
    except Exception:
        pass
    return params


async def _probe_param(url: str, param: str, timeout: float) -> List[dict]:
    findings: list[dict] = []

    # --- Baseline first --------------------------------------------------
    # Request the param with a benign value so we know what the page looks
    # like WITHOUT an injected quote. Any DB-error banner already present in
    # the baseline is part of the page (e.g. a tutorial that talks about SQL
    # errors) and must NOT be attributed to our payload.
    base_url = add_query(url, param, _BENIGN_PAYLOAD)
    base_resp = await fetch("GET", base_url, timeout=timeout)
    base_has_banner = bool(base_resp and _ERR_BANNERS.search(base_resp.body))

    # --- Error-banner path (differential) --------------------------------
    err_url = add_query(url, param, _ERR_PAYLOAD)
    err_resp = await fetch("GET", err_url, timeout=timeout)
    if err_resp and _ERR_BANNERS.search(err_resp.body) and not base_has_banner:
        # The banner appeared ONLY under the quote payload, not the benign
        # baseline → the injected quote broke a real SQL statement. A status
        # change (e.g. 200 -> 500) further corroborates a server-side error.
        status_shift = bool(base_resp) and base_resp.status != err_resp.status
        findings.append({
            "type": "sqli",
            "vuln_type": f"sqli:{param}",
            "title": f"SQL error banner for ?{param}=",
            "severity": "high",
            "url": err_url,
            "parameter": param,
            "payload": _ERR_PAYLOAD,
            "cwe": "CWE-89",
            "confidence": 0.9 if status_shift else 0.85,
            "evidence": (
                "SQL error banner appeared under payload \"1'\" but NOT in the "
                "benign baseline (?{p}=1)"
                + (" and HTTP status changed".format() if status_shift else "")
            ).replace("{p}", param),
        })
        return findings

    # --- Boolean-blind path (jitter-aware differential) ------------------
    # Static pages with per-request variability (rotating CSRF tokens, promo
    # blocks) naturally jitter in body length. Measure that natural jitter by
    # requesting the SAME benign value 2 more times, then only flag when the
    # 1=1 vs 1=2 delta CLEARLY exceeds the observed jitter AND the relationship
    # reproduces on a confirming pair (OR-true vs AND-false).
    t_url = add_query(url, param, _TRUE_PAYLOAD)
    f_url = add_query(url, param, _FALSE_PAYLOAD)
    t_resp = await fetch("GET", t_url, timeout=timeout)
    f_resp = await fetch("GET", f_url, timeout=timeout)
    if not (t_resp and f_resp and t_resp.ok and f_resp.ok
            and t_resp.status == f_resp.status):
        return findings

    diff = abs(len(t_resp.body) - len(f_resp.body))
    rel = diff / max(len(t_resp.body), 1)
    if not (diff > 50 and rel > 0.05):
        return findings

    # Natural jitter: two extra benign samples vs the first baseline.
    jitter = 0
    if base_resp is not None:
        for _ in range(2):
            j_resp = await fetch("GET", base_url, timeout=timeout)
            if j_resp is not None:
                jitter = max(jitter, abs(len(j_resp.body) - len(base_resp.body)))

    # The true/false delta must dwarf the page's own variability. Require a
    # comfortable margin (>= 3x jitter, and at least 50B above jitter) so a
    # rotating-token/promo page does not trip the probe.
    if diff <= max(50, jitter * 3) or diff <= jitter + 50:
        return findings

    # Confirming pair: "1 OR 1=1" (true-like) vs "1 AND 1=2" (false-like)
    # should reproduce a similar length relationship. Generic per-request
    # variance would NOT reproduce the same directional gap.
    c_true_url = add_query(url, param, "1 OR 1=1")
    ct_resp = await fetch("GET", c_true_url, timeout=timeout)
    if ct_resp is None or not ct_resp.ok:
        return findings
    confirm_diff = abs(len(ct_resp.body) - len(f_resp.body))
    if confirm_diff <= max(50, jitter * 3):
        return findings

    findings.append({
        "type": "sqli",
        "vuln_type": f"sqli_blind:{param}",
        "title": f"Boolean-blind SQLi candidate ?{param}=",
        "severity": "medium",
        "url": t_url,
        "parameter": param,
        "payload": _TRUE_PAYLOAD,
        "cwe": "CWE-89",
        "confidence": 0.55,
        "needs_manual_verification": True,
        "evidence": (
            "AND 1=1 -> {t}B, AND 1=2 -> {f}B ({r:.1f}% delta), "
            "page jitter {j}B, confirmed by 1 OR 1=1 -> {c}B"
        ).format(t=len(t_resp.body), f=len(f_resp.body),
                 r=rel * 100, j=jitter, c=len(ct_resp.body)),
    })
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)

    params = _candidate_params(url)[:5]
    findings: list[dict] = []
    for p in params:
        try:
            findings.extend(await _probe_param(url, p, timeout))
        except Exception as e:  # noqa: BLE001
            logger.debug("sqli probe %s?%s failed: %s", url, p, e)
    return findings


register_worker("vuln", TECHNIQUE, run)
