"""SQL injection probe worker (non-destructive).

Sends benign error-mode + boolean-mode payloads to each parameter on
the target URL. NEVER mutates data. Confirms via:
  - SQL error banners in response body
  - Boolean-true vs boolean-false response length divergence

If no parameters are visible, falls back to common parameter names
(id, user, page, q, name).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List
from urllib.parse import parse_qs, urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import add_query, fetch, normalize_target_url
from ._oob import fire_oob

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
# A single quote also routinely trips a WAF block or a non-SQL parser, neither
# of which is a SQL injection. These statuses are the signature of a WAF/edge
# block (or an explicit input filter), NOT a database error: a real SQL error
# surfaces as a reflected 200 or a 500 — essentially never a 403/406/429. When
# the quote response carries one of these statuses we refuse the error-banner
# path (the page may quote SQL-Server prose in its block explanation).
_WAF_BLOCK_STATUSES = frozenset({403, 406, 429})

# Block-page / security-explainer markers. A quote response that contains any of
# these ALONGSIDE a banner phrase is a WAF block page or a help/security page
# that merely TALKS about SQL — not a DB error spilled from a broken query.
_BLOCK_PAGE_MARKERS = re.compile(
    r"(web application firewall|"
    r"request was flagged|"
    r"security policy|"
    r"\bblocked\b|"
    r"\bforbidden\b|"
    r"access denied|"
    r"reference id|"
    r"ray id|"
    r"cf-ray|"
    r"akamai|"
    r"imperva|"
    r"incapsula|"
    r"mod_security|"
    r"\bwaf\b)",
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


async def _bypass_error_payload(url: str, param: str, timeout: float) -> List[dict]:
    """On a WAF block, retry encoding mutations of the quote payload. Emit a
    finding only if a non-blocked variant returns the SQL error banner (and the
    page is not itself a block/security page) — same signal, just past the WAF."""
    from ._bypass import adaptive_fetch

    def build(variant: str) -> str:
        return add_query(url, param, variant)

    res = await adaptive_fetch("GET", build, _ERR_PAYLOAD, timeout=timeout)
    if res.blocked or not res.bypassed or res.response is None:
        return []
    body = res.response.body or ""
    if _ERR_BANNERS.search(body) and not _BLOCK_PAGE_MARKERS.search(body):
        return [{
            "type": "sqli",
            "vuln_type": f"sqli:{param}",
            "title": f"SQL error banner for ?{param}= (WAF-bypassed)",
            "severity": "high",
            "url": build(res.payload),
            "parameter": param,
            "payload": res.payload,
            "cwe": "CWE-89",
            "confidence": 0.85,
            "evidence": (
                f"the raw quote payload was WAF-blocked; a '{res.label}' encoding "
                "bypass reached the app and produced a SQL error banner absent from "
                "the benign baseline"),
        }]
    return []


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
    # If a WAF blocked the raw quote, the app never saw it. Try to slip a mutated
    # quote past the WAF and re-run the SAME differential — still requires the SQL
    # error banner on a non-blocked response (no FP relaxation), just past the WAF.
    err_blocked = bool(err_resp) and (
        err_resp.status in _WAF_BLOCK_STATUSES
        or bool(_BLOCK_PAGE_MARKERS.search(err_resp.body)))
    if err_blocked and not base_has_banner:
        bypassed = await _bypass_error_payload(url, param, timeout)
        if bypassed:
            return bypassed
    if err_resp and _ERR_BANNERS.search(err_resp.body) and not base_has_banner:
        # The banner appeared ONLY under the quote payload, not the benign
        # baseline. Before attributing it to a broken SQL statement, rule out the
        # two realistic look-alikes a lone single quote also triggers:
        #
        #  (1) A WAF / edge block. A 403/406/429 to the quote is the signature of
        #      a block, not a DB error — real SQL errors come back as a reflected
        #      200 or a 500. The block page's explanatory copy often quotes
        #      SQL-Server prose ("incorrect syntax near"), which is what trips the
        #      banner. Refuse these statuses outright.
        #  (2) A block / security-explainer page (any status) whose body carries
        #      WAF markers ("web application firewall", "request was flagged",
        #      "reference id", a Cloudflare/Akamai/Imperva ray-id, etc.) next to
        #      the banner — again the WAF talking about SQL, not the DB erroring.
        #
        # Either way the request never reached app code or a database, so we do
        # NOT emit a finding (the boolean-blind path below still runs and can flag
        # genuine injection without depending on a quote-only error banner).
        if err_resp.status in _WAF_BLOCK_STATUSES:
            return findings
        if _BLOCK_PAGE_MARKERS.search(err_resp.body):
            return findings

        # Banner appeared under the quote, status is consistent with a real DB
        # error (reflected 200 or 5xx), and the page is not a block/security
        # page -> the injected quote broke a real SQL statement. A status change
        # (e.g. 200 -> 500) further corroborates a server-side error.
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
    # Per-param work is independent (own baseline differential; OOB canaries are
    # unique tokens), so params probe concurrently (bounded). Order preserved.
    _sem = asyncio.Semaphore(6)

    async def _one(p: str) -> List[dict]:
        out: list[dict] = []
        async with _sem:
            try:
                out.extend(await _probe_param(url, p, timeout))
            except Exception as e:  # noqa: BLE001
                logger.debug("sqli probe %s?%s failed: %s", url, p, e)
            # Blind/OAST SQLi: fire DNS-exfil canaries (MSSQL xp_dirtree + Oracle
            # UTL_INADDR) at this param (no-op without an OOB server). A DNS/HTTP
            # callback from the database is irrefutable where boolean/timing is not.
            for key in ("sqli_mssql", "sqli_oracle"):
                out.extend(await fire_oob(
                    url, p, vuln_type=f"sqli:blind:{key.split('_')[1]}:{p}",
                    title=f"Blind/OAST SQL injection candidate via ?{p}= "
                          f"({key.split('_')[1]})",
                    cwe="CWE-89", payload_key=key, severity="critical",
                    timeout=timeout))
        return out
    groups = await asyncio.gather(*[_one(p) for p in params])
    return [f for g in groups for f in g]


register_worker("vuln", TECHNIQUE, run)
