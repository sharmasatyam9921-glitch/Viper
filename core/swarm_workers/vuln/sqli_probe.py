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

_ERR_BANNERS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d+|sqlite3\.OperationalError|PG::\w+Error|"
    r"unclosed quotation|System\.Data\.SqlClient|Microsoft.{0,40}ODBC.{0,40}SQL|"
    r"native client|incorrect syntax near|JDBC|sqlite_master|psql)",
    re.IGNORECASE,
)
_DEFAULT_PARAMS = ["id", "user", "page", "q", "name", "search"]
_ERR_PAYLOAD = "1'"
_TRUE_PAYLOAD = "1 AND 1=1"
_FALSE_PAYLOAD = "1 AND 1=2"


def _candidate_params(url: str) -> list[str]:
    qs = parse_qs(urlsplit(url).query)
    if qs:
        return list(qs.keys())
    return list(_DEFAULT_PARAMS)


async def _probe_param(url: str, param: str, timeout: float) -> List[dict]:
    findings: list[dict] = []
    err_url = add_query(url, param, _ERR_PAYLOAD)
    err_resp = await fetch("GET", err_url, timeout=timeout)
    if err_resp and _ERR_BANNERS.search(err_resp.body):
        findings.append({
            "type": "sqli",
            "vuln_type": f"sqli:{param}",
            "title": f"SQL error banner for ?{param}=",
            "severity": "high",
            "url": err_url,
            "parameter": param,
            "payload": _ERR_PAYLOAD,
            "cwe": "CWE-89",
            "confidence": 0.85,
            "evidence": "SQL error banner appeared in response body",
        })
        return findings

    # Boolean blind: same URL, AND 1=1 vs AND 1=2 — length divergence
    t_url = add_query(url, param, _TRUE_PAYLOAD)
    f_url = add_query(url, param, _FALSE_PAYLOAD)
    t_resp = await fetch("GET", t_url, timeout=timeout)
    f_resp = await fetch("GET", f_url, timeout=timeout)
    if t_resp and f_resp and t_resp.ok and f_resp.ok:
        diff = abs(len(t_resp.body) - len(f_resp.body))
        rel = diff / max(len(t_resp.body), 1)
        # Sustained > 5% body delta with same status is a credible
        # boolean-blind indicator
        if diff > 50 and rel > 0.05 and t_resp.status == f_resp.status:
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
                "evidence": (
                    f"AND 1=1 → {len(t_resp.body)}B, "
                    f"AND 1=2 → {len(f_resp.body)}B ({rel*100:.1f}% delta)"
                ),
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
