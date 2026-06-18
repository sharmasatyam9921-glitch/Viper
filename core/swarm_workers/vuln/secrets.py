"""HTTP-response secret scanner.

Fetches the target's HTML, JS bundles linked from it, and a few common
exposure paths (`/.env`, `/.git/HEAD`, `/.aws/credentials`,
`/server-status`, `/actuator/env`, `/swagger.json`). Greps for known
credential / API-key shapes (AKIA…, GitHub PATs, Slack hooks, etc.)
using a small built-in pattern set.

Distinct from `recon/github_secrets.py` (org-wide GitHub) — this hits
the LIVE target host.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import fetch, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.secrets")

TECHNIQUE = "secrets"

# Pattern set: (name, regex, severity)
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws_session_token", re.compile(r"\bASIA[0-9A-Z]{16}\b"), "high"),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), "critical"),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"), "critical"),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"), "critical"),
    ("slack_bot_token", re.compile(r"\bxoxb-[A-Za-z0-9-]{10,}\b"), "high"),
    ("slack_user_token", re.compile(r"\bxoxp-[A-Za-z0-9-]{10,}\b"), "high"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "medium"),
    ("discord_webhook", re.compile(r"https://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+"), "medium"),
    ("stripe_live", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "critical"),
    ("stripe_test", re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"), "low"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), "critical"),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,}\b"), "low"),
    ("password_assignment", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"\'`]([A-Za-z0-9!@#$%^&*]{8,})[\"\'`]"), "medium"),
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"\'`]?([A-Za-z0-9/+]{40})[\"\'`]?"), "critical"),
]


_EXPOSURE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config",
    "/.aws/credentials", "/.aws/config",
    "/server-status", "/server-info",
    "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/composer.json", "/package.json",
    "/wp-config.php.bak", "/config.php.bak", "/.htaccess.bak",
    # Exposed-file / directory-listing surfaces (anonymous read).
    "/ftp", "/ftp/acquisitions.md", "/encryptionkeys",
]


# A response is HTML when the server says so OR the body opens with an HTML
# preamble. A real .env / .git / .aws / actuator dump is NEVER served as HTML,
# so an HTML body on an exposure path is a catch-all SPA index, not a leak.
_HTML_OPENERS = ("<!doctype html", "<html")


def _looks_like_html(resp) -> bool:
    ctype = (resp.headers.get("content-type", "") if resp.headers else "").lower()
    if "text/html" in ctype:
        return True
    head = resp.body.lstrip()[:14].lower()
    return head.startswith(_HTML_OPENERS)


# A dotenv file has at least one UPPERCASE KEY=value line (env-var convention),
# unlike an HTML page whose only `=` come from attribute syntax (lang="en").
_DOTENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]*=\S")


def _scan_body(body: str, url: str, *, is_html: bool = False) -> List[dict]:
    findings: list[dict] = []
    for name, pat, sev in _SECRET_PATTERNS:
        # The password_assignment regex matches any `password="<8 chars>"`,
        # which fires constantly on benign HTML (form markup, JS state, demo
        # placeholders). Suppress it on HTML bodies — real credential leaks in
        # HTML come from the high-confidence, shape-specific patterns above.
        if is_html and name == "password_assignment":
            continue
        for m in pat.finditer(body[:512 * 1024]):  # cap body scan
            secret = m.group(0)
            findings.append({
                "type": "secret_leak",
                "vuln_type": f"secret:{name}",
                "title": f"Leaked secret: {name}",
                "severity": sev,
                "url": url,
                "cwe": "CWE-540",
                "confidence": 0.9,
                "evidence": (
                    # Truncate visibly — never leak the full secret in audit
                    f"{name} found ({secret[:6]}…{secret[-4:]}, {len(secret)} chars)"
                ),
            })
            break  # one finding per pattern per URL
    return findings


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    timeout = min(agent.timeout_s, 8.0)
    findings: list[dict] = []

    # 1. Main page
    resp = await fetch("GET", url, timeout=timeout)
    if resp:
        findings.extend(_scan_body(resp.body, url, is_html=_looks_like_html(resp)))

    # 2. Common exposure paths — in parallel. These are ROOT-relative: the
    # worker may be dispatched against a discovered endpoint asset (e.g.
    # /styles.css), but /.env, /.git, /ftp etc. live at the site origin, not
    # under the asset's path. Derive the origin so we test scheme://host/<path>.
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else url.rstrip("/")

    async def _check(path: str) -> List[dict]:
        full = origin + path
        r = await fetch("GET", full, timeout=timeout, follow_redirects=False)
        if not r or not r.ok or not r.body:
            return []
        # A catch-all SPA / CDN re-serves its index.html (HTTP 200, text/html)
        # for EVERY unmatched route, including /.env, /.git, /.aws, /actuator.
        # That HTML is not an exposed secret file — none of these are ever
        # served as HTML — so suppress the exposure signals (and the noisy
        # HTML-only secret regexes) when the body looks like an HTML page.
        is_html = _looks_like_html(r)
        out: list[dict] = _scan_body(r.body, full, is_html=is_html)
        # Even without secret hits, exposing /.env is itself a finding — but
        # only when the body is an actual dotenv file: not HTML, with at least
        # one UPPERCASE KEY=value line (a bare `=` is satisfied by any HTML
        # attribute, the root of the catch-all-SPA false positive).
        if path == "/.env" and not is_html and _DOTENV_LINE.search(r.body):
            out.append({
                "type": "env_exposed",
                "vuln_type": f"env_exposed:{path}",
                "title": f"{path} publicly accessible",
                "severity": "high",
                "url": full,
                "cwe": "CWE-200",
                "confidence": 0.95,
                "evidence": f".env-style file served at {path}",
            })
        if path == "/.git/HEAD" and r.body.startswith("ref: refs/heads/"):
            out.append({
                "type": "git_exposed",
                "vuln_type": "git_exposed",
                "title": "Git repository exposed (.git/HEAD)",
                "severity": "high",
                "url": full,
                "cwe": "CWE-538",
                "confidence": 0.98,
                "evidence": ".git/HEAD returns a valid ref string — full repo likely recoverable",
            })
        if path == "/actuator/env" and ("propertySources" in r.body or "configurationProperties" in r.body):
            out.append({
                "type": "actuator_exposed",
                "vuln_type": "actuator_env",
                "title": "Spring Boot actuator/env exposed",
                "severity": "high",
                "url": full,
                "cwe": "CWE-200",
                "confidence": 0.9,
                "evidence": "/actuator/env returns property sources",
            })
        # Anonymous directory listing — a 200 HTML index linking downloadable
        # files (Juice-Shop-class /ftp, /encryptionkeys). vuln_type carries the
        # canonical "information_disclosure" label so triage/scoring classify it.
        if path in ("/ftp", "/encryptionkeys"):
            body_l = r.body.lower()
            listing = "<a href=" in body_l and any(
                ext in body_l for ext in (".md", ".pdf", ".bak", ".key", ".pub", ".json")
            )
            if r.status == 200 and listing:
                out.append({
                    "type": "directory_listing",
                    "vuln_type": f"information_disclosure:listing:{path}",
                    "title": f"Anonymous directory listing at {path}",
                    "severity": "high",
                    "url": full,
                    "cwe": "CWE-548",
                    "confidence": 0.9,
                    "evidence": (
                        f"{path} returns a 200 HTML index linking downloadable "
                        "files without authentication"
                    ),
                })
        if path == "/ftp/acquisitions.md" and r.status == 200 and "acquisition" in r.body.lower():
            out.append({
                "type": "sensitive_file_exposed",
                "vuln_type": "information_disclosure:confidential_doc",
                "title": "Confidential document served anonymously",
                "severity": "high",
                "url": full,
                "cwe": "CWE-200",
                "confidence": 0.9,
                "evidence": (
                    "/ftp/acquisitions.md returns a 200 body describing "
                    "confidential acquisitions without authentication"
                ),
            })
        return out

    results = await asyncio.gather(
        *(_check(p) for p in _EXPOSURE_PATHS), return_exceptions=True,
    )
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    return findings


register_worker("vuln", TECHNIQUE, run)
