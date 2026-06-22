"""Turn a gate-confirmed (submittable) finding into a platform-ready bug report.

Only findings the validation gate independently re-confirmed reach here, so the
draft can speak with confidence ("independently reproduced") and carry the exact
steps the gate used. Output is HackerOne-friendly Markdown following the project
reporting rules: precise vuln name, CVSS 3.1 + CWE, summary, business impact,
explicit reproduction (cURL), and actionable remediation.

This produces a DRAFT for human review — VIPER never submits on its own.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

# Per-class metadata: (CWE, CVSS 3.1 base score, CVSS vector, one-line impact,
# remediation). Keyed by the head token of vuln_type (before ':').
_CLASS = {
    "sqli": ("CWE-89", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "Full read/modify access to the backend database — data theft, auth "
             "bypass, and potential remote code execution.",
             "Use parameterized queries / prepared statements; never build SQL by "
             "string concatenation; apply least-privilege DB accounts."),
    "auth_bypass": ("CWE-89", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "Authentication bypass via SQL injection in the login flow.",
                    "Parameterize the login query; add server-side auth checks."),
    "rce": ("CWE-78", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Arbitrary OS command execution on the server.",
            "Never pass user input to a shell; use exec APIs with argument arrays; "
            "strict allow-list validation."),
    "ssti": ("CWE-1336", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
             "Server-side template injection leading to data disclosure and often "
             "remote code execution.",
             "Do not render user input as a template; use a logic-less/sandboxed "
             "engine and context-encode output."),
    "lfi": ("CWE-22", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "Reading arbitrary files on the server (config, secrets, source).",
            "Resolve and canonicalize paths against an allow-list; reject '../'; "
            "never use user input as a filesystem path."),
    "xss": ("CWE-79", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "Execution of attacker-controlled script in a victim's browser — "
            "session theft, account takeover, UI redress.",
            "Context-aware output encoding; a strict Content-Security-Policy; "
            "framework auto-escaping."),
    "idor": ("CWE-639", 6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             "One user can read another user's private objects (broken object-level "
             "authorization).",
             "Enforce per-object ownership checks on every request server-side; "
             "never trust a client-supplied object id."),
    "bola": ("CWE-639", 8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
             "Cross-user object access confirmed with two accounts (BOLA / OWASP "
             "API #1).",
             "Enforce object-level authorization on every endpoint; bind objects "
             "to the authenticated principal."),
    "cors": ("CWE-942", 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "A misconfigured CORS policy lets an attacker origin read authenticated "
             "responses.",
             "Reflect only an explicit allow-list of origins; never combine a "
             "wildcard/reflected origin with Access-Control-Allow-Credentials."),
    "open_redirect": ("CWE-601", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                      "An open redirect enables convincing phishing and OAuth token "
                      "theft.",
                      "Redirect only to a server-side allow-list of paths/hosts; "
                      "reject absolute external URLs."),
    "secret": ("CWE-798", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
               "A live credential is exposed in a public response.",
               "Revoke and rotate the credential immediately; move secrets to a "
               "vault / server-side config; scan builds for secrets."),
    "access_control": ("CWE-862", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                       "A protected endpoint returns sensitive data to an "
                       "unauthenticated request.",
                       "Require and enforce authorization on every sensitive "
                       "endpoint server-side; deny by default."),
    "env_exposed": ("CWE-200", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "An environment/config file with secrets is publicly served.",
                    "Block access to dotfiles/config; rotate any exposed secrets."),
    "information_disclosure": ("CWE-538", 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                               "Sensitive files/listing exposed to anonymous users.",
                               "Disable directory listing; restrict access to "
                               "sensitive paths."),
    "git_exposed": ("CWE-538", 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "An exposed .git directory leaks source code and history.",
                    "Block access to .git; deploy build artifacts only."),
    "web_cache_deception": ("CWE-525", 7.5, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                            "A cache stores authenticated pages under static-looking "
                            "URLs; an unauthenticated attacker retrieves another "
                            "user's private data from the cache.",
                            "Cache by content type from origin headers, not URL "
                            "suffix; set Cache-Control: no-store on authenticated "
                            "responses; normalize/validate paths at the edge."),
    "subdomain_takeover": ("CWE-350", 8.1, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                           "A dangling DNS record points at a de-provisioned "
                           "third-party resource; an attacker can register it and "
                           "serve arbitrary content on this subdomain — phishing, "
                           "cookie theft, and CSP/SSO trust abuse.",
                           "Remove the dangling DNS record, or re-claim the backing "
                           "resource; audit CNAMEs to retired services on a schedule."),
    "host_header": ("CWE-644", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "The app builds absolute URLs (redirects, password-reset links, "
                    "cached references) from an attacker-controlled host header — "
                    "enabling web cache poisoning, open redirect, password-reset "
                    "poisoning, and host-based SSRF.",
                    "Use a server-configured canonical host; never derive absolute "
                    "URLs from the incoming Host/X-Forwarded-Host; allow-list trusted "
                    "hosts at the edge."),
    "bfla": ("CWE-863", 8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
             "A low-privilege user can invoke a privileged/administrative function "
             "(broken function-level authorization, OWASP API #5).",
             "Enforce role/permission checks server-side on every privileged "
             "endpoint; deny by default; never rely on UI-hidden routes."),
    "chain": ("CWE-Other", 9.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
              "Multiple findings compose into a higher-severity attack chain.",
              "Remediate each contributing finding; the chain is broken if any "
              "link is fixed, but all should be addressed."),
}
_DEFAULT = ("CWE-Other", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "Security weakness confirmed on the target.",
            "Review and remediate per the finding details.")

_SEV_FROM_CVSS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low")]

# Normalize a worker vuln_type head to a _CLASS key.
_HEAD_ALIAS = {
    "xss_text": "xss", "xss_tag": "xss", "dom_xss": "xss", "reflected_xss": "xss",
    "sqli_blind": "sqli", "login_sqli": "sqli",
    "ssti_error": "ssti", "cmdi": "rce", "command_injection": "rce",
    "cors_wildcard": "cors", "cors_origin_reflect": "cors", "cors_null_origin": "cors",
    "actuator_env": "env_exposed", "js_secret": "secret", "github_secret": "secret",
}


def _norm_head(vuln_type: str) -> str:
    vt = (vuln_type or "").lower()
    if vt.startswith("chain:"):
        return "chain"
    if ":bola:" in vt:
        return "bola"
    if ":bfla:" in vt:
        return "bfla"
    head = vt.split(":")[0]
    return _HEAD_ALIAS.get(head, head)


def _meta(vuln_type: str):
    return _CLASS.get(_norm_head(vuln_type), _DEFAULT)


def _cvss_severity(score: float) -> str:
    for lo, label in _SEV_FROM_CVSS:
        if score >= lo:
            return label
    return "Info"


def _title(finding: dict, vuln_type: str) -> str:
    nice = {
        "sqli": "SQL Injection", "auth_bypass": "Authentication Bypass (SQLi)",
        "rce": "OS Command Injection", "ssti": "Server-Side Template Injection",
        "lfi": "Local File Inclusion / Path Traversal", "xss": "Reflected XSS",
        "idor": "Insecure Direct Object Reference (IDOR)",
        "bola": "Broken Object Level Authorization (BOLA)",
        "cors": "CORS Misconfiguration", "open_redirect": "Open Redirect",
        "secret": "Exposed Credential", "access_control": "Broken Access Control",
        "env_exposed": "Exposed Environment File",
        "information_disclosure": "Sensitive Information Disclosure",
        "git_exposed": "Exposed .git Directory",
        "bfla": "Broken Function-Level Authorization (BFLA)",
        "host_header": "Host Header Injection",
        "subdomain_takeover": "Subdomain Takeover",
        "web_cache_deception": "Web Cache Deception",
        "chain": "Attack Chain",
    }
    head = _norm_head(vuln_type)
    if head == "chain":
        return finding.get("title") or "Attack Chain"
    name = nice.get(head, (vuln_type or "Security Finding").replace("_", " ").title())
    param = finding.get("parameter")
    where = f" in parameter '{param}'" if param else ""
    host = urlsplit(finding.get("url") or "").netloc
    return f"{name}{where}" + (f" on {host}" if host else "")


def _curl(finding: dict) -> str:
    url = finding.get("url") or ""
    if not url:
        return "(no request captured)"
    return f"curl -i '{url}'"


def _repro(finding: dict, vuln_type: str) -> str:
    head = _norm_head(vuln_type)
    url = finding.get("url") or ""
    param = finding.get("parameter") or "<param>"
    base = url.split("?")[0]
    if head in ("sqli", "auth_bypass"):
        return (f"1. Send a single-quote breaker:\n   `curl -i \"{base}?{param}=1'\"`\n"
                f"2. Observe a database error in the response.\n"
                f"3. Send a benign value `{param}=1` — no error — confirming the "
                f"error is caused by the injected quote.")
    if head == "rce":
        return (f"1. Inject a time delay:\n   `curl -i \"{base}?{param}=x;sleep%207\"`\n"
                f"2. The response is delayed ~7s vs a control, and the delay scales "
                f"with the sleep value (paired-control time test).")
    if head == "ssti":
        return (f"1. Inject an arithmetic expression:\n   `curl -i \"{base}?{param}=${{7*7}}\"`\n"
                f"2. The response contains `49` at the reflection site (the expression "
                f"was evaluated, not echoed); fresh operands track (8*8->64, 11*11->121).")
    if head == "lfi":
        return (f"1. Request a traversal payload:\n   `curl -i \"{url}\"`\n"
                f"2. The response returns `/etc/passwd` contents (root:x:0:0:...), "
                f"absent for a benign value of `{param}`.")
    if head == "xss":
        return (f"1. Inject a script payload into `{param}`:\n"
                f"   `curl -i \"{base}?{param}=<svg/onload=alert(1)>\"`\n"
                f"2. The payload is reflected UNENCODED in an HTML response context "
                f"(live markup), so it executes in the browser.")
    if head in ("idor", "bola"):
        return (f"1. As **user A**, request the object:\n   `curl -i -H 'Cookie: <A session>' '{url}'`\n"
                f"2. As **user B** (a different account), request the SAME object:\n"
                f"   `curl -i -H 'Cookie: <B session>' '{url}'`\n"
                f"3. User B receives user A's private data — cross-user object access. "
                f"An unauthenticated request is denied, confirming the data is private.")
    if head == "cors":
        return (f"1. Send a cross-origin request with an attacker Origin:\n"
                f"   `curl -i -H 'Origin: https://attacker.example' '{url}'`\n"
                f"2. The response reflects the attacker origin in "
                f"`Access-Control-Allow-Origin`, allowing it to read the response.")
    if head == "open_redirect":
        return (f"1. Request the redirect with an external target:\n   `curl -i '{url}'`\n"
                f"2. The `Location` header points to the attacker-controlled host.")
    # exposure classes
    return f"1. Request the resource:\n   `{_curl(finding)}`\n2. The sensitive content is returned to an anonymous request."


def build_submission(finding: dict, target: Optional[str] = None) -> str:
    """Render a HackerOne-ready Markdown draft for one (submittable) finding."""
    vt = finding.get("vuln_type") or finding.get("type") or "finding"
    cwe, cvss, vector, impact, remediation = _meta(vt)
    # A chain carries its OWN per-recipe CWE/severity/narrative — prefer them.
    if _norm_head(vt) == "chain":
        cwe = finding.get("cwe") or cwe
        impact = finding.get("evidence") or impact
        cvss = {"critical": 9.3, "high": 8.1, "medium": 5.5, "low": 3.5}.get(
            str(finding.get("severity") or "").lower(), cvss)
    sev = _cvss_severity(cvss)
    title = _title(finding, vt)
    url = finding.get("url") or target or ""
    evidence = finding.get("evidence") or finding.get("validation_reason") or ""
    gate = finding.get("validation_reason") or ""
    gconf = finding.get("validation_confidence")
    gline = ""
    if gate:
        pct = f" ({gconf:.0%} confidence)" if isinstance(gconf, (int, float)) else ""
        gline = f"\n**Independently re-confirmed by VIPER's validation gate{pct}:** {gate}\n"

    return f"""# {title}

| | |
| --- | --- |
| **Severity** | {sev} (CVSS 3.1 {cvss}) |
| **CVSS Vector** | `CVSS:3.1/{vector}` |
| **Weakness** | {cwe} |
| **Asset** | `{url}` |

## Summary
{impact}
{gline}
## Steps to Reproduce
{_repro(finding, vt)}

## Evidence
```
{str(evidence)[:600]}
```

## Impact
{impact}

## Remediation
{remediation}

---
*Reported by VIPER (automated, authorized testing). This finding was independently
re-confirmed by an out-of-band validation pass before drafting; please verify in
your environment prior to triage.*
"""


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "finding").lower()).strip("-")[:50] or "finding"


def write_drafts(findings: List[dict], out_dir, target: Optional[str] = None,
                 only_submittable: bool = True) -> List[Path]:
    """Write one Markdown draft per (submittable) finding + a prioritized INDEX.md.

    Returns the per-finding draft paths (the index is written but not included).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    index_rows: List[tuple] = []
    for i, f in enumerate(findings, 1):
        if only_submittable and not f.get("submittable"):
            continue
        vt = f.get("vuln_type") or f.get("type") or "finding"
        name = f"{i:02d}-{_slug(vt)}.md"
        path = out / name
        path.write_text(build_submission(f, target), encoding="utf-8")
        written.append(path)
        index_rows.append((f, name))
    if written:
        _write_index(out, index_rows, target)
    return written


def _write_index(out: Path, rows: List[tuple], target: Optional[str]) -> None:
    """A one-page, priority-sorted triage index of the drafted findings."""
    try:
        from core.prioritization import priority_label, priority_score
        rows = sorted(rows, key=lambda r: priority_score(r[0]), reverse=True)
    except Exception:
        def priority_label(_s):
            return "-"

        def priority_score(_f):
            return 0
    lines = [f"# Submission index — {target or 'target'}",
             f"\n{len(rows)} submittable finding(s), highest priority first.\n",
             "| Priority | Severity | Type | Confidence | Draft |",
             "| --- | --- | --- | --- | --- |"]
    for f, name in rows:
        sev = str(f.get("severity") or "info").title()
        vt = f.get("vuln_type") or f.get("type") or "finding"
        conf = f.get("validation_confidence")
        cs = f"{conf:.0%}" if isinstance(conf, (int, float)) else "n/a"
        pscore = priority_score(f)
        lines.append(f"| {priority_label(pscore)} ({pscore}) | {sev} | `{vt}` | "
                     f"{cs} | [{name}]({name}) |")
    lines.append("\n*Each draft was independently re-confirmed by VIPER's validation "
                 "gate. Review before submitting; VIPER never submits on its own.*")
    (out / "INDEX.md").write_text("\n".join(lines), encoding="utf-8")
