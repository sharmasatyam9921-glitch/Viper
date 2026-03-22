"""
VIPER 4.0 - Secret Detection Engine
=====================================
Regex + Shannon entropy based secret detection for source code,
JavaScript files, HTTP responses, and GitHub repositories.

Secret detection inspired by open-source pentesting frameworks.
No external dependencies. Stdlib only.
"""

import re
import math
import json
import os
from typing import Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# =============================================================================
# SECRET PATTERNS - 50+ regex patterns for common secrets
# =============================================================================

SECRET_PATTERNS: Dict[str, str] = {
    # AWS
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "aws_mws_key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # Azure
    "azure_storage_key": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "azure_connection_string": r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}",
    "azure_sas_token": r"(?i)[?&]sig=[A-Za-z0-9%]{40,}",

    # Google Cloud
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "gcp_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "gcp_service_account": r"\"type\":\s*\"service_account\"",
    "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
    "firebase_api_key": r"(?i)firebase.*['\"][A-Za-z0-9_]{30,}['\"]",

    # GitHub
    "github_token_classic": r"ghp_[0-9a-zA-Z]{36}",
    "github_token_finegrained": r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
    "github_oauth": r"gho_[0-9a-zA-Z]{36}",
    "github_app_token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    "github_refresh_token": r"ghr_[0-9a-zA-Z]{36}",

    # GitLab
    "gitlab_token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "gitlab_runner_token": r"GR1348941[0-9a-zA-Z\-_]{20}",

    # Slack
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",

    # Stripe
    "stripe_live_key": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_test_key": r"sk_test_[0-9a-zA-Z]{24,}",
    "stripe_restricted_key": r"rk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_(live|test)_[0-9a-zA-Z]{24,}",

    # Payment
    "square_access_token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "square_oauth_secret": r"sq0csp-[0-9A-Za-z\-_]{43}",

    # Social/API
    "twitter_bearer": r"AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+",
    "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",

    # Messaging
    "twilio_api_key": r"SK[0-9a-fA-F]{32}",
    "twilio_account_sid": r"AC[a-zA-Z0-9]{32}",
    "sendgrid_api_key": r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "mailchimp_api_key": r"[0-9a-f]{32}-us[0-9]{1,2}",

    # Databases
    "mongodb_uri": r"mongodb(?:\+srv)?://[^\s'\"]+",
    "postgres_uri": r"postgres(?:ql)?://[^\s'\"]+",
    "mysql_uri": r"mysql://[^\s'\"]+",
    "redis_url": r"redis://[^\s'\"]+",

    # CI/CD & DevOps
    "heroku_api_key": r"(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "npm_token": r"(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}",
    "pypi_token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
    "docker_hub_token": r"dckr_pat_[A-Za-z0-9_-]{27}",

    # Cryptographic Keys
    "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
    "dsa_private_key": r"-----BEGIN DSA PRIVATE KEY-----",
    "ec_private_key": r"-----BEGIN EC PRIVATE KEY-----",
    "openssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "pgp_private_key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "generic_private_key": r"-----BEGIN PRIVATE KEY-----",

    # JWT & Auth
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "basic_auth_header": r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+",
    "bearer_token": r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",

    # Generic
    "generic_api_key": r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "generic_secret": r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
    "generic_token": r"(?i)(access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "hardcoded_password": r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",

    # Cloud & Infra
    "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
    "digitalocean_oauth": r"doo_v1_[a-f0-9]{64}",
    "shopify_token": r"shpat_[a-fA-F0-9]{32}",
    "shopify_shared_secret": r"shpss_[a-fA-F0-9]{32}",

    # Misc
    "telegram_bot_token": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "discord_bot_token": r"[MN][A-Za-z\d]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
    "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "private_ip": r"(?:^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9]|$)",
}

# Severity classification
SEVERITY_MAP = {
    "aws_access_key": "critical", "aws_secret_key": "critical", "aws_mws_key": "critical",
    "azure_storage_key": "critical", "azure_connection_string": "high",
    "google_api_key": "high", "gcp_service_account": "critical",
    "github_token_classic": "critical", "github_token_finegrained": "critical",
    "gitlab_token": "critical",
    "slack_token": "high", "slack_webhook": "medium",
    "stripe_live_key": "critical", "stripe_test_key": "low",
    "stripe_restricted_key": "high", "stripe_publishable": "info",
    "rsa_private_key": "critical", "openssh_private_key": "critical",
    "generic_private_key": "critical", "pgp_private_key": "critical",
    "ec_private_key": "critical", "dsa_private_key": "critical",
    "jwt_token": "medium", "bearer_token": "medium",
    "mongodb_uri": "high", "postgres_uri": "high", "mysql_uri": "high",
    "redis_url": "high",
    "telegram_bot_token": "high", "discord_bot_token": "high",
    "generic_api_key": "medium", "generic_secret": "medium",
    "generic_token": "medium", "hardcoded_password": "high",
    "private_ip": "info",
}

# Sensitive filenames
SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.backup", ".env.old", "credentials", "credentials.json",
    "id_rsa", "id_rsa.pub", "id_dsa", "id_ecdsa", "id_ed25519",
    ".pem", ".key", ".p12", ".pfx",
    "config.json", "config.yaml", "config.yml", "secrets.json", "secrets.yaml",
    "settings.json", ".htpasswd", ".netrc", ".npmrc", ".pypirc", ".dockercfg",
    "wp-config.php", "database.yml",
    "terraform.tfvars", "terraform.tfstate",
    ".bash_history", ".zsh_history", ".mysql_history",
    "backup.sql", "dump.sql", "database.sql",
    ".aws/credentials", "service-account.json", "kubeconfig",
}

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css", ".map", ".lock",
}

# Compile patterns once
_COMPILED_PATTERNS: Dict[str, re.Pattern] = {}
for _name, _pattern in SECRET_PATTERNS.items():
    try:
        _COMPILED_PATTERNS[_name] = re.compile(_pattern)
    except re.error:
        pass


# =============================================================================
# Entropy Detection
# =============================================================================

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / len(data)
        entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(content: str, threshold: float = 4.5) -> List[dict]:
    """
    Find high-entropy strings that might be secrets.

    Returns list of {type, match, entropy, length}.
    """
    findings = []
    patterns = [
        r'["\']([A-Za-z0-9+/=_-]{20,})["\']',
        r'=\s*([A-Za-z0-9+/=_-]{20,})',
    ]

    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            candidate = match.group(1)
            if candidate in seen:
                continue
            seen.add(candidate)

            ent = shannon_entropy(candidate)
            if ent >= threshold and len(candidate) >= 20:
                # Skip all-lowercase words (likely not secrets)
                if re.match(r'^[a-z]+$', candidate, re.IGNORECASE):
                    continue
                findings.append({
                    "type": "high_entropy_string",
                    "match": candidate[:80] + "..." if len(candidate) > 80 else candidate,
                    "entropy": round(ent, 2),
                    "length": len(candidate),
                    "severity": "medium",
                })

    return findings


# =============================================================================
# Scanning Functions
# =============================================================================

def scan_text(text: str, source_url: str = "") -> List[dict]:
    """
    Scan text for secrets using regex patterns.

    Returns list of findings:
    [{"type", "match", "severity", "source_url", "entropy"}, ...]
    """
    findings = []
    if not text:
        return findings

    for name, regex in _COMPILED_PATTERNS.items():
        for match in regex.finditer(text):
            matched = match.group(0)
            # Truncate long matches
            display = matched[:100] + "..." if len(matched) > 100 else matched
            severity = SEVERITY_MAP.get(name, "medium")
            findings.append({
                "type": name,
                "match": display,
                "severity": severity,
                "source_url": source_url,
                "entropy": round(shannon_entropy(matched), 2),
                "line": text[:match.start()].count("\n") + 1,
            })

    # Also check high-entropy strings
    entropy_findings = find_high_entropy_strings(text)
    for f in entropy_findings:
        f["source_url"] = source_url
        findings.append(f)

    return findings


def scan_js_file(url: str, content: str) -> List[dict]:
    """
    Scan JavaScript file content for exposed secrets.

    Specifically tuned for JS patterns: variable assignments, config objects,
    template literals, etc.
    """
    findings = scan_text(content, source_url=url)

    # Additional JS-specific patterns
    js_patterns = {
        "js_api_endpoint": r'(?:api_?url|endpoint|base_?url)\s*[:=]\s*["\']https?://[^"\']+["\']',
        "js_graphql_endpoint": r'["\']https?://[^"\']*graphql[^"\']*["\']',
        "js_internal_url": r'["\']https?://(?:internal|staging|dev|admin|api)\.[^"\']+["\']',
        "js_debug_flag": r'(?:debug|verbose|dev_?mode)\s*[:=]\s*true',
    }

    for name, pattern in js_patterns.items():
        try:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "type": name,
                    "match": match.group(0)[:100],
                    "severity": "low" if "debug" in name else "info",
                    "source_url": url,
                    "entropy": 0.0,
                    "line": content[:match.start()].count("\n") + 1,
                })
        except re.error:
            continue

    return findings


def scan_github_repo(owner: str, repo: str, token: str = None,
                     max_files: int = 200) -> List[dict]:
    """
    Scan a GitHub repository for secrets via the GitHub API.

    Uses the GitHub REST API (tree endpoint) to enumerate files,
    then fetches and scans text files.

    Args:
        owner: Repository owner
        repo: Repository name
        token: GitHub personal access token (optional, increases rate limit)
        max_files: Maximum number of files to scan

    Returns:
        List of secret findings.
    """
    findings = []
    base_url = f"https://api.github.com/repos/{owner}/{repo}"

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # Get repository tree (recursive)
    try:
        req = Request(f"{base_url}/git/trees/HEAD?recursive=1", headers=headers)
        with urlopen(req, timeout=30) as resp:
            tree_data = json.loads(resp.read().decode())
    except (URLError, HTTPError) as e:
        return [{"type": "error", "match": f"Failed to fetch repo tree: {e}",
                 "severity": "info", "source_url": base_url}]

    tree = tree_data.get("tree", [])
    scanned = 0

    for item in tree:
        if scanned >= max_files:
            break
        if item.get("type") != "blob":
            continue

        path = item.get("path", "")
        filename = os.path.basename(path)

        # Check for sensitive filenames
        if filename in SENSITIVE_FILENAMES or path in SENSITIVE_FILENAMES:
            findings.append({
                "type": "sensitive_filename",
                "match": path,
                "severity": "high",
                "source_url": f"https://github.com/{owner}/{repo}/blob/HEAD/{path}",
                "entropy": 0.0,
            })

        # Skip binary extensions
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            continue

        # Only scan small text files (< 500KB)
        size = item.get("size", 0)
        if size > 500_000 or size == 0:
            continue

        # Fetch file content
        try:
            blob_url = item.get("url", "")
            if not blob_url:
                continue
            req = Request(blob_url, headers=headers)
            with urlopen(req, timeout=15) as resp:
                blob_data = json.loads(resp.read().decode())

            content = blob_data.get("content", "")
            encoding = blob_data.get("encoding", "")

            if encoding == "base64":
                import base64
                try:
                    content = base64.b64decode(content).decode("utf-8", errors="replace")
                except Exception:
                    continue
            elif encoding != "utf-8":
                continue

            file_url = f"https://github.com/{owner}/{repo}/blob/HEAD/{path}"
            file_findings = scan_text(content, source_url=file_url)
            findings.extend(file_findings)
            scanned += 1

        except (URLError, HTTPError):
            continue
        except Exception:
            continue

    return findings


# =============================================================================
# SecretScanner Class (stateful accumulator)
# =============================================================================

class SecretScanner:
    """Stateful secret scanner that accumulates findings across multiple scans."""

    def __init__(self):
        self.findings: List[dict] = []
        self.sources_scanned: List[str] = []
        self._seen_hashes: set = set()

    def scan(self, text: str, source: str = "") -> List[dict]:
        """Scan text and accumulate findings. Returns new findings from this scan."""
        new_findings = scan_text(text, source_url=source)

        # Deduplicate
        unique = []
        for f in new_findings:
            key = f"{f['type']}:{f['match']}"
            if key not in self._seen_hashes:
                self._seen_hashes.add(key)
                unique.append(f)

        self.findings.extend(unique)
        if source:
            self.sources_scanned.append(source)
        return unique

    def scan_js(self, url: str, content: str) -> List[dict]:
        """Scan JavaScript file and accumulate findings."""
        new_findings = scan_js_file(url, content)

        unique = []
        for f in new_findings:
            key = f"{f['type']}:{f['match']}"
            if key not in self._seen_hashes:
                self._seen_hashes.add(key)
                unique.append(f)

        self.findings.extend(unique)
        self.sources_scanned.append(url)
        return unique

    def get_findings(self) -> List[dict]:
        """Get all accumulated findings."""
        return self.findings

    def get_findings_by_severity(self) -> Dict[str, List[dict]]:
        """Get findings grouped by severity."""
        grouped: Dict[str, List[dict]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in self.findings:
            sev = f.get("severity", "medium")
            grouped.setdefault(sev, []).append(f)
        return grouped

    def get_summary(self) -> dict:
        """Get scan summary statistics."""
        by_sev = self.get_findings_by_severity()
        by_type: Dict[str, int] = {}
        for f in self.findings:
            t = f.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        return {
            "total_findings": len(self.findings),
            "sources_scanned": len(self.sources_scanned),
            "by_severity": {k: len(v) for k, v in by_sev.items()},
            "by_type": by_type,
            "critical_count": len(by_sev.get("critical", [])),
            "high_count": len(by_sev.get("high", [])),
        }

    def to_json(self) -> str:
        """Export findings as JSON string."""
        return json.dumps({
            "summary": self.get_summary(),
            "findings": self.findings,
        }, indent=2)

    def clear(self):
        """Reset scanner state."""
        self.findings.clear()
        self.sources_scanned.clear()
        self._seen_hashes.clear()


if __name__ == "__main__":
    # Quick test
    scanner = SecretScanner()

    test_text = """
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    GITHUB_TOKEN = "ghp_ABCDEFghijklmnop1234567890qrstuv"
    DATABASE_URL = "postgres://user:pass@host:5432/db"
    api_key = "sk_test_EXAMPLE_NOT_REAL_KEY_1234"
    password = "SuperSecretP@ss123"
    """

    results = scanner.scan(test_text, source="test_input")
    summary = scanner.get_summary()

    print(f"[*] Secret Scanner Test")
    print(f"    Total findings: {summary['total_findings']}")
    print(f"    Critical: {summary['critical_count']}")
    print(f"    High: {summary['high_count']}")
    print(f"\n[*] Findings:")
    for f in results:
        print(f"    [{f['severity'].upper()}] {f['type']}: {f['match'][:60]}")
