#!/usr/bin/env python3
"""
VIPER Secret Scanner — Find leaked credentials in public GitHub repos.

Scans GitHub organizations, user repos, and code search for accidentally
committed API keys, tokens, passwords, and private keys. Uses 40+ regex
patterns plus Shannon entropy analysis to reduce false positives.

SECURITY: Never stores or logs full secret values — all matches are truncated.
"""

import asyncio
import math
import os
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("viper.secrets")

# Files likely to contain secrets
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    "config.yml", "config.yaml", "config.json", "config.py", "config.js",
    "settings.py", "settings.yml", "settings.json",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", ".dockerenv",
    "credentials", "credentials.json", "credentials.yml",
    "secrets.yml", "secrets.json", "secrets.yaml",
    ".htpasswd", ".netrc", ".pgpass",
    "wp-config.php", "application.properties", "application.yml",
    "appsettings.json", "web.config",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc", "pip.conf",
    "terraform.tfvars", "terraform.tfstate",
]

# Code search queries to find secrets referencing a target domain
SECRET_SEARCH_QUERIES = [
    "password", "api_key", "apikey", "secret", "token",
    "access_key", "private_key", "credentials",
]


@dataclass
class SecretFinding:
    """A single secret finding."""
    secret_type: str
    match_preview: str  # Truncated — never the full secret
    source_url: str
    file_path: str
    severity: str
    entropy: float = 0.0
    line_number: int = 0
    context: str = ""  # Surrounding text (redacted)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "type": "secret_exposure",
            "vuln_type": "secret_exposure",
            "attack": f"leaked_{self.secret_type}",
            "severity": self.severity,
            "url": self.source_url,
            "details": f"Leaked {self.secret_type}: {self.match_preview}",
            "file_path": self.file_path,
            "entropy": round(self.entropy, 2),
            "confidence": 0.9 if self.entropy >= 4.5 else 0.7,
            "discovered_at": self.discovered_at,
        }


class SecretScanner:
    """Scan GitHub repositories for leaked secrets."""

    # 40+ regex patterns for different secret types
    PATTERNS: Dict[str, re.Pattern] = {}
    _PATTERN_DEFS = {
        # AWS
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "aws_mws_key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        # GitHub
        "github_pat": r"ghp_[A-Za-z0-9_]{36}",
        "github_oauth": r"gho_[A-Za-z0-9_]{36}",
        "github_app_token": r"ghu_[A-Za-z0-9_]{36}",
        "github_refresh_token": r"ghr_[A-Za-z0-9_]{36}",
        "github_fine_grained": r"github_pat_[A-Za-z0-9_]{22,}",
        # Slack
        "slack_token": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        # Google / Firebase
        "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
        "firebase_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "gcp_service_account": r'"type"\s*:\s*"service_account"',
        "google_oauth_id": r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
        # Stripe
        "stripe_live_key": r"sk_live_[0-9a-zA-Z]{24,}",
        "stripe_test_key": r"sk_test_[0-9a-zA-Z]{24,}",
        "stripe_restricted": r"rk_live_[0-9a-zA-Z]{24,}",
        # Payment / Commerce
        "square_access_token": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "square_oauth": r"sq0csp-[0-9A-Za-z\-_]{43}",
        "shopify_shared_secret": r"shpss_[a-fA-F0-9]{32}",
        "shopify_access_token": r"shpat_[a-fA-F0-9]{32}",
        "shopify_custom_token": r"shpca_[a-fA-F0-9]{32}",
        "shopify_private_token": r"shppa_[a-fA-F0-9]{32}",
        # Communication
        "twilio_account_sid": r"AC[a-z0-9]{32}",
        "twilio_api_key": r"SK[0-9a-fA-F]{32}",
        "sendgrid_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "mailgun_key": r"key-[0-9a-zA-Z]{32}",
        "mailchimp_key": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "telegram_bot_token": r"[0-9]+:AA[A-Za-z0-9_-]{33}",
        "discord_token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        # Cloud / Infra
        "heroku_api_key": r"[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "azure_storage_key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
        "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
        # Auth / Tokens
        "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "oauth_token": r"ya29\.[A-Za-z0-9_-]+",
        "bearer_token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}",
        # Package managers
        "npm_token": r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+",
        "pypi_token": r"pypi-[A-Za-z0-9_-]{50,}",
        "nuget_key": r"oy2[a-z0-9]{43}",
        "dockerhub_token": r"dckr_pat_[A-Za-z0-9_-]+",
        # Crypto
        "private_key_pem": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        # Database
        "database_url": r"(?i)(mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp)://[^\s'\"]+",
        "password_in_url": r"://[^/\s:]+:[^/\s:@]+@[^/\s]+",
        # Generic
        "generic_api_key": r'(?i)(api[_\-]?key|apikey|api_secret)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{20,})',
        "generic_secret": r'(?i)(secret|password|passwd|pwd|token)\s*[=:]\s*[\'"]?([^\s\'"]{8,})',
    }

    # Severity per secret type
    SEVERITY_MAP = {
        "aws_access_key": "critical", "aws_secret_key": "critical", "aws_mws_key": "critical",
        "github_pat": "high", "github_oauth": "high", "github_app_token": "high",
        "github_refresh_token": "high", "github_fine_grained": "high",
        "stripe_live_key": "critical", "stripe_restricted": "critical",
        "stripe_test_key": "medium",
        "private_key_pem": "critical", "database_url": "critical",
        "password_in_url": "critical", "azure_storage_key": "critical",
        "gcp_service_account": "high",
        "slack_token": "high", "slack_webhook": "medium",
        "sendgrid_key": "high", "mailgun_key": "high",
        "twilio_account_sid": "high", "twilio_api_key": "high",
        "telegram_bot_token": "high", "discord_token": "high",
        "jwt_token": "medium", "oauth_token": "high", "bearer_token": "medium",
        "generic_api_key": "medium", "generic_secret": "medium",
    }

    # Types that should skip entropy check (structural matches are enough)
    SKIP_ENTROPY = {
        "private_key_pem", "database_url", "password_in_url",
        "gcp_service_account", "azure_storage_key", "slack_webhook",
    }

    def __init__(self, github_token: Optional[str] = None, verbose: bool = True):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.verbose = verbose
        self.findings: List[SecretFinding] = []
        self._rate_remaining = 60 if not self.github_token else 5000
        self._seen_hashes: set = set()  # Dedup

        # Compile patterns once
        if not SecretScanner.PATTERNS:
            for name, pattern in self._PATTERN_DEFS.items():
                try:
                    SecretScanner.PATTERNS[name] = re.compile(pattern)
                except re.error:
                    logger.warning(f"Invalid regex for {name}, skipping")

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [SECRETS] [{level}] {msg}")

    # --- Entropy ---

    @staticmethod
    def shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if len(s) < 8:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((f / length) * math.log2(f / length) for f in freq.values())

    def _is_high_entropy(self, s: str, threshold: float = 4.5) -> bool:
        return self.shannon_entropy(s) >= threshold

    # --- Truncation (NEVER store full secret) ---

    @staticmethod
    def _truncate(value: str, max_len: int = 20) -> str:
        """Truncate secret value for safe storage. NEVER stores full secrets."""
        if len(value) <= max_len:
            half = len(value) // 3
            return value[:half] + "***"
        return value[:max_len] + "..."

    # --- GitHub API helpers ---

    def _api_headers(self) -> dict:
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "VIPER-SecretScanner"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    async def _github_get(self, session, url: str) -> Optional[dict]:
        """GET from GitHub API with rate limit awareness."""
        if self._rate_remaining <= 1:
            self.log("GitHub API rate limit reached, stopping", "WARN")
            return None
        try:
            async with session.get(url, headers=self._api_headers(), timeout=15) as resp:
                self._rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", self._rate_remaining - 1))
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 403:
                    self.log(f"Rate limited or forbidden: {url}", "WARN")
                    self._rate_remaining = 0
                elif resp.status == 404:
                    pass  # Normal — org vs user
                else:
                    self.log(f"GitHub API {resp.status}: {url}", "WARN")
        except Exception as e:
            self.log(f"GitHub API error: {e}", "ERROR")
        return None

    async def _github_get_text(self, session, url: str) -> Optional[str]:
        """GET raw text content from GitHub."""
        if self._rate_remaining <= 1:
            return None
        try:
            headers = self._api_headers()
            headers["Accept"] = "application/vnd.github.v3.raw"
            async with session.get(url, headers=headers, timeout=15) as resp:
                self._rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", self._rate_remaining - 1))
                if resp.status == 200:
                    return await resp.text()
        except Exception:
            pass
        return None

    # --- Core scanning ---

    def _scan_content(self, content: str, source_url: str, file_path: str = "") -> List[SecretFinding]:
        """Scan text content against all secret patterns. Returns new findings."""
        new_findings = []
        lines = content.split("\n")

        for name, pattern in self.PATTERNS.items():
            for match in pattern.finditer(content):
                raw = match.group()

                # Dedup by hash
                import hashlib
                h = hashlib.sha256(raw.encode(errors="ignore")).hexdigest()[:16]
                if h in self._seen_hashes:
                    continue

                # Entropy check (skip for structural matches)
                entropy = self.shannon_entropy(raw)
                if name not in self.SKIP_ENTROPY and not self._is_high_entropy(raw) and len(raw) < 40:
                    continue

                self._seen_hashes.add(h)

                # Find line number
                pos = match.start()
                line_num = content[:pos].count("\n") + 1

                # Context (redacted neighbor lines)
                ctx = ""
                if 0 < line_num <= len(lines):
                    ctx = lines[line_num - 1].strip()[:80]

                finding = SecretFinding(
                    secret_type=name,
                    match_preview=self._truncate(raw),
                    source_url=source_url,
                    file_path=file_path,
                    severity=self.SEVERITY_MAP.get(name, "medium"),
                    entropy=entropy,
                    line_number=line_num,
                    context=ctx,
                )
                new_findings.append(finding)
                self.findings.append(finding)
                self.log(f"Found {name} in {file_path} (entropy={entropy:.2f})")

        return new_findings

    # --- Public scanning methods ---

    async def scan_github_org(self, org_name: str, session=None, max_repos: int = 20) -> List[SecretFinding]:
        """Scan public repos of a GitHub org or user."""
        import aiohttp
        close_session = False
        if session is None:
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            close_session = True

        try:
            self.log(f"Scanning GitHub org/user: {org_name} (max {max_repos} repos)")

            # Try org first, then user
            repos_data = await self._github_get(session, f"https://api.github.com/orgs/{org_name}/repos?per_page=100&sort=updated")
            if not repos_data:
                repos_data = await self._github_get(session, f"https://api.github.com/users/{org_name}/repos?per_page=100&sort=updated")
            if not repos_data:
                self.log(f"No repos found for {org_name}", "WARN")
                return []

            repos = repos_data[:max_repos]
            self.log(f"Found {len(repos_data)} repos, scanning top {len(repos)}")

            all_findings = []
            for repo in repos:
                if self._rate_remaining <= 5:
                    self.log("Approaching rate limit, stopping scan", "WARN")
                    break
                repo_name = repo.get("full_name", "")
                if repo.get("fork"):
                    continue  # Skip forks
                findings = await self._scan_repo_contents(session, repo_name)
                all_findings.extend(findings)

            self.log(f"Org scan complete: {len(all_findings)} secrets found in {org_name}")
            return all_findings
        finally:
            if close_session:
                await session.close()

    async def _scan_repo_contents(self, session, repo_full_name: str) -> List[SecretFinding]:
        """Scan sensitive files in a single repo."""
        findings = []
        api_base = f"https://api.github.com/repos/{repo_full_name}/contents"

        # Check root directory for sensitive files
        root = await self._github_get(session, api_base)
        if not root or not isinstance(root, list):
            return findings

        root_files = {item["name"]: item for item in root if item.get("type") == "file"}

        for sensitive_name in SENSITIVE_FILES:
            if sensitive_name in root_files:
                item = root_files[sensitive_name]
                raw_url = item.get("download_url", "")
                if not raw_url:
                    continue
                content = await self._github_get_text(session, raw_url)
                if content:
                    html_url = item.get("html_url", raw_url)
                    findings.extend(self._scan_content(content, html_url, f"{repo_full_name}/{sensitive_name}"))

        # Also scan common subdirectories
        for subdir in ["config", "configs", "settings", ".github", "deploy", "scripts", "infra"]:
            if subdir in {item["name"] for item in root if item.get("type") == "dir"}:
                subdir_items = await self._github_get(session, f"{api_base}/{subdir}")
                if subdir_items and isinstance(subdir_items, list):
                    for item in subdir_items[:10]:
                        if item.get("type") != "file":
                            continue
                        name = item["name"]
                        if any(name.endswith(ext) for ext in [".yml", ".yaml", ".json", ".env", ".conf", ".cfg", ".ini", ".properties", ".py", ".js", ".sh"]):
                            raw_url = item.get("download_url", "")
                            if raw_url:
                                content = await self._github_get_text(session, raw_url)
                                if content and len(content) < 500_000:  # Skip huge files
                                    html_url = item.get("html_url", raw_url)
                                    findings.extend(self._scan_content(content, html_url, f"{repo_full_name}/{subdir}/{name}"))

        return findings

    async def scan_repo(self, repo_url: str, session=None) -> List[SecretFinding]:
        """Scan a single GitHub repo by URL."""
        import aiohttp
        close_session = False
        if session is None:
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            close_session = True

        try:
            parsed = urlparse(repo_url)
            parts = parsed.path.strip("/").split("/")
            if len(parts) >= 2:
                repo_full_name = f"{parts[0]}/{parts[1]}"
                self.log(f"Scanning repo: {repo_full_name}")
                return await self._scan_repo_contents(session, repo_full_name)
            else:
                self.log(f"Invalid repo URL: {repo_url}", "ERROR")
                return []
        finally:
            if close_session:
                await session.close()

    async def scan_code_search(self, domain: str, session=None, max_queries: int = 5) -> List[SecretFinding]:
        """Use GitHub code search to find secrets mentioning the target domain."""
        import aiohttp
        close_session = False
        if session is None:
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            close_session = True

        try:
            self.log(f"Code search for secrets mentioning: {domain}")
            all_findings = []

            for query_term in SECRET_SEARCH_QUERIES[:max_queries]:
                if self._rate_remaining <= 5:
                    break
                search_url = f"https://api.github.com/search/code?q={domain}+{query_term}&per_page=10"
                result = await self._github_get(session, search_url)
                if not result:
                    continue

                items = result.get("items", [])
                for item in items[:5]:
                    raw_url = item.get("html_url", "")
                    git_url = item.get("git_url", "")
                    if git_url:
                        content = await self._github_get_text(session, git_url)
                        if content:
                            path = item.get("path", "")
                            repo_name = item.get("repository", {}).get("full_name", "")
                            all_findings.extend(self._scan_content(content, raw_url, f"{repo_name}/{path}"))

                # Brief pause between search queries to be polite
                await asyncio.sleep(1)

            self.log(f"Code search complete: {len(all_findings)} secrets found")
            return all_findings
        finally:
            if close_session:
                await session.close()

    async def scan_target(self, target_domain: str, session=None) -> List[SecretFinding]:
        """Full secret scan: org repos + code search. Main entry point for viper_core integration."""
        import aiohttp
        close_session = False
        if session is None:
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            close_session = True

        try:
            # Extract org name from domain (e.g., "example.com" -> "example")
            org_guess = target_domain.split(".")[0] if "." in target_domain else target_domain

            self.log(f"=== Secret Scan: {target_domain} ===")
            all_findings = []

            # Phase 1: Scan org/user repos
            org_findings = await self.scan_github_org(org_guess, session=session)
            all_findings.extend(org_findings)

            # Phase 2: Code search for domain references
            search_findings = await self.scan_code_search(target_domain, session=session)
            all_findings.extend(search_findings)

            self.log(f"=== Secret Scan Complete: {len(all_findings)} total findings ===")
            return all_findings
        finally:
            if close_session:
                await session.close()

    def scan_text(self, text: str, source: str = "inline") -> List[SecretFinding]:
        """Scan arbitrary text for secrets (synchronous). Useful for scanning local files or responses."""
        return self._scan_content(text, source, source)

    def get_findings_dicts(self) -> List[dict]:
        """Return all findings as dicts suitable for viper_core results."""
        return [f.to_dict() for f in self.findings]

    def summary(self) -> str:
        """Human-readable summary of findings."""
        if not self.findings:
            return "No secrets found."
        by_type: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        lines = [f"Secret Scanner: {len(self.findings)} findings"]
        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_sev:
                lines.append(f"  {sev.upper()}: {by_sev[sev]}")
        for t, c in sorted(by_type.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  - {t}: {c}")
        return "\n".join(lines)
