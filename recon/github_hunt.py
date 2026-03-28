#!/usr/bin/env python3
"""
VIPER 4.0 GitHub Secret Hunt — Org-wide secret scanning.

Searches GitHub for an organization/domain and scans:
  - Organization repos (public)
  - Member repos (optional)
  - Gists (optional)
  - Commit history (configurable depth)

Uses 40+ secret regex patterns plus Shannon entropy detection.
PyGithub if available, otherwise falls back to GitHub REST API via urllib.

SECURITY: All matched secret values are truncated in output.
"""

import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote as url_quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger("viper.github_hunt")

# Try PyGithub, fall back gracefully
try:
    from github import Github, Auth
    from github.GithubException import RateLimitExceededException, GithubException
    HAS_PYGITHUB = True
except ImportError:
    HAS_PYGITHUB = False

# ═══════════════════════════════════════════════════════════════════
# SECRET PATTERNS — 40+ regex patterns
# ═══════════════════════════════════════════════════════════════════

SECRET_PATTERNS: Dict[str, str] = {
    # AWS
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "AWS MWS Key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    # Azure
    "Azure Storage Key": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "Azure Connection String": r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}",
    "Azure SAS Token": r"(?i)[?&]sig=[A-Za-z0-9%]{40,}",
    # GCP
    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GCP Service Account": r"\"type\":\s*\"service_account\"",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    # GitHub
    "GitHub Token (Classic)": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Token (Fine-grained)": r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
    "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
    "GitHub App Token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    # GitLab
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    # Slack
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    # Stripe
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
    # Payment
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    # Social / APIs
    "Twitter Bearer": r"AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    # Messaging
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-zA-Z0-9]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    # Databases
    "MongoDB Connection": r"mongodb(?:\+srv)?://[^\s'\"]+",
    "PostgreSQL Connection": r"postgres(?:ql)?://[^\s'\"]+",
    "Redis URL": r"redis://[^\s'\"]+",
    # CI/CD
    "NPM Token": r"(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}",
    "PyPI Token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}",
    "Docker Hub Token": r"dckr_pat_[A-Za-z0-9_-]{27}",
    # Keys
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    # JWT / Auth
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    # Generic
    "Generic API Key": r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
    "Hardcoded Password": r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",
    # Cloud
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    "Shopify Token": r"shpat_[a-fA-F0-9]{32}",
    # Misc
    "Telegram Bot Token": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
}

# Sensitive filenames
SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    "credentials", "credentials.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "config.json", "config.yaml", "config.yml", "secrets.json", "secrets.yaml",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc", ".dockercfg",
    "wp-config.php", "database.yml", "terraform.tfvars", "terraform.tfstate",
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


# ═══════════════════════════════════════════════════════════════════
# ENTROPY DETECTION
# ═══════════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _find_high_entropy_strings(content: str, threshold: float = 4.5, min_len: int = 16, max_len: int = 128) -> List[Dict]:
    """Find high-entropy strings that might be secrets."""
    findings = []
    # Match alphanumeric strings of significant length
    for match in re.finditer(r'[A-Za-z0-9+/=\-_]{' + str(min_len) + r',' + str(max_len) + r'}', content):
        candidate = match.group(0)
        entropy = _shannon_entropy(candidate)
        if entropy >= threshold:
            findings.append({
                "value": candidate[:40] + "..." if len(candidate) > 40 else candidate,
                "entropy": round(entropy, 2),
                "length": len(candidate),
            })
    return findings


# ═══════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class SecretFinding:
    """A single secret found in a GitHub resource."""
    pattern_name: str
    matched_value: str  # truncated
    file_path: str
    repo: str
    line_number: int = 0
    commit_sha: str = ""
    source_type: str = "file"  # file, commit, gist
    entropy: float = 0.0
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern_name,
            "value": self.matched_value,
            "file": self.file_path,
            "repo": self.repo,
            "line": self.line_number,
            "commit": self.commit_sha,
            "source": self.source_type,
            "entropy": self.entropy,
            "verified": self.verified,
        }


@dataclass
class GitHubHuntResults:
    """Aggregated results from a GitHub secret hunt."""
    findings: List[SecretFinding] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    high_entropy_strings: List[Dict] = field(default_factory=list)
    repos_scanned: int = 0
    members_scanned: int = 0
    gists_scanned: int = 0
    commits_scanned: int = 0
    target: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "sensitive_files": self.sensitive_files,
            "high_entropy_strings": self.high_entropy_strings,
            "repos_scanned": self.repos_scanned,
            "members_scanned": self.members_scanned,
            "gists_scanned": self.gists_scanned,
            "commits_scanned": self.commits_scanned,
            "target": self.target,
            "error": self.error,
        }


# ═══════════════════════════════════════════════════════════════════
# GITHUB REST API FALLBACK (urllib)
# ═══════════════════════════════════════════════════════════════════

def _github_api_get(url: str, token: Optional[str] = None, page: int = 1, per_page: int = 100) -> Tuple[List, bool]:
    """
    GET from GitHub REST API. Returns (data, has_more).
    Uses urllib so PyGithub is not required.
    """
    separator = "&" if "?" in url else "?"
    full_url = f"{url}{separator}page={page}&per_page={per_page}"

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "VIPER/4.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = Request(full_url, headers=headers)
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            has_more = len(data) == per_page if isinstance(data, list) else False
            return (data if isinstance(data, list) else [data]), has_more
    except HTTPError as e:
        if e.code == 403:
            logger.warning(f"[GitHubHunt] Rate limited or forbidden: {full_url}")
        elif e.code == 404:
            logger.info(f"[GitHubHunt] Not found: {full_url}")
        else:
            logger.warning(f"[GitHubHunt] HTTP {e.code}: {full_url}")
        return [], False
    except (URLError, Exception) as e:
        logger.warning(f"[GitHubHunt] Request failed: {e}")
        return [], False


def _get_file_content_api(owner: str, repo: str, path: str, token: Optional[str] = None) -> Optional[str]:
    """Fetch file content from GitHub API (base64 decoded)."""
    import base64
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{url_quote(path, safe='/')}"
    data, _ = _github_api_get(url, token)
    if data and isinstance(data, list) and len(data) > 0:
        item = data[0]
    elif data and isinstance(data, dict):
        item = data
    else:
        return None

    content_b64 = item.get("content", "")
    if content_b64:
        try:
            return base64.b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════════════════════
# SCANNING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def _scan_content(content: str, file_path: str, repo: str, source_type: str = "file",
                  commit_sha: str = "", entropy_threshold: float = 4.5) -> Tuple[List[SecretFinding], List[Dict]]:
    """Scan content for secrets using regex patterns + entropy."""
    findings: List[SecretFinding] = []
    entropy_hits: List[Dict] = []
    seen_values: Set[str] = set()

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern in SECRET_PATTERNS.items():
            try:
                for match in re.finditer(pattern, line):
                    value = match.group(0)
                    truncated = value[:8] + "****..." if len(value) > 8 else "****"
                    if truncated in seen_values:
                        continue
                    seen_values.add(truncated)
                    findings.append(SecretFinding(
                        pattern_name=pattern_name,
                        matched_value=truncated,
                        file_path=file_path,
                        repo=repo,
                        line_number=line_num,
                        commit_sha=commit_sha,
                        source_type=source_type,
                        entropy=round(_shannon_entropy(value), 2),
                    ))
            except re.error:
                continue

    # High-entropy string detection
    for hit in _find_high_entropy_strings(content, threshold=entropy_threshold):
        hit["file"] = file_path
        hit["repo"] = repo
        hit["source"] = source_type
        entropy_hits.append(hit)

    return findings, entropy_hits


def _scan_repo_files_api(owner: str, repo_name: str, token: Optional[str] = None,
                         max_files: int = 200) -> Tuple[List[SecretFinding], List[Dict], List[Dict]]:
    """Scan repo files for secrets using GitHub API tree endpoint."""
    findings: List[SecretFinding] = []
    entropy_hits: List[Dict] = []
    sensitive_files: List[Dict] = []

    # Get repo tree (recursive)
    url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/HEAD?recursive=1"
    data, _ = _github_api_get(url, token)

    tree_items = []
    if data and isinstance(data, list):
        # API returns the tree object, not a list
        tree_items = data[0].get("tree", []) if isinstance(data[0], dict) else []
    elif data and isinstance(data, dict):
        tree_items = data.get("tree", [])

    files_scanned = 0
    for item in tree_items:
        if files_scanned >= max_files:
            break
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        basename = os.path.basename(path)
        ext = os.path.splitext(path)[1].lower()

        # Check sensitive filename
        if basename in SENSITIVE_FILENAMES or path in SENSITIVE_FILENAMES:
            sensitive_files.append({"file": path, "repo": f"{owner}/{repo_name}"})

        # Skip binary/large extensions
        if ext in SKIP_EXTENSIONS:
            continue

        # Skip large files (>1MB blobs)
        size = item.get("size", 0)
        if size > 1_000_000:
            continue

        content = _get_file_content_api(owner, repo_name, path, token)
        if content:
            files_scanned += 1
            f, e = _scan_content(content, path, f"{owner}/{repo_name}")
            findings.extend(f)
            entropy_hits.extend(e)

    return findings, entropy_hits, sensitive_files


def _scan_commits_api(owner: str, repo_name: str, token: Optional[str] = None,
                      max_commits: int = 50) -> List[SecretFinding]:
    """Scan recent commit diffs for secrets."""
    findings: List[SecretFinding] = []
    url = f"https://api.github.com/repos/{owner}/{repo_name}/commits"
    commits, _ = _github_api_get(url, token, per_page=min(max_commits, 100))

    for commit in commits[:max_commits]:
        sha = commit.get("sha", "")
        if not sha:
            continue
        # Get commit diff
        diff_url = f"https://api.github.com/repos/{owner}/{repo_name}/commits/{sha}"
        diff_data, _ = _github_api_get(diff_url, token)
        if not diff_data:
            continue

        item = diff_data[0] if isinstance(diff_data, list) else diff_data
        for file_info in item.get("files", []):
            patch = file_info.get("patch", "")
            if patch:
                f, _ = _scan_content(
                    patch,
                    file_info.get("filename", "unknown"),
                    f"{owner}/{repo_name}",
                    source_type="commit",
                    commit_sha=sha[:8],
                )
                findings.extend(f)

    return findings


def _scan_gists_api(username: str, token: Optional[str] = None, max_gists: int = 50) -> List[SecretFinding]:
    """Scan a user's public gists for secrets."""
    findings: List[SecretFinding] = []
    url = f"https://api.github.com/users/{username}/gists"
    gists, _ = _github_api_get(url, token, per_page=min(max_gists, 100))

    for gist in gists[:max_gists]:
        gist_id = gist.get("id", "")
        files = gist.get("files", {})
        for fname, finfo in files.items():
            raw_url = finfo.get("raw_url", "")
            if not raw_url:
                continue
            try:
                req = Request(raw_url, headers={"User-Agent": "VIPER/4.0"})
                with urlopen(req, timeout=15) as resp:
                    content = resp.read().decode("utf-8", errors="replace")
                f, _ = _scan_content(content, fname, f"gist:{gist_id}", source_type="gist")
                findings.extend(f)
            except Exception:
                continue

    return findings


# ═══════════════════════════════════════════════════════════════════
# PYGITHUB PATH (preferred when available)
# ═══════════════════════════════════════════════════════════════════

def _scan_with_pygithub(
    target_org: str,
    token: str,
    scan_members: bool = False,
    scan_gists: bool = True,
    scan_commits: bool = True,
    max_commits: int = 50,
    max_repos: int = 100,
) -> GitHubHuntResults:
    """Full scan using PyGithub library."""
    results = GitHubHuntResults(target=target_org)
    g = Github(auth=Auth.Token(token)) if token else Github()

    try:
        org = g.get_organization(target_org)
        repos = list(org.get_repos(type="public"))[:max_repos]
    except GithubException:
        # Maybe it's a user, not an org
        try:
            user = g.get_user(target_org)
            repos = list(user.get_repos())[:max_repos]
        except GithubException as e:
            results.error = f"Could not find org or user '{target_org}': {e}"
            return results

    results.repos_scanned = len(repos)

    for repo in repos:
        try:
            # Scan default branch tree
            tree = repo.get_git_tree(sha=repo.default_branch, recursive=True)
            files_scanned = 0
            for item in tree.tree:
                if files_scanned >= 200:
                    break
                if item.type != "blob":
                    continue
                basename = os.path.basename(item.path)
                ext = os.path.splitext(item.path)[1].lower()

                if basename in SENSITIVE_FILENAMES or item.path in SENSITIVE_FILENAMES:
                    results.sensitive_files.append({"file": item.path, "repo": repo.full_name})

                if ext in SKIP_EXTENSIONS or (item.size and item.size > 1_000_000):
                    continue

                try:
                    blob = repo.get_git_blob(item.sha)
                    import base64
                    content = base64.b64decode(blob.content).decode("utf-8", errors="replace")
                    files_scanned += 1
                    f, e = _scan_content(content, item.path, repo.full_name)
                    results.findings.extend(f)
                    results.high_entropy_strings.extend(e)
                except Exception:
                    continue

            # Scan commits
            if scan_commits:
                try:
                    commits = list(repo.get_commits())[:max_commits]
                    for commit in commits:
                        results.commits_scanned += 1
                        for cf in commit.files:
                            if cf.patch:
                                f, _ = _scan_content(
                                    cf.patch, cf.filename, repo.full_name,
                                    source_type="commit", commit_sha=commit.sha[:8],
                                )
                                results.findings.extend(f)
                except Exception:
                    pass

        except RateLimitExceededException:
            logger.warning("[GitHubHunt] Rate limit hit, pausing 60s...")
            time.sleep(60)
        except GithubException as e:
            logger.warning(f"[GitHubHunt] Error scanning {repo.full_name}: {e}")

    # Scan member repos + gists
    if scan_members or scan_gists:
        try:
            org = g.get_organization(target_org)
            members = list(org.get_members())[:50]
            results.members_scanned = len(members)
            for member in members:
                if scan_gists:
                    try:
                        for gist in member.get_gists()[:20]:
                            results.gists_scanned += 1
                            for fname, finfo in gist.files.items():
                                try:
                                    content = finfo.content or ""
                                    if content:
                                        f, _ = _scan_content(content, fname, f"gist:{gist.id}", source_type="gist")
                                        results.findings.extend(f)
                                except Exception:
                                    continue
                    except Exception:
                        pass
        except Exception:
            pass

    g.close()
    return results


# ═══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def run_github_hunt(
    target: str,
    token: Optional[str] = None,
    scan_members: bool = False,
    scan_gists: bool = True,
    scan_commits: bool = True,
    max_commits: int = 50,
    max_repos: int = 100,
    entropy_threshold: float = 4.5,
) -> GitHubHuntResults:
    """
    Run GitHub secret hunt for an organization or user.

    Args:
        target: GitHub org name, username, or domain (e.g. "acme-corp" or "acme.com").
        token: GitHub personal access token. Falls back to GITHUB_TOKEN env var.
        scan_members: Scan member repos (org only, requires auth).
        scan_gists: Scan user/member gists.
        scan_commits: Scan recent commit diffs.
        max_commits: Max commits to scan per repo.
        max_repos: Max repos to scan.
        entropy_threshold: Shannon entropy threshold for high-entropy detection.

    Returns:
        GitHubHuntResults with all findings.
    """
    token = token or os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GITHUB_ACCESS_TOKEN", "")

    # Normalize target: if it looks like a domain, strip TLD for org search
    org_name = target
    if "." in target:
        org_name = target.split(".")[0]

    logger.info(f"[GitHubHunt] Starting secret hunt for: {org_name} (from: {target})")
    logger.info(f"[GitHubHunt] Auth: {'token provided' if token else 'unauthenticated (rate-limited)'}")
    logger.info(f"[GitHubHunt] Scan members: {scan_members}, gists: {scan_gists}, commits: {scan_commits}")

    # Use PyGithub if available and token is set
    if HAS_PYGITHUB and token:
        logger.info("[GitHubHunt] Using PyGithub backend")
        return _scan_with_pygithub(
            org_name, token,
            scan_members=scan_members,
            scan_gists=scan_gists,
            scan_commits=scan_commits,
            max_commits=max_commits,
            max_repos=max_repos,
        )

    # Fallback: urllib REST API
    logger.info("[GitHubHunt] Using urllib REST API fallback")
    results = GitHubHuntResults(target=org_name)

    # Get org/user repos
    repos_url = f"https://api.github.com/orgs/{org_name}/repos"
    repos, _ = _github_api_get(repos_url, token, per_page=min(max_repos, 100))
    if not repos:
        # Try as user
        repos_url = f"https://api.github.com/users/{org_name}/repos"
        repos, _ = _github_api_get(repos_url, token, per_page=min(max_repos, 100))

    if not repos:
        results.error = f"No repos found for '{org_name}'"
        return results

    results.repos_scanned = len(repos[:max_repos])

    for repo_data in repos[:max_repos]:
        repo_name = repo_data.get("name", "")
        owner = repo_data.get("owner", {}).get("login", org_name)
        full_name = f"{owner}/{repo_name}"

        logger.info(f"[GitHubHunt] Scanning {full_name}...")

        # Scan files
        f, e, sf = _scan_repo_files_api(owner, repo_name, token)
        results.findings.extend(f)
        results.high_entropy_strings.extend(e)
        results.sensitive_files.extend(sf)

        # Scan commits
        if scan_commits:
            cf = _scan_commits_api(owner, repo_name, token, max_commits)
            results.findings.extend(cf)
            results.commits_scanned += min(max_commits, 100)

    # Scan gists
    if scan_gists:
        gf = _scan_gists_api(org_name, token)
        results.findings.extend(gf)
        results.gists_scanned += 1

    logger.info(f"[GitHubHunt] Complete: {len(results.findings)} secrets, "
                f"{len(results.sensitive_files)} sensitive files, "
                f"{len(results.high_entropy_strings)} high-entropy strings")

    return results


async def run_github_hunt_async(target: str, **kwargs) -> GitHubHuntResults:
    """Async wrapper."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: run_github_hunt(target, **kwargs))
