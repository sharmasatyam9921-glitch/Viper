#!/usr/bin/env python3
"""
VIPER 4.0 — ParamSpider Passive URL Parameter Mining (G8)

Discovers historically parameterized URLs via Wayback Machine using ParamSpider.
Runs per-domain with temp directory management, deduplication, and param classification.
Graceful fallback if paramspider is not installed.

Usage:
    from recon.paramspider_discovery import run_paramspider_discovery, paramspider_available
    if paramspider_available():
        results = run_paramspider_discovery({"example.com", "sub.example.com"})
"""

import logging
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("viper.paramspider")

# ---------------------------------------------------------------------------
# Parameter classification
# ---------------------------------------------------------------------------

_PARAM_CATEGORIES = {
    "idor": {"id", "uid", "user_id", "userid", "account", "account_id",
             "order_id", "orderid", "invoice", "profile", "pid", "cid"},
    "redirect": {"url", "uri", "link", "href", "redirect", "return", "next",
                 "goto", "redir", "callback", "cb", "continue", "dest",
                 "destination", "return_to", "returnTo", "redirect_uri"},
    "file_inclusion": {"file", "filename", "path", "filepath", "dir", "folder",
                       "document", "template", "tpl", "page", "include", "inc",
                       "load", "read", "fetch", "content"},
    "injection": {"cmd", "exec", "command", "run", "query", "search", "q", "s",
                  "keyword", "input", "data", "payload", "value", "param",
                  "sql", "filter", "where", "sort", "order"},
    "auth": {"token", "key", "api_key", "apikey", "secret", "access_token",
             "session", "auth", "password", "passwd", "user", "username",
             "email", "login"},
    "debug": {"debug", "test", "verbose", "trace", "mode", "env", "config",
              "admin", "internal", "dev"},
    "ssrf": {"url", "uri", "host", "endpoint", "proxy", "target", "server",
             "fetch", "request", "webhook", "callback"},
}


def classify_parameter(name: str) -> str:
    """Classify a parameter name into a security-relevant category."""
    name_lower = name.lower().strip()
    for category, names in _PARAM_CATEGORIES.items():
        if name_lower in names:
            return category
    return "standard"


# ---------------------------------------------------------------------------
# ParamSpider availability check
# ---------------------------------------------------------------------------

def paramspider_available() -> bool:
    """Check if paramspider binary is installed and on PATH."""
    return shutil.which("paramspider") is not None


# ---------------------------------------------------------------------------
# Temp directory management
# ---------------------------------------------------------------------------

def _create_temp_dir() -> Path:
    """Create a temp directory for ParamSpider output files."""
    import tempfile
    base = Path(tempfile.gettempdir()) / "viper_paramspider"
    base.mkdir(parents=True, exist_ok=True)
    tmp = base / f"run_{uuid.uuid4().hex[:8]}"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def _cleanup_temp_dir(tmp_dir: Path):
    """Clean up temp directory, swallow errors."""
    try:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Per-domain execution
# ---------------------------------------------------------------------------

def _run_paramspider_for_domain(
    domain: str,
    placeholder: str = "FUZZ",
    timeout: int = 120,
    tmp_dir: Optional[Path] = None,
) -> List[str]:
    """
    Run ParamSpider for a single domain.

    Args:
        domain: Target domain to query (e.g. example.com)
        placeholder: Placeholder string for discovered param values
        timeout: Subprocess timeout in seconds
        tmp_dir: Working directory for output files

    Returns:
        List of discovered parameterized URLs (deduplicated)
    """
    cmd = ["paramspider", "-d", domain, "-s", "-p", placeholder]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(tmp_dir) if tmp_dir else None,
        )

        urls: Set[str] = set()

        # Parse stdout — one URL per line
        if result.stdout:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(line)

        # Fallback: read output file (ParamSpider writes results/{domain}.txt)
        if tmp_dir:
            for candidate in [
                tmp_dir / "results" / f"{domain}.txt",
                tmp_dir / "output" / f"{domain}.txt",
            ]:
                if candidate.exists():
                    for line in candidate.read_text(errors="replace").splitlines():
                        line = line.strip()
                        if line and line.startswith("http"):
                            urls.add(line)

        return sorted(urls)

    except subprocess.TimeoutExpired:
        logger.warning(f"[ParamSpider] Timeout ({timeout}s) for {domain}")
        # Attempt partial result recovery from output file
        partial: Set[str] = set()
        if tmp_dir:
            for candidate in [
                tmp_dir / "results" / f"{domain}.txt",
                tmp_dir / "output" / f"{domain}.txt",
            ]:
                if candidate.exists():
                    for line in candidate.read_text(errors="replace").splitlines():
                        line = line.strip()
                        if line and line.startswith("http"):
                            partial.add(line)
        if partial:
            logger.info(f"[ParamSpider] Recovered {len(partial)} partial results for {domain}")
        return sorted(partial)

    except FileNotFoundError:
        logger.warning("[ParamSpider] Binary not found — is it installed? pip install paramspider")
        return []

    except Exception as e:
        logger.warning(f"[ParamSpider] Error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# Multi-domain orchestrator
# ---------------------------------------------------------------------------

def run_paramspider_discovery(
    target_domains: Set[str],
    placeholder: str = "FUZZ",
    timeout_per_domain: int = 120,
) -> Dict:
    """
    Run ParamSpider passive parameter discovery across multiple domains.

    Args:
        target_domains: Set of domains to query
        placeholder: Placeholder for parameter values (default "FUZZ")
        timeout_per_domain: Per-domain timeout in seconds

    Returns:
        Dict with keys:
            urls            - list of all discovered parameterized URLs (deduplicated)
            urls_by_domain  - dict mapping domain -> list of URLs
            params          - list of {name, url, category} dicts for discovered params
            domains_scanned - number of domains processed
            stats           - summary statistics
    """
    if not paramspider_available():
        logger.info("[ParamSpider] Not installed — skipping passive param mining")
        return {
            "urls": [],
            "urls_by_domain": {},
            "params": [],
            "domains_scanned": 0,
            "stats": {"skipped": True, "reason": "paramspider not installed"},
        }

    logger.info(f"[ParamSpider] Starting passive parameter discovery")
    logger.info(f"[ParamSpider] Domains: {len(target_domains)}, placeholder: {placeholder}")

    all_urls: Set[str] = set()
    urls_by_domain: Dict[str, List[str]] = {}
    tmp_dir = _create_temp_dir()

    try:
        for i, domain in enumerate(sorted(target_domains), 1):
            logger.info(f"[ParamSpider] [{i}/{len(target_domains)}] Querying: {domain}")

            domain_urls = _run_paramspider_for_domain(
                domain=domain,
                placeholder=placeholder,
                timeout=timeout_per_domain,
                tmp_dir=tmp_dir,
            )

            urls_by_domain[domain] = domain_urls
            all_urls.update(domain_urls)
            logger.info(f"[ParamSpider] Found {len(domain_urls)} parameterized URLs for {domain}")
    finally:
        _cleanup_temp_dir(tmp_dir)

    # Deduplicate and extract parameters with classification
    deduped_urls = sorted(all_urls)
    params: List[Dict] = []
    seen_params: Set[str] = set()

    for url in deduped_urls:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for name in qs:
                key = f"{name}:{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if key not in seen_params:
                    seen_params.add(key)
                    params.append({
                        "name": name,
                        "url": url,
                        "category": classify_parameter(name),
                        "source": "paramspider",
                    })
        except Exception:
            continue

    stats = {
        "total_urls": len(deduped_urls),
        "total_params": len(params),
        "domains_scanned": len(target_domains),
        "domains_with_results": sum(1 for v in urls_by_domain.values() if v),
        "by_category": {},
    }

    # Count params by category
    for p in params:
        cat = p["category"]
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

    logger.info(f"[ParamSpider] Total: {len(deduped_urls)} URLs, {len(params)} unique params")
    if stats["by_category"]:
        for cat, count in sorted(stats["by_category"].items(), key=lambda x: -x[1]):
            logger.info(f"[ParamSpider]   {cat}: {count}")

    return {
        "urls": deduped_urls,
        "urls_by_domain": urls_by_domain,
        "params": params,
        "domains_scanned": len(target_domains),
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Merge helper for resource_enum integration
# ---------------------------------------------------------------------------

def merge_paramspider_into_results(
    paramspider_urls: List[str],
    paramspider_params: List[Dict],
    all_urls: Set[str],
    all_params: List[Dict],
    seen_params: Set[str],
) -> Tuple[int, int]:
    """
    Merge ParamSpider results into the main resource_enum collections.

    Args:
        paramspider_urls: URLs discovered by ParamSpider
        paramspider_params: Classified params from ParamSpider
        all_urls: Main URL set (mutated in-place)
        all_params: Main params list (mutated in-place)
        seen_params: Dedup set for params (mutated in-place)

    Returns:
        Tuple of (new_urls_added, new_params_added)
    """
    urls_before = len(all_urls)
    all_urls.update(paramspider_urls)
    new_urls = len(all_urls) - urls_before

    new_params = 0
    for p in paramspider_params:
        key = f"{p['name']}:{p['url']}"
        if key not in seen_params:
            seen_params.add(key)
            all_params.append(p)
            new_params += 1

    return new_urls, new_params
