#!/usr/bin/env python3
"""
VIPER 4.0 - 7-Phase Automated Recon Pipeline
==============================================
Multi-tool parallel recon pipeline architecture. Orchestrates:

  Phase 1: Domain Discovery    - subdomains (subfinder/amass/crt.sh), DNS resolution
  Phase 2: Passive Intelligence- URLScan.io + WHOIS + Shodan InternetDB (no target contact)
  Phase 3: Port Scanning       - naabu/nmap + Shodan enrichment
  Phase 4: HTTP Probing        - httpx alive check, Wappalyzer tech fingerprinting
  Phase 5: Resource Enum       - katana crawling, gau/wayback URLs, JS analysis
  Phase 6: Vuln Scanning       - nuclei templates, custom security checks
  Phase 7: MITRE Enrichment    - CVE -> CWE -> CAPEC mapping

Reuses existing VIPER modules. External tools via subprocess with graceful
degradation. Graph writes happen in a background thread (serialised, max_workers=1).
Async-native, also callable sync via ``pipeline.run_sync(target)``.

Usage::

    pipeline = ReconPipeline(graph_engine=ge)
    results = await pipeline.run("example.com")
    results = await pipeline.run("example.com", phases=["domain_discovery", "port_scan"])
    # or synchronously:
    results = pipeline.run_sync("example.com")
"""

import asyncio
import copy
import json
import logging
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("viper.recon.pipeline")

HACKAGENT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = HACKAGENT_DIR / "data" / "recon" / "pipeline"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Lazy imports — each VIPER component is optional
# ---------------------------------------------------------------------------

def _import_recon_engine():
    from recon.recon_engine import ReconEngine, ReconResult
    return ReconEngine, ReconResult

def _import_surface_mapper():
    from recon.surface_mapper import SurfaceMapper
    return SurfaceMapper

def _import_web_crawler():
    from recon.web_crawler import WebCrawler
    return WebCrawler

def _import_wappalyzer():
    from recon.wappalyzer import fingerprint as wappalyzer_fingerprint
    return wappalyzer_fingerprint

def _import_shodan():
    from recon.shodan_enricher import enrich_ips
    return enrich_ips

def _import_urlscan():
    from recon.urlscan_enricher import search as urlscan_search
    return urlscan_search

def _import_whois():
    from recon.whois_lookup import lookup as whois_lookup
    return whois_lookup

def _import_otx():
    from recon.otx_enricher import enrich as otx_enrich
    return otx_enrich

def _import_virustotal():
    from recon.virustotal_enricher import enrich as vt_enrich
    return vt_enrich

def _import_censys():
    from recon.censys_enricher import enrich_ips as censys_enrich_ips
    return censys_enrich_ips

def _import_masscan():
    from recon.masscan_scanner import (
        scan as masscan_scan,
        masscan_available,
        is_cidr,
        expand_cidr,
    )
    return masscan_scan, masscan_available, is_cidr, expand_cidr

def _import_fofa():
    from recon.fofa_enricher import enrich as fofa_enrich
    return fofa_enrich

def _import_netlas():
    from recon.netlas_enricher import enrich as netlas_enrich
    return netlas_enrich

def _import_criminalip():
    from recon.criminalip_enricher import enrich as cip_enrich
    return cip_enrich

def _import_zoomeye():
    from recon.zoomeye_enricher import enrich as ze_enrich
    return ze_enrich

def _import_wpscan():
    from recon.wpscan_scanner import scan as wpscan_scan, is_wordpress
    return wpscan_scan, is_wordpress

def _import_cve_lookup():
    from recon.cve_lookup import lookup_cves, lookup_cves_for_cpes
    return lookup_cves, lookup_cves_for_cpes

def _import_nuclei():
    from scanners.nuclei_scanner import NucleiScanner
    return NucleiScanner

def _import_mitre():
    from core.mitre_mapper import MitreMapper, enrich_finding_mitre
    return MitreMapper, enrich_finding_mitre

def _import_graph():
    from core.graph_engine import GraphEngine
    return GraphEngine


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ReconResults:
    """Aggregated results from the full 6-phase recon pipeline."""
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    phases_run: List[str] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)

    # Phase 1 — Domain Discovery
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    resolved_ips: Dict[str, str] = field(default_factory=dict)  # subdomain -> ip

    # Phase 1.5 — Passive Intelligence
    passive_subdomains: List[str] = field(default_factory=list)
    passive_ips: List[str] = field(default_factory=list)
    whois_data: Dict = field(default_factory=dict)
    urlscan_data: Dict = field(default_factory=dict)
    otx_data: Dict = field(default_factory=dict)
    virustotal_data: Dict = field(default_factory=dict)
    censys_data: List[Dict] = field(default_factory=list)
    fofa_data: Dict = field(default_factory=dict)
    netlas_data: Dict = field(default_factory=dict)
    criminalip_data: Dict = field(default_factory=dict)
    zoomeye_data: Dict = field(default_factory=dict)
    wpscan_data: Dict = field(default_factory=dict)
    js_analysis: Dict = field(default_factory=dict)
    passive_cves: List[Dict] = field(default_factory=list)

    # IP-mode metadata (when target is a CIDR or raw IP)
    ip_mode: bool = False
    cidr_targets: List[str] = field(default_factory=list)

    # Per-phase wall-clock timings (seconds) for parallel-group analytics
    phase_timings: Dict[str, float] = field(default_factory=dict)
    parallel_groups: List[Dict] = field(default_factory=list)

    # Phase 2 — Port Scanning
    open_ports: Dict[str, List[int]] = field(default_factory=dict)  # host -> [ports]
    shodan_data: Dict[str, Dict] = field(default_factory=dict)      # ip -> shodan blob

    # Phase 3 — HTTP Probing
    live_hosts: List[str] = field(default_factory=list)
    technologies: Dict[str, List[Dict]] = field(default_factory=dict)  # url -> [tech]
    http_responses: List[Dict] = field(default_factory=list)

    # Phase 4 — Resource Enumeration
    crawled_urls: List[str] = field(default_factory=list)
    archived_urls: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[Dict] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    endpoints: List[str] = field(default_factory=list)

    # Phase 5 — Vulnerability Scanning
    vulnerabilities: List[Dict] = field(default_factory=list)
    nuclei_findings: List[Dict] = field(default_factory=list)

    # Phase 6 — MITRE Enrichment
    mitre_enriched: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: (list(v) if isinstance(v, set) else v)
                for k, v in self.__dict__.items()}

    def save(self, path: Path = None) -> Path:
        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = self.target.replace("://", "_").replace("/", "_").replace(".", "_")
            path = OUTPUT_DIR / f"pipeline_{safe}_{ts}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        logger.info("Results saved to %s", path)
        return path


# ---------------------------------------------------------------------------
# Backward-compat aliases so old code importing PipelineResult still works
# ---------------------------------------------------------------------------
PipelineResult = ReconResults


# ---------------------------------------------------------------------------
# Progress helper
# ---------------------------------------------------------------------------

def _emit(phase: int, step: str, progress: float = 0.0, detail: str = ""):
    logger.info("[Phase %d/7] %s (%.0f%%) %s", phase, step, progress * 100, detail)


# ---------------------------------------------------------------------------
# External-tool helpers — graceful degradation
# ---------------------------------------------------------------------------

import os as _os

# ProjectDiscovery / Go security tools (httpx, nuclei, naabu, katana, ...)
# install to ~/go/bin. A pip package can shadow the real binary on PATH — most
# notably the `httpx` python library's CLI, which doesn't understand httpx's
# flags and silently produces no output (manifesting as "0 alive hosts"). So
# resolve to the REAL tool: explicit <NAME>_PATH env → ~/go/bin → PATH.
_GOBIN = Path(_os.environ.get("GOBIN") or (Path.home() / "go" / "bin"))


def _resolve_tool(name: str) -> Optional[str]:
    env = _os.environ.get(f"{name.upper()}_PATH")
    if env and Path(env).exists():
        return env
    for cand in (_GOBIN / name, _GOBIN / f"{name}.exe"):
        if cand.exists():
            return str(cand)
    return shutil.which(name)


def _tool_available(name: str) -> bool:
    return _resolve_tool(name) is not None


async def _run_tool(cmd: List[str], timeout: int = 300) -> Optional[str]:
    """Run an external CLI tool. Returns stdout or None.

    Uses synchronous subprocess.run() in a dedicated thread (not the
    default asyncio executor) so it works reliably from any thread.
    ``asyncio.create_subprocess_exec`` hangs in non-main threads on
    Windows ProactorEventLoop, and the default asyncio executor can be
    saturated when multiple background pipelines run concurrently.
    """
    tool = cmd[0]
    resolved = _resolve_tool(tool)
    if resolved is None:
        logger.warning("Tool '%s' not found on PATH -- skipping", tool)
        return None
    cmd = [resolved] + list(cmd[1:])  # use the real binary, not a pip shim

    import subprocess
    import concurrent.futures

    def _blocking_run():
        try:
            # Explicit stdin=DEVNULL so tools like naabu don't hang
            # waiting on inherited/undefined stdin from a parent that
            # has no terminal (happens when the whole chain runs via
            # the dashboard's spawned Python process).
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(
                    "%s exited %d: %s", tool, result.returncode,
                    result.stderr.decode(errors="replace")[:200],
                )
            return result.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            logger.warning("%s timed out after %ds", tool, timeout)
            return None
        except FileNotFoundError:
            logger.warning("Tool '%s' not found", tool)
            return None
        except Exception as exc:
            logger.warning("%s failed: %s", tool, exc)
            return None

    # Use a dedicated single-shot executor so we don't share the
    # (possibly saturated) default asyncio thread pool.
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        try:
            return await loop.run_in_executor(ex, _blocking_run)
        except Exception as exc:
            logger.warning("%s executor failed: %s", tool, exc)
            return None


def _write_targets_file(targets) -> str:
    """Write targets to a temp file and return its path."""
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tf.write("\n".join(targets))
    tf.close()
    return tf.name


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_PHASES = [
    "domain_discovery", "passive_intel", "port_scan", "http_probe",
    "resource_enum", "vuln_scan", "mitre_enrich",
]


# ---------------------------------------------------------------------------
# ReconPipeline
# ---------------------------------------------------------------------------

class ReconPipeline:
    """
    7-phase automated recon pipeline for VIPER 4.0.

    Phases run sequentially; within each phase, independent subtasks are
    parallelised via ThreadPoolExecutor or asyncio.gather.  Results flow
    forward through a context dict so later phases can use earlier output.

    Graph writes are serialised on a background thread so the main pipeline
    never blocks on DB I/O.
    """

    def __init__(self, graph_engine=None, session=None, settings: Dict = None):
        self.settings = settings or {}
        self.graph_engine = graph_engine
        self.session = session  # optional aiohttp session (backward compat)
        self._graph_executor: Optional[ThreadPoolExecutor] = None
        self._graph_futures: List = []
        self._recon_engine = None

    # ── Graph background writes ──────────────────────────────────────────

    def _graph_start(self):
        if self.graph_engine is not None:
            self._graph_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="graph-bg",
            )
            self._graph_futures = []

    def _graph_submit(self, fn, *args, **kwargs):
        """Submit a graph write to the background thread (deep-copy safe)."""
        if self._graph_executor is None:
            return
        # Deep-copy only JSON-serialisable data, skip unpicklable objects
        # (graph engine, queue objects, etc.)
        safe_args = []
        for a in args:
            try:
                safe_args.append(copy.deepcopy(a))
            except (TypeError, AttributeError):
                safe_args.append(a)  # Pass reference if not copyable
        safe_kwargs = {}
        for k, v in kwargs.items():
            try:
                safe_kwargs[k] = copy.deepcopy(v)
            except (TypeError, AttributeError):
                safe_kwargs[k] = v
        future = self._graph_executor.submit(fn, *safe_args, **safe_kwargs)
        self._graph_futures.append(future)

    def _graph_finish(self):
        if self._graph_executor is None:
            return
        self._graph_executor.shutdown(wait=True)
        for f in self._graph_futures:
            exc = f.exception()
            if exc:
                logger.warning("Graph write error: %s", exc)
        self._graph_executor = None

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname or url.split("/")[0]

    # ── Sync convenience ─────────────────────────────────────────────────

    def run_sync(self, target: str, phases: List[str] = None) -> ReconResults:
        """Synchronous wrapper — calls ``asyncio.run(self.run(...))``."""
        return asyncio.run(self.run(target, phases))

    # ══════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════

    # ── RoE time-window enforcement ───────────────────────────────────────

    def _check_roe_time_window(self) -> tuple:
        """
        Pre-phase check: block recon if outside the
        approved time window. Returns ``(allowed, reason)``.

        Honors two settings keys:
            - ``roe_window_start``: "HH:MM" local time (inclusive)
            - ``roe_window_end``:   "HH:MM" local time (exclusive)

        If neither is set, recon runs unrestricted.
        """
        start = self.settings.get("roe_window_start")
        end = self.settings.get("roe_window_end")
        if not (start and end):
            return True, ""

        try:
            now = datetime.now().time()
            sh, sm = map(int, start.split(":"))
            eh, em = map(int, end.split(":"))
            from datetime import time as dtime
            t_start, t_end = dtime(sh, sm), dtime(eh, em)
            if t_start <= now < t_end:
                return True, ""
            return False, (
                f"Outside RoE time window {start}-{end} (now={now.strftime('%H:%M')})"
            )
        except (ValueError, AttributeError) as exc:
            logger.warning("RoE time-window parse error: %s", exc)
            return True, ""

    # ── IP-mode detection ─────────────────────────────────────────────────

    def _detect_ip_mode(self, target: str) -> tuple:
        """
        Detect whether the target is a CIDR range or a bare IP.

        Returns ``(is_ip_mode, cidr_list, primary_label)`` where the
        primary_label is what to use as the domain key in the context
        dict (the first IP, for IP mode; the actual domain otherwise).
        """
        try:
            from recon.masscan_scanner import is_cidr, expand_cidr
            import ipaddress

            # Strip URL scheme but PRESERVE CIDR prefix.
            # Only split off a path if a scheme is present (http://host/path).
            if "://" in target:
                rest = target.split("://", 1)[1]
                cleaned = rest.split("/", 1)[0]  # strips path
            else:
                cleaned = target  # raw IP, CIDR, or domain

            # CIDR? Expand and use as primary host list
            if is_cidr(cleaned):
                hosts = expand_cidr(cleaned, max_hosts=256)
                if hosts:
                    return True, [cleaned], hosts[0]

            # Bare IPv4/IPv6, optionally with a port (host:port / [ipv6]:port).
            host_only = cleaned
            if cleaned.startswith("["):              # [::1]:4000
                host_only = cleaned[1:].split("]", 1)[0]
            elif cleaned.count(":") == 1:            # 127.0.0.1:4000
                host_only = cleaned.split(":", 1)[0]
            try:
                ipaddress.ip_address(host_only)
                return True, [host_only], host_only
            except ValueError:
                pass
        except ImportError:
            pass
        return False, [], ""

    async def run(self, target, phases: List[str] = None,
                  timeout_minutes: float = 30) -> ReconResults:
        """Run full or partial recon pipeline.

        Args:
            target: Domain, URL string, CIDR range, or Target dataclass.
            phases: Phase names to run (default: all 6).
            timeout_minutes: Hard timeout for the entire pipeline.

        Returns:
            ReconResults with all discovered data.
        """
        url = target.url if hasattr(target, "url") else str(target)

        # ── RoE time-window check (pre-phase) ────────────────────────
        allowed, reason = self._check_roe_time_window()
        if not allowed:
            results = ReconResults(target=url)
            results.errors.append({"phase": "roe_check", "error": reason})
            results.end_time = datetime.now().isoformat()
            logger.warning("[RoE] BLOCKED: %s", reason)
            return results

        # ── IP-mode detection ────────────────────────────────────────
        is_ip_mode, cidr_targets, primary_ip = self._detect_ip_mode(url)
        if is_ip_mode:
            domain = primary_ip
            logger.info("=== IP-MODE recon: target=%s (%d hosts)",
                        cidr_targets[0], len(cidr_targets))
        else:
            domain = self._extract_domain(url)

        phases = phases or list(ALL_PHASES)

        # In IP-mode, skip domain_discovery (no DNS to enumerate)
        if is_ip_mode and "domain_discovery" in phases:
            phases = [p for p in phases if p != "domain_discovery"]
            logger.info("IP-mode: skipping domain_discovery phase")

        results = ReconResults(target=url)
        results.ip_mode = is_ip_mode
        results.cidr_targets = cidr_targets
        logger.info("=== VIPER Recon Pipeline starting for: %s ===", domain)
        logger.info("Phases: %s", phases)

        self._graph_start()

        # Initialise shared recon engine
        try:
            ReconEngine, _ = _import_recon_engine()
            self._recon_engine = ReconEngine(verbose=True)
        except Exception as exc:
            logger.warning("ReconEngine import failed: %s", exc)
            self._recon_engine = None

        # Phase dispatch table
        phase_map = {
            "domain_discovery": (1, self._phase1_domain_discovery),
            "passive_intel":    (2, self._phase2_passive_intel),
            "port_scan":        (3, self._phase3_port_scan),
            "http_probe":       (4, self._phase4_http_probe),
            "resource_enum":    (5, self._phase5_resource_enum),
            "vuln_scan":        (6, self._phase6_vuln_scan),
            "mitre_enrich":     (7, self._phase7_mitre_enrich),
        }

        # Shared context carries data forward between phases
        ctx: Dict[str, Any] = {
            "domain": domain,
            "url": url,
            "subdomains": list(cidr_targets) if is_ip_mode else [],
            "resolved_ips": (
                {ip: ip for ip in cidr_targets} if is_ip_mode else {}
            ),
            "alive_hosts": [],
            "endpoints": [],
            "findings": [],
            "ip_mode": is_ip_mode,
            "cidr_targets": cidr_targets,
        }

        for phase_name in phases:
            if phase_name not in phase_map:
                logger.warning("Unknown phase '%s' -- skipping", phase_name)
                continue
            num, fn = phase_map[phase_name]
            _emit(num, f"Starting {phase_name}")
            t0 = time.time()
            try:
                phase_out = await fn(ctx, results)
                ctx.update(phase_out or {})
                results.phases_run.append(phase_name)
                phase_dur = time.time() - t0
                results.phase_timings[phase_name] = round(phase_dur, 2)
                _emit(num, f"Completed {phase_name}", 1.0,
                      f"({phase_dur:.1f}s)")
            except Exception as exc:
                logger.error("Phase %s failed: %s", phase_name, exc, exc_info=True)
                results.errors.append({"phase": phase_name, "error": str(exc)})

        self._graph_finish()
        results.end_time = datetime.now().isoformat()
        results.save()
        logger.info("=== Pipeline complete. %d/%d phases OK ===",
                     len(results.phases_run), len(phases))
        return results

    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Domain Discovery
    # ══════════════════════════════════════════════════════════════════════

    async def _phase1_domain_discovery(self, ctx: dict, results: ReconResults) -> dict:
        domain = ctx["domain"]
        subdomains: Set[str] = set()

        # 1a. ReconEngine built-in enum (subfinder + amass + crt.sh + hackertarget)
        if self._recon_engine:
            _emit(1, "Subdomain enumeration via ReconEngine", 0.1)
            try:
                subs = await self._recon_engine.enumerate_subdomains(
                    domain, parallel=True,
                )
                subdomains.update(subs)
            except Exception as exc:
                logger.warning("ReconEngine subdomain enum failed: %s", exc)

        # 1b. Direct subfinder fallback
        if not subdomains and _tool_available("subfinder"):
            _emit(1, "subfinder fallback", 0.3)
            out = await _run_tool(
                ["subfinder", "-d", domain, "-silent", "-all"], timeout=120,
            )
            if out:
                subdomains.update(l.strip() for l in out.splitlines() if l.strip())

        # 1c. crt.sh Python fallback
        if not subdomains:
            _emit(1, "crt.sh Python fallback", 0.5)
            try:
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(
                        f"https://crt.sh/?q=%.{domain}&output=json",
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 200:
                            for entry in await resp.json(content_type=None):
                                for n in entry.get("name_value", "").split("\n"):
                                    n = n.strip().lstrip("*.")
                                    if n.endswith(domain):
                                        subdomains.add(n)
            except Exception as exc:
                logger.warning("crt.sh fallback failed: %s", exc)

        subdomains.add(domain)

        # 1d. DNS resolution (parallel)
        _emit(1, "DNS resolution", 0.7)
        resolved: Dict[str, str] = {}
        if self._recon_engine:
            try:
                results.dns_records = await self._recon_engine.enumerate_dns(domain)
            except Exception as exc:
                logger.warning("DNS enumeration failed: %s", exc)

        import socket
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=20, thread_name_prefix="dns") as pool:
            async def _resolve(sub):
                try:
                    ip = await loop.run_in_executor(pool, socket.gethostbyname, sub)
                    return sub, ip
                except Exception:
                    return sub, None

            for coro in asyncio.as_completed([_resolve(s) for s in subdomains]):
                sub, ip = await coro
                if ip:
                    resolved[sub] = ip

        sub_list = sorted(subdomains)
        results.subdomains = sub_list
        results.resolved_ips = resolved

        if self.graph_engine:
            def _g(ge, dom, subs, ips):
                ge.add_target(dom)
                for s in subs:
                    ge.add_subdomain(s, dom)
                    if s in ips:
                        ge.add_ip(ips[s])
            self._graph_submit(_g, self.graph_engine, domain, sub_list, resolved)

        _emit(1, "Domain discovery done", 1.0,
              f"{len(sub_list)} subdomains, {len(resolved)} resolved")
        return {"subdomains": sub_list, "resolved_ips": resolved}

    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Passive Intelligence (URLScan + WHOIS + Shodan InternetDB)
    # ══════════════════════════════════════════════════════════════════════

    async def _phase2_passive_intel(self, ctx: dict, results: ReconResults) -> dict:
        """
        Passive OSINT that never touches the target. Implements the GROUP-1
        fan-out/fan-in pattern: URLScan.io, WHOIS, and Shodan InternetDB run
        CONCURRENTLY via ``asyncio.gather`` (independent — no shared state),
        then results are merged sequentially. Feeds new subdomains/IPs into
        ctx for Phase 3.
        """
        domain = ctx["domain"]
        subdomains = set(ctx.get("subdomains", []))
        resolved_ips = dict(ctx.get("resolved_ips", {}))
        loop = asyncio.get_event_loop()

        new_subs: set = set()
        new_ips: set = set()

        # ── Inner async tasks (each returns its own slice of state) ──
        async def _task_urlscan():
            try:
                urlscan_search = _import_urlscan()
                data = await loop.run_in_executor(
                    None, lambda: urlscan_search(domain)
                )
                return ("urlscan", data, None)
            except Exception as exc:
                return ("urlscan", {}, exc)

        async def _task_whois():
            try:
                whois_lookup = _import_whois()
                data = await loop.run_in_executor(
                    None, lambda: whois_lookup(domain)
                )
                return ("whois", data, None)
            except Exception as exc:
                return ("whois", {}, exc)

        async def _task_shodan(ip_list):
            if not ip_list:
                return ("shodan", [], None)
            try:
                enrich_ips_fn = _import_shodan()
                enrichments = await enrich_ips_fn(
                    ip_list[:100], concurrency=5, delay=0.3
                )
                return ("shodan", enrichments, None)
            except Exception as exc:
                return ("shodan", [], exc)

        async def _task_otx(ip_list):
            try:
                otx_enrich = _import_otx()
                data = await loop.run_in_executor(
                    None, lambda: otx_enrich(domain, ip_list[:5])
                )
                return ("otx", data, None)
            except Exception as exc:
                return ("otx", {}, exc)

        async def _task_virustotal(ip_list):
            try:
                vt_enrich = _import_virustotal()
                data = await loop.run_in_executor(
                    None, lambda: vt_enrich(domain, ip_list[:5])
                )
                return ("virustotal", data, None)
            except Exception as exc:
                return ("virustotal", {}, exc)

        async def _task_censys(ip_list):
            if not ip_list:
                return ("censys", [], None)
            try:
                censys_enrich_ips = _import_censys()
                data = await censys_enrich_ips(ip_list[:10])
                return ("censys", data, None)
            except Exception as exc:
                return ("censys", [], exc)

        async def _task_fofa(ip_list):
            try:
                fofa_enrich = _import_fofa()
                data = await loop.run_in_executor(
                    None, lambda: fofa_enrich(domain, ip_list[:5])
                )
                return ("fofa", data, None)
            except Exception as exc:
                return ("fofa", {}, exc)

        async def _task_netlas(ip_list):
            try:
                netlas_enrich = _import_netlas()
                data = await loop.run_in_executor(
                    None, lambda: netlas_enrich(domain, ip_list[:5])
                )
                return ("netlas", data, None)
            except Exception as exc:
                return ("netlas", {}, exc)

        async def _task_criminalip(ip_list):
            try:
                cip_enrich = _import_criminalip()
                data = await loop.run_in_executor(
                    None, lambda: cip_enrich(domain, ip_list[:5])
                )
                return ("criminalip", data, None)
            except Exception as exc:
                return ("criminalip", {}, exc)

        async def _task_zoomeye(ip_list):
            try:
                ze_enrich = _import_zoomeye()
                data = await loop.run_in_executor(
                    None, lambda: ze_enrich(domain, ip_list[:5])
                )
                return ("zoomeye", data, None)
            except Exception as exc:
                return ("zoomeye", {}, exc)

        # ── GROUP-1: launch all sources in parallel (fan-out) ────────
        initial_ips = list(set(resolved_ips.values()))
        enabled_osint = self.settings.get("osint_sources", [
            "urlscan", "whois", "shodan", "otx", "virustotal", "censys",
            "fofa", "netlas", "criminalip", "zoomeye",
        ])
        tasks = []
        if "urlscan" in enabled_osint:
            tasks.append(_task_urlscan())
        if "whois" in enabled_osint:
            tasks.append(_task_whois())
        if "shodan" in enabled_osint:
            tasks.append(_task_shodan(initial_ips))
        if "otx" in enabled_osint:
            tasks.append(_task_otx(initial_ips))
        if "virustotal" in enabled_osint:
            tasks.append(_task_virustotal(initial_ips))
        if "censys" in enabled_osint:
            tasks.append(_task_censys(initial_ips))
        if "fofa" in enabled_osint:
            tasks.append(_task_fofa(initial_ips))
        if "netlas" in enabled_osint:
            tasks.append(_task_netlas(initial_ips))
        if "criminalip" in enabled_osint:
            tasks.append(_task_criminalip(initial_ips))
        if "zoomeye" in enabled_osint:
            tasks.append(_task_zoomeye(initial_ips))

        _emit(2, f"Parallel passive intel ({len(tasks)} sources)", 0.1)
        t_group = time.time()
        group_results = await asyncio.gather(*tasks, return_exceptions=False)
        group_dur = time.time() - t_group
        results.parallel_groups.append({
            "phase": 2,
            "name": "passive_intel",
            "tasks": len(tasks),
            "duration_sec": round(group_dur, 2),
            "sources": enabled_osint,
        })
        _emit(2, "GROUP-1 fan-in", 0.7,
              f"{len(tasks)} sources in {group_dur:.1f}s")

        # ── Fan-in: merge results sequentially (no race conditions) ──
        for tag, payload, exc in group_results:
            if exc is not None:
                logger.warning("Passive task '%s' failed: %s", tag, exc)

            if tag == "urlscan":
                results.urlscan_data = payload
                for sub in payload.get("subdomains", []):
                    if sub not in subdomains:
                        new_subs.add(sub)
                        subdomains.add(sub)
                for ip in payload.get("ips", []):
                    if ip not in resolved_ips.values():
                        new_ips.add(ip)
                logger.info("URLScan: %d results, %d subs, %d IPs",
                            payload.get("results_count", 0),
                            len(payload.get("subdomains", [])),
                            len(payload.get("ips", [])))

            elif tag == "whois":
                results.whois_data = payload
                for ns in payload.get("nameservers", []):
                    ns_domain = ns.rstrip(".")
                    if ns_domain.endswith("." + domain):
                        new_subs.add(ns_domain)
                        subdomains.add(ns_domain)
                logger.info("WHOIS: registrar=%s ns=%d",
                            payload.get("registrar", "unknown"),
                            len(payload.get("nameservers", [])))

            elif tag == "shodan":
                for entry in payload:
                    ip = entry.get("ip", "")
                    if not ip:
                        continue
                    results.shodan_data[ip] = entry
                    for hostname in entry.get("hostnames", []):
                        hn = hostname.lower()
                        if hn.endswith("." + domain) or hn == domain:
                            if hn not in subdomains:
                                new_subs.add(hn)
                                subdomains.add(hn)
                    for vuln_id in entry.get("vulns", []):
                        results.passive_cves.append({
                            "id": vuln_id,
                            "source": "shodan_internetdb",
                            "ip": ip,
                        })
                enriched_count = sum(1 for e in payload if e.get("ports"))
                logger.info("Shodan InternetDB: %d/%d IPs with data",
                            enriched_count, len(payload))

            elif tag == "otx":
                results.otx_data = payload
                domain_report = payload.get("domain_report", {})
                pulse_count = domain_report.get("pulse_count", 0)
                # Harvest passive DNS hostnames as new subdomains
                for entry in domain_report.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower().strip()
                    if hostname.endswith("." + domain) and hostname not in subdomains:
                        new_subs.add(hostname)
                        subdomains.add(hostname)
                logger.info("OTX: %d pulses, %d passive DNS records",
                            pulse_count,
                            len(domain_report.get("passive_dns", [])))

            elif tag == "virustotal":
                results.virustotal_data = payload
                domain_report = payload.get("domain_report", {})
                stats = domain_report.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                logger.info("VirusTotal: reputation=%d, malicious_engines=%d",
                            domain_report.get("reputation", 0), malicious)

            elif tag == "censys":
                results.censys_data = payload
                for entry in payload:
                    ip = entry.get("ip", "")
                    ports = entry.get("ports", [])
                    if ip and ports:
                        pass  # Ports merged in Phase 3 via results.censys_data
                logger.info("Censys: %d hosts enriched", len(payload))

            elif tag == "fofa":
                results.fofa_data = payload
                domain_report = payload.get("domain_report", {})
                # Harvest new IPs from FOFA
                for ip in domain_report.get("ips", []):
                    if ip not in resolved_ips.values():
                        new_ips.add(ip)
                logger.info("FOFA: %d hosts, %d IPs",
                            len(domain_report.get("hosts", [])),
                            len(domain_report.get("ips", [])))

            elif tag == "netlas":
                results.netlas_data = payload
                logger.info("Netlas: %d hosts",
                            len(payload.get("domain_report", {}).get("hosts", [])))

            elif tag == "criminalip":
                results.criminalip_data = payload
                domain_report = payload.get("domain_report", {})
                # Harvest connected IPs
                for ip in domain_report.get("connected_ips", []):
                    if ip and ip not in resolved_ips.values():
                        new_ips.add(ip)
                logger.info("CriminalIP: %d connected IPs, %d technologies",
                            len(domain_report.get("connected_ips", [])),
                            len(domain_report.get("technologies", [])))

            elif tag == "zoomeye":
                results.zoomeye_data = payload
                domain_report = payload.get("domain_report", {})
                for ip in domain_report.get("ips", []):
                    if ip not in resolved_ips.values():
                        new_ips.add(ip)
                logger.info("ZoomEye: %d hosts, total=%d",
                            len(domain_report.get("hosts", [])),
                            domain_report.get("total", 0))

        # --- 2d. DNS-resolve newly discovered subdomains ---
        if new_subs:
            _emit(2, "Resolving new passive subdomains", 0.9)
            import socket
            with ThreadPoolExecutor(max_workers=10,
                                    thread_name_prefix="dns-passive") as pool:
                async def _resolve(sub):
                    try:
                        ip = await loop.run_in_executor(
                            pool, socket.gethostbyname, sub
                        )
                        return sub, ip
                    except Exception:
                        return sub, None

                for coro in asyncio.as_completed(
                    [_resolve(s) for s in new_subs]
                ):
                    sub, ip = await coro
                    if ip:
                        resolved_ips[sub] = ip

        # Update results
        all_subs = sorted(subdomains)
        results.subdomains = all_subs
        results.resolved_ips = resolved_ips
        results.passive_subdomains = sorted(new_subs)
        results.passive_ips = sorted(new_ips)

        if self.graph_engine:
            def _g(ge, dom, subs, ips):
                for s in subs:
                    ge.add_subdomain(s, dom)
                    if s in ips:
                        ge.add_ip(ips[s])
            self._graph_submit(
                _g, self.graph_engine, domain,
                sorted(new_subs), resolved_ips
            )

        _emit(2, "Passive intelligence done", 1.0,
              f"+{len(new_subs)} subdomains, +{len(new_ips)} IPs, "
              f"{len(results.passive_cves)} passive CVEs")

        return {
            "subdomains": all_subs,
            "resolved_ips": resolved_ips,
        }

    # ══════════════════════════════════════════════════════════════════════
    # Phase 3: Port Scanning
    # ══════════════════════════════════════════════════════════════════════

    async def _phase3_port_scan(self, ctx: dict, results: ReconResults) -> dict:
        """
        GROUP-3 fan-out: active port scan (ReconEngine), masscan (high-speed
        SYN), and passive Shodan enrichment run CONCURRENTLY since they're
        independent. Results merge by host with port deduplication. naabu
        fallback runs sequentially only if all three returned nothing.

        In IP-mode, masscan is the primary scanner. Censys port hints from
        Phase 2 are also merged in.
        """
        subdomains = ctx.get("subdomains", [ctx["domain"]])
        resolved_ips = ctx.get("resolved_ips", {})
        unique_ips = list(set(resolved_ips.values()))
        is_ip_mode = ctx.get("ip_mode", False)
        cidr_targets = ctx.get("cidr_targets", [])
        open_ports: Dict[str, List[int]] = {}

        # ── Seed from Censys port data harvested in Phase 2 ──────────
        for entry in results.censys_data:
            ip = entry.get("ip", "")
            ports = entry.get("ports", [])
            if ip and ports:
                open_ports[ip] = sorted(set(ports))

        # ── Inner async tasks (independent) ──────────────────────────
        async def _task_active_scan():
            if not (self._recon_engine and subdomains) or is_ip_mode:
                return ("active", {}, None)
            try:
                data = await self._recon_engine.scan_ports(set(subdomains[:50]))
                return ("active", data, None)
            except Exception as exc:
                return ("active", {}, exc)

        async def _task_masscan():
            try:
                masscan_scan, masscan_available, _, _ = _import_masscan()
                if not masscan_available():
                    return ("masscan", {}, None)

                # Pick targets: CIDR ranges in IP-mode, else resolved IPs
                if is_ip_mode and cidr_targets:
                    targets = cidr_targets
                else:
                    targets = unique_ips[:100]

                if not targets:
                    return ("masscan", {}, None)

                rate = self.settings.get("masscan_rate", 1000)
                ports = self.settings.get("masscan_ports", None)

                kwargs = {"targets": targets, "rate": rate, "timeout": 600}
                if ports:
                    kwargs["ports"] = ports
                data = await masscan_scan(**kwargs)
                return ("masscan", data, None)
            except Exception as exc:
                return ("masscan", {}, exc)

        async def _task_shodan_enrich():
            if not unique_ips:
                return ("shodan", [], None)
            try:
                enrich_ips = _import_shodan()
                data = await enrich_ips(unique_ips[:100], concurrency=5)
                return ("shodan", data, None)
            except Exception as exc:
                return ("shodan", [], exc)

        # ── GROUP-3: launch all three in parallel (fan-out) ──────────
        _emit(3, "Parallel port scan (ReconEngine + masscan + Shodan)", 0.2)
        t_group = time.time()
        group_results = await asyncio.gather(
            _task_active_scan(),
            _task_masscan(),
            _task_shodan_enrich(),
            return_exceptions=True,
        )
        group_dur = time.time() - t_group
        results.parallel_groups.append({
            "phase": 3,
            "name": "port_scan",
            "tasks": 3,
            "duration_sec": round(group_dur, 2),
            "sources": ["recon_engine", "masscan", "shodan_internetdb"],
        })
        _emit(3, "GROUP-3 fan-in", 0.6,
              f"3 sources in {group_dur:.1f}s")

        # ── Fan-in: merge with port deduplication ────────────────────
        for tag, payload, exc in group_results:
            if exc is not None:
                logger.warning("Port scan task '%s' failed: %s", tag, exc)

            if tag == "active":
                for host, ports in payload.items():
                    merged = set(open_ports.get(host, []))
                    merged.update(ports)
                    open_ports[host] = sorted(merged)
            elif tag == "masscan":
                for host, ports in payload.items():
                    merged = set(open_ports.get(host, []))
                    merged.update(ports)
                    open_ports[host] = sorted(merged)
                if payload:
                    logger.info("masscan: %d hosts, %d total open ports",
                                len(payload),
                                sum(len(p) for p in payload.values()))
            elif tag == "shodan":
                for entry in payload:
                    ip = entry.get("ip", "")
                    if not ip:
                        continue
                    results.shodan_data[ip] = entry
                    passive = entry.get("ports", [])
                    if passive:
                        merged = set(open_ports.get(ip, []))
                        merged.update(passive)
                        open_ports[ip] = sorted(merged)

        # ── Sequential naabu fallback if active scan returned nothing ─
        if not open_ports and _tool_available("naabu"):
            _emit(3, "naabu direct fallback", 0.8)
            out = await _run_tool(
                ["naabu", "-host", ",".join(subdomains[:50]), "-silent", "-json"],
                timeout=180,
            )
            if out:
                for line in out.splitlines():
                    try:
                        j = json.loads(line)
                        host = j.get("host", j.get("ip", ""))
                        port = j.get("port")
                        if host and port:
                            open_ports.setdefault(host, []).append(int(port))
                    except (json.JSONDecodeError, ValueError):
                        pass
                # Deduplicate naabu results
                for host in open_ports:
                    open_ports[host] = sorted(set(open_ports[host]))

        results.open_ports = open_ports

        if self.graph_engine:
            def _g(ge, pd):
                for host, ports in pd.items():
                    for p in ports:
                        ge.add_port(host, p)
            self._graph_submit(_g, self.graph_engine, open_ports)

        total = sum(len(v) for v in open_ports.values())
        _emit(3, "Port scan done", 1.0, f"{len(open_ports)} hosts, {total} open ports")
        return {"open_ports": open_ports}

    # ══════════════════════════════════════════════════════════════════════
    # Phase 4: HTTP Probing
    # ══════════════════════════════════════════════════════════════════════

    async def _phase4_http_probe(self, ctx: dict, results: ReconResults) -> dict:
        subdomains = ctx.get("subdomains", [ctx["domain"]])
        open_ports = ctx.get("open_ports", {})
        alive: List[str] = []
        tech_map: Dict[str, List[Dict]] = {}

        # Build probe targets
        HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 4200,
                      5000, 9000, 9090}
        probe_targets: Set[str] = set(subdomains)
        for host in subdomains:
            for port in open_ports.get(host, []):
                if port in HTTP_PORTS:
                    probe_targets.add(f"{host}:{port}")

        # Always probe the EXACT target the operator pointed us at, including a
        # non-standard explicit port (e.g. http://host:4000). Recon's host
        # extraction drops the port and the HTTP_PORTS allowlist can omit it, so
        # without this seed a target on a non-standard port is never probed and
        # the whole hunt sees "0 alive".
        orig_url = ctx.get("url", "")
        if orig_url:
            _pu = urlparse(orig_url if "://" in orig_url else f"http://{orig_url}")
            if _pu.hostname and _pu.port:
                probe_targets.add(f"{_pu.hostname}:{_pu.port}")

        # 3a. httpx
        if _tool_available("httpx"):
            _emit(4, "httpx probing", 0.2)
            tf = _write_targets_file(probe_targets)
            try:
                out = await _run_tool(
                    ["httpx", "-l", tf, "-silent", "-json", "-status-code",
                     "-title", "-tech-detect", "-follow-redirects"],
                    timeout=180,
                )
                if out:
                    for line in out.splitlines():
                        try:
                            j = json.loads(line)
                            url = j.get("url", "")
                            if url:
                                alive.append(url)
                                results.http_responses.append({
                                    "url": url,
                                    "status": j.get("status_code"),
                                    "title": j.get("title", ""),
                                    "tech": j.get("tech", []),
                                    "content_length": j.get("content_length"),
                                    "webserver": j.get("webserver", ""),
                                })
                                if j.get("tech"):
                                    tech_map[url] = [{"name": t} for t in j["tech"]]
                        except json.JSONDecodeError:
                            pass
            finally:
                Path(tf).unlink(missing_ok=True)
        else:
            # Fallback: ReconEngine probe
            _emit(4, "Python HTTP probing fallback", 0.2)
            if self._recon_engine:
                try:
                    live_set = await self._recon_engine.probe_live_hosts(set(subdomains))
                    alive = [f"https://{h}" for h in live_set]
                except Exception as exc:
                    logger.warning("Live host probing failed: %s", exc)

        # 3b. Wappalyzer deep fingerprinting
        _emit(4, "Wappalyzer fingerprinting", 0.6)
        try:
            wap_fp = _import_wappalyzer()
            import aiohttp
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=False),
            ) as sess:
                for url in alive[:30]:
                    try:
                        async with sess.get(url) as resp:
                            body = await resp.text(errors="replace")
                            headers = dict(resp.headers)
                            techs = wap_fp(url, headers, body)
                            if techs:
                                existing = tech_map.get(url, [])
                                seen = {t.get("name") for t in existing}
                                for t in techs:
                                    if t.get("name") not in seen:
                                        existing.append(t)
                                tech_map[url] = existing
                    except Exception:
                        pass
        except Exception as exc:
            logger.warning("Wappalyzer fingerprinting failed: %s", exc)

        results.live_hosts = alive
        results.technologies = tech_map

        # ── WPScan: conditional on WordPress detection ───────────────
        try:
            wpscan_scan, is_wordpress = _import_wpscan()
            if is_wordpress(tech_map) and alive:
                _emit(4, "WPScan (WordPress detected)", 0.85)
                wp_target = alive[0]
                for url in alive:
                    if any(
                        t.get("name", "").lower() in ("wordpress", "wp")
                        for t in tech_map.get(url, [])
                        if isinstance(t, dict)
                    ):
                        wp_target = url
                        break
                try:
                    results.wpscan_data = await wpscan_scan(wp_target)
                    wp_vulns = results.wpscan_data.get("vulnerabilities", [])
                    logger.info("WPScan: %d plugins, %d vulns",
                                len(results.wpscan_data.get("plugins", [])),
                                len(wp_vulns))
                except Exception as exc:
                    logger.warning("WPScan failed: %s", exc)
        except Exception:
            pass  # wpscan module not available

        if self.graph_engine:
            def _g(ge, tmap, alive_list):
                for url in alive_list:
                    ge.add_base_url(url)
                for url, techs in tmap.items():
                    for t in techs:
                        ge.add_technology(url, t.get("name", "unknown"),
                                          version=t.get("version", ""))
            self._graph_submit(_g, self.graph_engine, tech_map, alive)

        _emit(4, "HTTP probing done", 1.0,
              f"{len(alive)} alive, {len(tech_map)} fingerprinted")
        return {"alive_hosts": alive}

    # ══════════════════════════════════════════════════════════════════════
    # Phase 5: Resource Enumeration
    # ══════════════════════════════════════════════════════════════════════

    async def _phase5_resource_enum(self, ctx: dict, results: ReconResults) -> dict:
        """
        GROUP-5 fan-out: katana crawling, gau/wayback URL retrieval, and
        Surface Mapping all run CONCURRENTLY (independent — no shared
        state). JS secret scanning and Arjun param discovery run
        sequentially after the parallel group since they depend on its
        outputs (js_files set, all_endpoints list).

        Skip-on-empty guard: if Phase 4 found no live hosts AND skipping
        is enabled, this phase exits early to avoid wasted active scans.
        """
        alive_hosts = ctx.get("alive_hosts", [])
        domain = ctx["domain"]

        # ── Skip-on-empty guard (conditional skip pattern) ─
        if not alive_hosts:
            if self.settings.get("skip_active_on_empty", False):
                _emit(5, "SKIPPED: no live hosts from Phase 4", 1.0)
                logger.info("Phase 5 skipped — no alive hosts and "
                            "skip_active_on_empty=True")
                return {"endpoints": []}
            alive_hosts = [f"https://{domain}"]
            logger.info("Phase 5: no alive hosts, falling back to %s",
                        alive_hosts[0])

        crawled: Set[str] = set()
        archived: Set[str] = set()
        js_files: Set[str] = set()
        api_endpoints: List[Dict] = []
        params: Dict[str, List[str]] = {}

        # ── Inner async tasks (each returns its own slice of state) ──
        async def _task_katana():
            local_crawled: Set[str] = set()
            local_js: Set[str] = set()
            if _tool_available("katana"):
                tf = _write_targets_file(alive_hosts[:10])
                try:
                    out = await _run_tool(
                        ["katana", "-list", tf, "-silent",
                         "-depth", "3", "-js-crawl"],
                        timeout=300,
                    )
                    if out:
                        for line in out.splitlines():
                            url = line.strip()
                            if url and url.startswith("http"):
                                local_crawled.add(url)
                                if url.endswith(".js"):
                                    local_js.add(url)
                finally:
                    Path(tf).unlink(missing_ok=True)
            else:
                # Fallback: VIPER WebCrawler
                try:
                    WebCrawler = _import_web_crawler()
                    crawler = WebCrawler()
                    for url in alive_hosts[:5]:
                        try:
                            cr = await crawler.crawl(url, max_depth=3, max_pages=100)
                            local_crawled.update(getattr(cr, "visited_urls", []))
                            local_js.update(getattr(cr, "js_files", []))
                        except Exception as exc:
                            logger.warning("Crawl failed for %s: %s", url, exc)
                except Exception as exc:
                    logger.warning("WebCrawler import failed: %s", exc)
            return ("crawl", local_crawled, local_js, None)

        async def _task_archive():
            local_archived: Set[str] = set()
            try:
                if _tool_available("gau"):
                    out = await _run_tool(
                        ["gau", "--subs", domain, "--threads", "5"], timeout=120,
                    )
                    if out:
                        local_archived.update(
                            l.strip() for l in out.splitlines() if l.strip()
                        )
                else:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as sess:
                        wb = (f"https://web.archive.org/cdx/search/cdx"
                              f"?url=*.{domain}/*&output=text&fl=original"
                              f"&collapse=urlkey&limit=2000")
                        async with sess.get(wb) as resp:
                            if resp.status == 200:
                                local_archived.update(
                                    l.strip() for l in (await resp.text()).splitlines()
                                    if l.strip()
                                )
            except Exception as exc:
                return ("archive", local_archived, None, exc)
            return ("archive", local_archived, None, None)

        async def _task_surface_map():
            local_endpoints: List[Dict] = []
            local_params: Dict[str, List[str]] = {}
            try:
                SurfaceMapper = _import_surface_mapper()
                mapper = SurfaceMapper()
                # Only map primary host — Phase 3 of viper_core handles per-port
                for url in alive_hosts[:1]:
                    try:
                        surface = await mapper.map_surface(
                            url, crawl_depth=2, max_pages=50
                        )
                        local_endpoints.extend(
                            getattr(surface, "api_endpoints", [])
                        )
                        for u, p_set in getattr(
                            surface, "url_parameters", {}
                        ).items():
                            local_params[u] = (
                                list(p_set) if isinstance(p_set, set) else p_set
                            )
                    except Exception as exc:
                        logger.warning("Surface map failed for %s: %s", url, exc)
            except Exception as exc:
                return ("surface", local_endpoints, local_params, exc)
            return ("surface", local_endpoints, local_params, None)

        # ── GROUP-5: launch crawl + archive + surface map in parallel ─
        _emit(5, "Parallel resource enum (katana + gau + SurfaceMapper)", 0.1)
        t_group = time.time()
        group_results = await asyncio.gather(
            _task_katana(),
            _task_archive(),
            _task_surface_map(),
            return_exceptions=False,
        )
        _emit(5, "GROUP-5 fan-in", 0.6,
              f"3 sources in {time.time() - t_group:.1f}s")

        # ── Fan-in: merge results ────────────────────────────────────
        for result in group_results:
            tag = result[0]
            if tag == "crawl":
                _, local_crawled, local_js, exc = result
                if exc:
                    logger.warning("Crawl task failed: %s", exc)
                crawled.update(local_crawled)
                js_files.update(local_js)
            elif tag == "archive":
                _, local_archived, _, exc = result
                if exc:
                    logger.warning("Archive task failed: %s", exc)
                archived.update(local_archived)
            elif tag == "surface":
                _, local_endpoints, local_params, exc = result
                if exc:
                    logger.warning("Surface map task failed: %s", exc)
                api_endpoints.extend(local_endpoints)
                params.update(local_params)

        results.crawled_urls = sorted(crawled)
        results.archived_urls = sorted(archived)
        results.js_files = sorted(js_files)
        results.api_endpoints = api_endpoints
        results.parameters = params

        # 4c2. JS Secret Scanner — scan discovered JS files for leaked secrets
        if js_files:
            try:
                from recon.js_scanner import JSSecretScanner
                _emit(5, "JS secret scanning", 0.75)
                js_scanner = JSSecretScanner()
                base_url = alive_hosts[0] if alive_hosts else f"https://{ctx['domain']}"
                js_secrets = await js_scanner.scan_target(
                    base_url, list(js_files)[:100],
                )
                if js_secrets:
                    for secret in js_secrets:
                        results.vulnerabilities.append({
                            "type": "js_secret_leak",
                            "subtype": secret.type,
                            "url": secret.js_url,
                            "confidence": secret.confidence,
                            "entropy": secret.entropy,
                            "line": secret.line_number,
                            "context": secret.context,
                            "value_preview": secret.value,
                            "severity": "high" if secret.confidence == "high" else "medium",
                        })
                    logger.info("JS scanner found %d secrets in %d files",
                                len(js_secrets), len(js_files))
            except ImportError:
                logger.debug("JSSecretScanner not available — skipping")
            except Exception as exc:
                logger.warning("JS secret scanning failed: %s", exc)

        all_endpoints = list(crawled | archived)

        # 4d. Arjun parameter discovery on param-less endpoints
        arjun_param_count = 0
        try:
            from recon.arjun_discovery import (
                arjun_available as _arjun_ok,
                urls_needing_param_discovery,
                run_arjun_discovery as _run_arjun,
            )
            if _arjun_ok():
                # Build set of URLs that already have known params
                known_param_keys: Set[str] = set()
                for url_key, param_list in params.items():
                    for p in param_list:
                        known_param_keys.add(f"{p}:{url_key}")

                arjun_targets = urls_needing_param_discovery(
                    all_endpoints, known_param_keys,
                    max_endpoints=self.settings.get("arjun_max_endpoints", 20),
                )
                if arjun_targets:
                    _emit(5, "Arjun parameter discovery", 0.85)
                    arjun_disc = await _run_arjun(
                        arjun_targets,
                        rate_limit=self.settings.get("arjun_rate_limit", 0),
                        proxy=self.settings.get("arjun_proxy"),
                        max_endpoints=self.settings.get("arjun_max_endpoints", 20),
                    )
                    # Merge discovered params into results.parameters
                    for r in arjun_disc.results:
                        param_names = [p["name"] for p in r.params]
                        if param_names:
                            existing = params.get(r.url, [])
                            existing_set = set(existing)
                            new_params = [p for p in param_names if p not in existing_set]
                            if new_params:
                                params[r.url] = existing + new_params
                                arjun_param_count += len(new_params)
                    results.parameters = params
                    logger.info("Arjun discovered %d new params across %d endpoints",
                                arjun_param_count, len(arjun_disc.results))
            else:
                logger.debug("Arjun binary not found — skipping pipeline param discovery")
        except ImportError:
            logger.debug("Arjun module not available — skipping pipeline param discovery")
        except Exception as exc:
            logger.warning("Arjun parameter discovery failed: %s", exc)

        if self.graph_engine:
            def _g(ge, urls, eps, alive_list):
                for url in alive_list:
                    ge.add_base_url(url)
                    for ep in eps:
                        if isinstance(ep, dict):
                            ge.add_endpoint(ep.get("path", "/"), url)
            self._graph_submit(_g, self.graph_engine, list(crawled)[:200],
                               api_endpoints, alive_hosts)

        _emit(5, "Resource enum done", 1.0,
              f"{len(crawled)} crawled, {len(archived)} archived, "
              f"{len(js_files)} JS files, {arjun_param_count} arjun params")
        return {"endpoints": all_endpoints}

    # ══════════════════════════════════════════════════════════════════════
    # Phase 6: Vulnerability Scanning
    # ══════════════════════════════════════════════════════════════════════

    async def _phase6_vuln_scan(self, ctx: dict, results: ReconResults) -> dict:
        """
        Vuln scan with skip-on-empty guard. If Phase 4 found no live hosts
        AND skip_active_on_empty is enabled, this phase exits early to
        avoid running nuclei against synthetic targets.
        """
        alive_hosts = ctx.get("alive_hosts", [])
        domain = ctx["domain"]

        # ── Skip-on-empty guard (conditional skip pattern) ─
        if not alive_hosts:
            if self.settings.get("skip_active_on_empty", False):
                _emit(6, "SKIPPED: no live hosts from Phase 4", 1.0)
                logger.info("Phase 6 skipped — no alive hosts and "
                            "skip_active_on_empty=True")
                return {"findings": []}
            alive_hosts = [f"https://{domain}"]
            logger.info("Phase 6: no alive hosts, falling back to %s",
                        alive_hosts[0])

        findings: List[Dict] = []

        # 5a. Nuclei via VIPER wrapper
        _emit(6, "Nuclei vulnerability scan", 0.2)
        try:
            NucleiScanner = _import_nuclei()
            scanner = NucleiScanner(verbose=True)
            for url in alive_hosts[:1]:
                try:
                    sr = await scanner.scan(
                        url,
                        severity=self.settings.get(
                            "nuclei_severity", ["low", "medium", "high", "critical"]),
                        rate_limit=self.settings.get("nuclei_rate_limit", 100),
                    )
                    for f in sr.findings:
                        findings.append(
                            f.to_dict() if hasattr(f, "to_dict") else f.__dict__
                        )
                except Exception as exc:
                    logger.warning("Nuclei scan failed for %s: %s", url, exc)
        except Exception as exc:
            logger.warning("NucleiScanner import/init failed: %s", exc)

        # 5b. Direct nuclei CLI fallback
        if not findings and _tool_available("nuclei"):
            _emit(6, "nuclei CLI fallback", 0.5)
            tf = _write_targets_file(alive_hosts[:20])
            try:
                out = await _run_tool(
                    ["nuclei", "-l", tf, "-jsonl", "-silent",
                     "-severity", "low,medium,high,critical",
                     "-rate-limit", "100"],
                    timeout=600,
                )
                if out:
                    for line in out.splitlines():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            finally:
                Path(tf).unlink(missing_ok=True)

        # 5c. Shodan CVE cross-reference
        for ip, data in results.shodan_data.items():
            for cve in data.get("vulns", []):
                findings.append({
                    "source": "shodan_internetdb",
                    "host": ip,
                    "cve_id": cve,
                    "severity": "unknown",
                    "name": f"Shodan CVE: {cve}",
                })

        results.vulnerabilities = findings
        results.nuclei_findings = [
            f for f in findings if f.get("source") != "shodan_internetdb"
        ]

        if self.graph_engine:
            def _g(ge, vulns):
                for v in vulns:
                    vid = v.get("template-id",
                                v.get("cve_id", v.get("name", "unknown")))
                    sev = v.get("severity",
                                v.get("info", {}).get("severity", "unknown"))
                    ge.add_vulnerability(vid, v.get("name", vid), sev)
                    cve = (v.get("cve_id")
                           or v.get("info", {}).get("classification", {}).get("cve-id"))
                    if cve:
                        for c in (cve if isinstance(cve, list) else [cve]):
                            ge.add_cve(c)
            self._graph_submit(_g, self.graph_engine, findings)

        _emit(6, "Vuln scan done", 1.0, f"{len(findings)} findings")
        return {"findings": findings}

    # ══════════════════════════════════════════════════════════════════════
    # Phase 7: MITRE Enrichment
    # ══════════════════════════════════════════════════════════════════════

    async def _phase7_mitre_enrich(self, ctx: dict, results: ReconResults) -> dict:
        findings = ctx.get("findings", [])
        if not findings:
            _emit(7, "No findings to enrich", 1.0)
            return {}

        _emit(7, "MITRE CVE->CWE->CAPEC mapping", 0.3)
        enriched: List[Dict] = []

        try:
            _MitreMapper, enrich_finding_mitre = _import_mitre()
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="mitre") as pool:
                async def _enrich(finding):
                    try:
                        return await loop.run_in_executor(
                            pool, enrich_finding_mitre, finding,
                        )
                    except Exception as exc:
                        logger.warning("MITRE enrich failed for %s: %s",
                                       finding.get("name", "?"), exc)
                        return finding

                enriched = list(await asyncio.gather(
                    *[_enrich(f) for f in findings]
                ))
        except Exception as exc:
            logger.warning("MitreMapper import failed: %s — returning unenriched", exc)
            enriched = findings

        results.mitre_enriched = enriched

        if self.graph_engine:
            def _g(ge, elist):
                for f in elist:
                    cwe = f.get("cwe_id") or f.get("cwe")
                    cve = f.get("cve_id") or f.get("cve")
                    capec = f.get("capec_id") or f.get("capec")
                    if cve and cwe:
                        ge.add_mitre_data(cve, cwe)
                    if capec and cwe:
                        ge.add_capec(capec, cwe)
            self._graph_submit(_g, self.graph_engine, enriched)

        _emit(7, "MITRE enrichment done", 1.0, f"{len(enriched)} enriched")
        return {"enriched": enriched}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="VIPER 4.0 Recon Pipeline")
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--phases", nargs="*", default=None,
                        help="Phases to run (default: all 6)")
    parser.add_argument("--graph", action="store_true",
                        help="Enable knowledge graph storage")
    parser.add_argument("-v", "--verbose", action="store_true", default=True)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    graph_engine = None
    if args.graph:
        try:
            GraphEngine = _import_graph()
            graph_engine = GraphEngine()
        except Exception as exc:
            logger.warning("Graph engine unavailable: %s", exc)

    pipeline = ReconPipeline(graph_engine=graph_engine)
    results = await pipeline.run(args.target, phases=args.phases)

    print(f"\n{'='*60}")
    print(f"Target:          {results.target}")
    print(f"Phases run:      {results.phases_run}")
    print(f"Subdomains:      {len(results.subdomains)}")
    print(f"Open ports:      {sum(len(v) for v in results.open_ports.values())}")
    print(f"Alive hosts:     {len(results.live_hosts)}")
    print(f"Crawled URLs:    {len(results.crawled_urls)}")
    print(f"Archived URLs:   {len(results.archived_urls)}")
    print(f"JS files:        {len(results.js_files)}")
    print(f"Vulnerabilities: {len(results.vulnerabilities)}")
    print(f"MITRE enriched:  {len(results.mitre_enriched)}")
    print(f"Errors:          {len(results.errors)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
