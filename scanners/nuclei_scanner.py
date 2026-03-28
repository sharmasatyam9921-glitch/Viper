#!/usr/bin/env python3
"""
VIPER Nuclei Scanner Integration

Wraps Nuclei vulnerability scanner and integrates with VIPER knowledge base.

Features:
- Run nuclei scans with customizable templates
- Parse JSON output
- Feed findings to VIPER knowledge base
- Severity-based filtering
- Template management
"""

import asyncio
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("viper.nuclei")

HACKAGENT_DIR = Path(__file__).parent.parent
NUCLEI_OUTPUT_DIR = HACKAGENT_DIR / "data" / "nuclei"
NUCLEI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Default custom template directory
CUSTOM_TEMPLATES_DIR = HACKAGENT_DIR / "data" / "nuclei" / "custom"

# Knowledge file for integration
KNOWLEDGE_FILE = HACKAGENT_DIR / "core" / "viper_knowledge.json"


@dataclass
class NucleiFinding:
    """A single nuclei finding"""
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    matcher_name: str = ""
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def is_critical(self) -> bool:
        return self.severity.lower() in ['critical', 'high']
    
    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "matcher_name": self.matcher_name,
            "extracted_results": self.extracted_results,
            "curl_command": self.curl_command,
            "timestamp": self.timestamp
        }


@dataclass
class NucleiScanResult:
    """Results from a nuclei scan"""
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    findings: List[NucleiFinding] = field(default_factory=list)
    templates_used: int = 0
    requests_made: int = 0
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
            "templates_used": self.templates_used,
            "requests_made": self.requests_made,
            "scan_duration": self.scan_duration,
            "errors": self.errors,
            "summary": {
                "critical": len([f for f in self.findings if f.severity.lower() == 'critical']),
                "high": len([f for f in self.findings if f.severity.lower() == 'high']),
                "medium": len([f for f in self.findings if f.severity.lower() == 'medium']),
                "low": len([f for f in self.findings if f.severity.lower() == 'low']),
                "info": len([f for f in self.findings if f.severity.lower() == 'info']),
            }
        }
    
    def save(self, filename: str = None) -> Path:
        if not filename:
            safe_target = self.target.replace('://', '_').replace('/', '_').replace(':', '_')
            filename = f"nuclei_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = NUCLEI_OUTPUT_DIR / filename
        filepath.write_text(json.dumps(self.to_dict(), indent=2))
        return filepath


class NucleiScanner:
    """
    Wraps Nuclei vulnerability scanner.
    
    Provides async interface for running scans and parsing results.
    """
    
    def __init__(self, verbose: bool = True, tool_manager=None,
                 custom_template_dirs: Optional[List[str]] = None):
        self.verbose = verbose
        self.tool_manager = tool_manager
        if tool_manager and tool_manager.check_tool("nuclei"):
            self.nuclei_path = tool_manager.get_path("nuclei")
            self.log(f"Using nuclei from ToolManager: {self.nuclei_path}")
        else:
            self.nuclei_path = self._find_nuclei()
        self.templates_path = self._find_templates()

        # Custom template discovery (G9)
        self._custom_template_dirs: List[Path] = [CUSTOM_TEMPLATES_DIR]
        if custom_template_dirs:
            self._custom_template_dirs.extend(Path(d) for d in custom_template_dirs)
        self._template_catalog: List[Dict] = []
        self._discover_and_log_templates()
    
    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [NUCLEI] [{level}] {msg}")
    
    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary"""
        try:
            result = subprocess.run(
                ['where' if sys.platform == 'win32' else 'which', 'nuclei'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                path = result.stdout.strip().split('\n')[0]
                self.log(f"Found nuclei: {path}")
                return path
        except:
            pass
        
        # Check common paths
        common_paths = [
            Path.home() / "go" / "bin" / "nuclei.exe",
            Path.home() / "go" / "bin" / "nuclei",
            Path("/usr/local/bin/nuclei"),
            Path("/usr/bin/nuclei"),
        ]
        
        for p in common_paths:
            if p.exists():
                self.log(f"Found nuclei: {p}")
                return str(p)
        
        self.log("Nuclei not found - install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "WARN")
        return None
    
    def _find_templates(self) -> Optional[Path]:
        """Find nuclei templates directory"""
        common_paths = [
            Path.home() / "nuclei-templates",
            Path.home() / ".local" / "nuclei-templates",
            Path("/opt/nuclei-templates"),
        ]
        
        for p in common_paths:
            if p.exists():
                return p

        return None

    # ------------------------------------------------------------------
    # G9: Custom template auto-discovery
    # ------------------------------------------------------------------

    def discover_custom_templates(self, template_dir: Optional[str] = None) -> List[Dict]:
        """
        Scan custom template directories for YAML nuclei templates.

        Parses each .yaml/.yml file for: id, name, severity, author, description, tags.

        Args:
            template_dir: Optional additional directory to scan. If None, uses
                          the configured custom_template_dirs list.

        Returns:
            List of template metadata dicts with keys:
                id, name, severity, author, description, tags, path
        """
        dirs_to_scan = list(self._custom_template_dirs)
        if template_dir:
            dirs_to_scan.append(Path(template_dir))

        templates: List[Dict] = []
        seen_ids: Set[str] = set()

        for tdir in dirs_to_scan:
            if not tdir.is_dir():
                continue

            for fpath in sorted(tdir.rglob("*.yaml")):
                meta = self._parse_template_yaml(fpath)
                if meta and meta["id"] not in seen_ids:
                    seen_ids.add(meta["id"])
                    templates.append(meta)

            # Also match .yml extension
            for fpath in sorted(tdir.rglob("*.yml")):
                meta = self._parse_template_yaml(fpath)
                if meta and meta["id"] not in seen_ids:
                    seen_ids.add(meta["id"])
                    templates.append(meta)

        return templates

    def _parse_template_yaml(self, fpath: Path) -> Optional[Dict]:
        """Parse a single nuclei template YAML file for metadata."""
        if yaml is None:
            # Fallback: basic regex parsing if PyYAML not available
            return self._parse_template_fallback(fpath)

        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                data = next(yaml.safe_load_all(f), None)

            if not isinstance(data, dict):
                return None

            info = data.get("info", {})
            if not isinstance(info, dict):
                return None

            template_id = data.get("id", fpath.stem)
            if not template_id:
                return None

            return {
                "id": str(template_id),
                "name": str(info.get("name", "")),
                "severity": str(info.get("severity", "unknown")).lower(),
                "author": str(info.get("author", "")),
                "description": str(info.get("description", ""))[:200],
                "tags": str(info.get("tags", "")),
                "path": str(fpath),
            }
        except Exception:
            return None

    def _parse_template_fallback(self, fpath: Path) -> Optional[Dict]:
        """Regex-based fallback parser when PyYAML is unavailable."""
        import re
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")[:4096]
        except Exception:
            return None

        def _extract(key: str) -> str:
            m = re.search(rf"^\s*{key}\s*:\s*(.+)$", content, re.MULTILINE)
            return m.group(1).strip().strip("\"'") if m else ""

        template_id = _extract("id") or fpath.stem
        name = _extract("name")
        severity = _extract("severity") or "unknown"
        author = _extract("author")
        description = _extract("description")[:200]
        tags = _extract("tags")

        if not template_id:
            return None

        return {
            "id": template_id,
            "name": name,
            "severity": severity.lower(),
            "author": author,
            "description": description,
            "tags": tags,
            "path": str(fpath),
        }

    def _discover_and_log_templates(self):
        """Discover custom templates at startup and log them."""
        self._template_catalog = self.discover_custom_templates()
        if self._template_catalog:
            self.log(f"Discovered {len(self._template_catalog)} custom templates:")
            for t in self._template_catalog:
                self.log(f"  [{t['severity']}] {t['id']}: {t['name']}")
        else:
            self.log("No custom templates found in configured directories")

    @property
    def template_catalog(self) -> List[Dict]:
        """Property exposing the discovered custom template catalog."""
        return self._template_catalog

    def get_template_catalog(self) -> str:
        """
        Return a formatted string listing all custom templates.

        Suitable for injection into LLM system prompts so the agent knows
        which custom templates are available.

        Returns:
            Formatted multi-line string, or empty string if no templates.
        """
        if not self._template_catalog:
            return ""

        lines = ["Custom Nuclei Templates Available:"]
        lines.append(f"  Total: {len(self._template_catalog)}")
        lines.append("")

        # Group by severity
        by_sev: Dict[str, List[Dict]] = {}
        for t in self._template_catalog:
            sev = t["severity"]
            by_sev.setdefault(sev, []).append(t)

        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        for sev in sev_order:
            templates = by_sev.get(sev, [])
            if not templates:
                continue
            lines.append(f"  [{sev.upper()}] ({len(templates)}):")
            for t in templates:
                lines.append(f"    - {t['id']}: {t['name']}")
                if t["description"]:
                    lines.append(f"      {t['description']}")
                if t["tags"]:
                    lines.append(f"      tags: {t['tags']}")
                lines.append(f"      path: {t['path']}")
            lines.append("")

        return "\n".join(lines)

    async def check_and_update_templates(self) -> bool:
        """Update nuclei templates"""
        if not self.nuclei_path:
            return False
        
        self.log("Updating nuclei templates...")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, '-update-templates',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            
            if proc.returncode == 0:
                self.log("Templates updated successfully")
                return True
            else:
                self.log(f"Template update failed: {stderr.decode()}", "ERROR")
                return False
        except asyncio.TimeoutError:
            self.log("Template update timed out", "ERROR")
            return False
        except Exception as e:
            self.log(f"Template update error: {e}", "ERROR")
            return False
    
    async def scan(self, target: str,
                   severity: List[str] = None,
                   tags: List[str] = None,
                   templates: List[str] = None,
                   exclude_tags: List[str] = None,
                   rate_limit: int = 150,
                   timeout: int = 300) -> NucleiScanResult:
        """
        Run nuclei scan against target.
        
        Args:
            target: URL or host to scan
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (cve, rce, sqli, xss, etc.)
            templates: Specific templates to use
            exclude_tags: Tags to exclude
            rate_limit: Requests per second
            timeout: Scan timeout in seconds
        """
        result = NucleiScanResult(target=target)
        
        if not self.nuclei_path:
            result.errors.append("Nuclei not installed")
            return result
        
        # Build command
        cmd = [
            self.nuclei_path,
            '-u', target,
            '-json',
            '-silent',
            '-rate-limit', str(rate_limit),
            '-stats',
        ]
        
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        if templates:
            for t in templates:
                cmd.extend(['-t', t])
        
        if exclude_tags:
            cmd.extend(['-exclude-tags', ','.join(exclude_tags)])
        
        self.log(f"Starting scan: {target}")
        self.log(f"Command: {' '.join(cmd)}")
        
        start_time = datetime.now()
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=timeout
            )
            
            result.scan_duration = (datetime.now() - start_time).total_seconds()
            
            # Parse JSON output (one JSON object per line)
            for line in stdout.decode().split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    finding_data = json.loads(line)
                    finding = NucleiFinding(
                        template_id=finding_data.get('template-id', ''),
                        template_name=finding_data.get('info', {}).get('name', ''),
                        severity=finding_data.get('info', {}).get('severity', 'unknown'),
                        host=finding_data.get('host', ''),
                        matched_at=finding_data.get('matched-at', finding_data.get('matched', '')),
                        matcher_name=finding_data.get('matcher-name', ''),
                        extracted_results=finding_data.get('extracted-results', []),
                        curl_command=finding_data.get('curl-command', '')
                    )
                    result.findings.append(finding)
                    
                    level = "VULN" if finding.is_critical else "FOUND"
                    self.log(f"  [{finding.severity.upper()}] {finding.template_name} @ {finding.matched_at}", level)
                    
                except json.JSONDecodeError:
                    continue
            
            # Parse stats from stderr
            stderr_text = stderr.decode()
            if 'templates loaded' in stderr_text.lower():
                import re
                match = re.search(r'(\d+)\s+templates', stderr_text)
                if match:
                    result.templates_used = int(match.group(1))
            
            self.log(f"Scan complete: {len(result.findings)} findings in {result.scan_duration:.1f}s")
            
        except asyncio.TimeoutError:
            result.errors.append(f"Scan timed out after {timeout}s")
            self.log(f"Scan timed out", "ERROR")
        except Exception as e:
            result.errors.append(str(e))
            self.log(f"Scan error: {e}", "ERROR")
        
        # Save results
        result.save()
        
        # Feed to VIPER knowledge base
        await self._feed_to_knowledge_base(result)
        
        return result
    
    async def quick_scan(self, target: str) -> NucleiScanResult:
        """Run a quick scan with common vulnerability templates"""
        return await self.scan(
            target,
            severity=['critical', 'high', 'medium'],
            tags=['cve', 'rce', 'sqli', 'xss', 'lfi', 'ssrf'],
            rate_limit=100,
            timeout=180
        )
    
    async def full_scan(self, target: str) -> NucleiScanResult:
        """Run a comprehensive scan"""
        return await self.scan(
            target,
            severity=['critical', 'high', 'medium', 'low'],
            exclude_tags=['dos'],  # Exclude DoS templates
            rate_limit=50,
            timeout=600
        )
    
    async def cve_scan(self, target: str, years: List[str] = None) -> NucleiScanResult:
        """Scan for known CVEs"""
        tags = ['cve']
        if years:
            tags.extend([f'cve{y}' for y in years])
        
        return await self.scan(
            target,
            tags=tags,
            rate_limit=100,
            timeout=300
        )
    
    async def _feed_to_knowledge_base(self, result: NucleiScanResult):
        """Feed findings to VIPER knowledge base"""
        if not result.findings:
            return
        
        try:
            # Load existing knowledge
            if KNOWLEDGE_FILE.exists():
                knowledge = json.loads(KNOWLEDGE_FILE.read_text())
            else:
                knowledge = {"nuclei_findings": [], "attack_stats": {}}
            
            # Add findings
            if "nuclei_findings" not in knowledge:
                knowledge["nuclei_findings"] = []
            
            for finding in result.findings:
                entry = {
                    "target": result.target,
                    "template_id": finding.template_id,
                    "severity": finding.severity,
                    "matched_at": finding.matched_at,
                    "timestamp": finding.timestamp
                }
                knowledge["nuclei_findings"].append(entry)
            
            # Keep last 500 findings
            knowledge["nuclei_findings"] = knowledge["nuclei_findings"][-500:]
            
            # Update attack stats - nuclei findings count as successful attacks
            for finding in result.findings:
                category = self._categorize_finding(finding)
                if category not in knowledge.get("attack_stats", {}):
                    knowledge["attack_stats"][category] = {"attempts": 0, "successes": 0}
                knowledge["attack_stats"][category]["successes"] += 1
            
            # Save
            KNOWLEDGE_FILE.write_text(json.dumps(knowledge, indent=2))
            self.log(f"Fed {len(result.findings)} findings to knowledge base")
            
        except Exception as e:
            self.log(f"Failed to update knowledge base: {e}", "ERROR")
    
    def _categorize_finding(self, finding: NucleiFinding) -> str:
        """Categorize finding into attack category"""
        template_lower = finding.template_id.lower()
        name_lower = finding.template_name.lower()
        combined = f"{template_lower} {name_lower}"
        
        if any(x in combined for x in ['sqli', 'sql-injection', 'sql']):
            return "sqli"
        elif any(x in combined for x in ['xss', 'cross-site-scripting']):
            return "xss"
        elif any(x in combined for x in ['rce', 'remote-code-execution', 'command-injection']):
            return "rce"
        elif any(x in combined for x in ['lfi', 'local-file-inclusion', 'path-traversal']):
            return "lfi"
        elif any(x in combined for x in ['ssrf', 'server-side-request']):
            return "ssrf"
        elif any(x in combined for x in ['auth', 'bypass', 'credential', 'default-login']):
            return "auth"
        elif any(x in combined for x in ['disclosure', 'exposure', 'leak']):
            return "disclosure"
        else:
            return "other"


async def main():
    """CLI interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("VIPER Nuclei Scanner")
        print()
        print("Usage:")
        print("  python nuclei_scanner.py <url>           # Quick scan")
        print("  python nuclei_scanner.py <url> --full    # Full scan")
        print("  python nuclei_scanner.py <url> --cve     # CVE scan")
        print("  python nuclei_scanner.py --update        # Update templates")
        return
    
    scanner = NucleiScanner()
    
    if sys.argv[1] == '--update':
        await scanner.check_and_update_templates()
        return
    
    target = sys.argv[1]
    
    if '--full' in sys.argv:
        result = await scanner.full_scan(target)
    elif '--cve' in sys.argv:
        result = await scanner.cve_scan(target)
    else:
        result = await scanner.quick_scan(target)
    
    print(f"\n=== Nuclei Scan Results for {target} ===")
    summary = result.to_dict()['summary']
    print(f"Critical: {summary['critical']}")
    print(f"High: {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low: {summary['low']}")
    print(f"Info: {summary['info']}")
    print(f"Duration: {result.scan_duration:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
