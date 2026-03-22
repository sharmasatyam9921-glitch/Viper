#!/usr/bin/env python3
"""
VIPER RoE Parser — Parse Rules of Engagement documents into machine-enforceable scope.

Supports PDF, TXT, MD, RST, and JSON engagement documents. Extracts:
- In-scope and out-of-scope domains, IPs, URLs
- Testing rules (rate limits, testing hours, excluded vuln types)
- Program metadata

Uses pypdf2 for PDFs with graceful fallback to text extraction.
"""

import json
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("viper.roe")

# Import scope types from sibling module
try:
    from scope.scope_manager import BugBountyScope, ScopeEntry, ProgramRules, ScopeManager
except ImportError:
    from scope_manager import BugBountyScope, ScopeEntry, ProgramRules, ScopeManager


# --- Extraction patterns ---

DOMAIN_RE = re.compile(
    r'(?<![A-Za-z0-9@/])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![A-Za-z0-9])'
)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')
URL_RE = re.compile(r'https?://[^\s<>"\')\]},]+')
WILDCARD_RE = re.compile(r'\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')

# Section markers
IN_SCOPE_MARKERS = [
    "in scope", "in-scope", "scope:", "target", "targets",
    "allowed", "included", "assets in scope", "target scope",
    "testing scope", "authorized targets", "scope of engagement",
]
OUT_SCOPE_MARKERS = [
    "out of scope", "out-of-scope", "excluded", "not in scope",
    "off limits", "off-limits", "do not test", "excluded assets",
    "exclusions", "restrictions on targets",
]
RULE_MARKERS = [
    "rules of engagement", "rules", "restrictions", "guidelines",
    "constraints", "requirements", "policy", "terms",
    "testing rules", "engagement rules", "test limitations",
]

# Common non-target domains to filter out
IGNORE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "github.com", "gitlab.com", "bitbucket.org",
    "hackerone.com", "bugcrowd.com", "intigriti.com",
    "google.com", "microsoft.com", "apple.com",
    "stackoverflow.com", "wikipedia.org",
    "w3.org", "schema.org", "json-ld.org",
    "creativecommons.org", "opensource.org",
    "mozilla.org", "chromium.org",
    "localhost", "127.0.0.1",
}

# Vuln type keywords to detect in exclusion rules
VULN_TYPE_KEYWORDS = {
    "dos": ["dos", "denial of service", "ddos", "resource exhaustion"],
    "social_engineering": ["social engineering", "phishing", "pretexting"],
    "spam": ["spam", "unsolicited"],
    "physical": ["physical", "physical access", "physical security"],
    "rate_limiting": ["rate limit", "rate-limit", "brute force"],
    "self_xss": ["self-xss", "self xss"],
    "missing_headers": ["missing headers", "security headers", "clickjacking"],
    "logout_csrf": ["logout csrf", "logout cross-site"],
    "account_enumeration": ["user enumeration", "account enumeration", "username enumeration"],
}


@dataclass
class ParsedSection:
    """A detected section in the RoE document."""
    section_type: str  # "in_scope", "out_scope", "rules", "unknown"
    title: str
    content: str
    start_line: int = 0


class RoEParser:
    """Parse Rules of Engagement documents into machine-enforceable scope."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [ROE] [{level}] {msg}")

    # --- PDF extraction ---

    def _extract_pdf_text(self, pdf_path: str) -> str:
        """Extract text from PDF. Tries pypdf2, falls back to basic read."""
        path = Path(pdf_path)
        if not path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        # Try PyPDF2
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(str(path))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            if pages:
                self.log(f"Extracted {len(pages)} pages via PyPDF2")
                return "\n\n".join(pages)
        except ImportError:
            self.log("PyPDF2 not installed, trying fallbacks", "WARN")
        except Exception as e:
            self.log(f"PyPDF2 extraction failed: {e}", "WARN")

        # Try pypdf (newer package name)
        try:
            from pypdf import PdfReader
            reader = PdfReader(str(path))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            if pages:
                self.log(f"Extracted {len(pages)} pages via pypdf")
                return "\n\n".join(pages)
        except ImportError:
            pass
        except Exception as e:
            self.log(f"pypdf extraction failed: {e}", "WARN")

        # Try pdfplumber
        try:
            import pdfplumber
            pages = []
            with pdfplumber.open(str(path)) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        pages.append(text)
            if pages:
                self.log(f"Extracted {len(pages)} pages via pdfplumber")
                return "\n\n".join(pages)
        except ImportError:
            pass
        except Exception as e:
            self.log(f"pdfplumber extraction failed: {e}", "WARN")

        # Last resort: try reading as text (won't work for real PDFs but handles misnamed files)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if text.strip():
                self.log("Read PDF as plain text (fallback)", "WARN")
                return text
        except Exception:
            pass

        raise RuntimeError(f"Could not extract text from {pdf_path}. Install pypdf2: pip install PyPDF2")

    # --- Section detection ---

    def _detect_sections(self, text: str) -> List[ParsedSection]:
        """Split document text into labeled sections based on header markers."""
        lines = text.split("\n")
        sections: List[ParsedSection] = []
        current_type = "unknown"
        current_title = ""
        current_lines: List[str] = []
        current_start = 0

        for i, line in enumerate(lines):
            line_lower = line.strip().lower()

            # Detect section headers
            detected = None
            for marker in IN_SCOPE_MARKERS:
                if marker in line_lower and len(line.strip()) < 100:
                    detected = "in_scope"
                    break
            if not detected:
                for marker in OUT_SCOPE_MARKERS:
                    if marker in line_lower and len(line.strip()) < 100:
                        detected = "out_scope"
                        break
            if not detected:
                for marker in RULE_MARKERS:
                    if marker in line_lower and len(line.strip()) < 100:
                        detected = "rules"
                        break

            if detected:
                # Save previous section
                if current_lines:
                    sections.append(ParsedSection(
                        section_type=current_type,
                        title=current_title,
                        content="\n".join(current_lines),
                        start_line=current_start,
                    ))
                current_type = detected
                current_title = line.strip()
                current_lines = []
                current_start = i
            else:
                current_lines.append(line)

        # Save last section
        if current_lines:
            sections.append(ParsedSection(
                section_type=current_type,
                title=current_title,
                content="\n".join(current_lines),
                start_line=current_start,
            ))

        return sections

    # --- Asset extraction ---

    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names, filtering noise."""
        raw = DOMAIN_RE.findall(text)
        # Also get wildcards
        wildcards = WILDCARD_RE.findall(text)
        domains = []
        seen = set()
        for d in raw + wildcards:
            d_lower = d.lower().strip(".")
            if d_lower in seen:
                continue
            if d_lower in IGNORE_DOMAINS:
                continue
            # Skip things that look like file extensions or versions
            if re.match(r'^\d+\.\d+\.\d+', d_lower):
                continue
            if len(d_lower) < 4:
                continue
            seen.add(d_lower)
            domains.append(d_lower)
        return domains

    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses and CIDR ranges."""
        raw = IP_RE.findall(text)
        ips = []
        seen = set()
        for ip in raw:
            if ip in seen:
                continue
            # Validate IP octets
            parts = ip.split("/")[0].split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    seen.add(ip)
                    ips.append(ip)
        return ips

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs."""
        raw = URL_RE.findall(text)
        urls = []
        seen = set()
        for url in raw:
            # Clean trailing punctuation
            url = url.rstrip(".,;:!?)")
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls

    def _classify_asset(self, asset: str) -> str:
        """Determine asset type."""
        if asset.startswith("*."):
            return "wildcard"
        if "/" in asset and "." in asset.split("/")[0]:
            parts = asset.split("/")[0].split(".")
            if all(p.isdigit() for p in parts):
                return "cidr"
        if IP_RE.fullmatch(asset.split("/")[0] if "/" in asset else asset):
            return "ip"
        if asset.startswith("http"):
            return "url"
        if "api" in asset.lower() or asset.startswith("/"):
            return "api"
        return "domain"

    # --- Rule extraction ---

    def _extract_rules(self, text: str) -> ProgramRules:
        """Extract testing rules from text."""
        rules = ProgramRules()
        text_lower = text.lower()

        # Rate limits
        rate_match = re.search(r'(\d+)\s*(?:requests?|req)\s*(?:per|/)\s*(?:second|sec|s)', text_lower)
        if rate_match:
            rules.max_rps = float(rate_match.group(1))
        else:
            rate_match = re.search(r'rate\s*(?:limit)?\s*(?:of|:)?\s*(\d+)', text_lower)
            if rate_match:
                rules.max_rps = float(rate_match.group(1))

        # Testing hours
        hours_match = re.search(r'(\d{1,2})\s*(?::\d{2})?\s*(?:am|pm|utc)?\s*(?:to|-|–)\s*(\d{1,2})\s*(?::\d{2})?\s*(?:am|pm|utc)?', text_lower)
        if hours_match and any(kw in text_lower for kw in ["testing hours", "test window", "allowed hours", "business hours"]):
            start = int(hours_match.group(1))
            end = int(hours_match.group(2))
            if 0 <= start <= 23 and 0 <= end <= 23:
                rules.testing_hours = (start, end)

        # Excluded vuln types
        excluded = list(rules.excluded_vuln_types)  # Start with defaults
        for vuln_type, keywords in VULN_TYPE_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower and vuln_type not in excluded:
                    # Check it's in an exclusion context
                    for line in text.split("\n"):
                        line_l = line.lower()
                        if kw in line_l and any(neg in line_l for neg in ["not", "exclud", "do not", "won't", "will not", "out of scope", "no "]):
                            excluded.append(vuln_type)
                            break
        rules.excluded_vuln_types = excluded

        # No automated tools
        if any(phrase in text_lower for phrase in ["no automated", "manual only", "no scanners", "no automated tools"]):
            rules.no_automated_tools = True

        # Manual verification required
        if any(phrase in text_lower for phrase in ["manual verification", "verify manually", "must verify"]):
            rules.require_manual_verification = True

        return rules

    # --- Main parsing ---

    def parse_text(self, text: str, source_name: str = "document") -> BugBountyScope:
        """Parse plain text RoE into a BugBountyScope object."""
        self.log(f"Parsing RoE text ({len(text)} chars) from {source_name}")

        sections = self._detect_sections(text)
        self.log(f"Detected {len(sections)} sections: {[s.section_type for s in sections]}")

        scope = BugBountyScope(program_name=source_name, platform="custom")

        # If no sections detected, treat entire document as in-scope
        if all(s.section_type == "unknown" for s in sections):
            self.log("No section markers found, extracting from full document")
            domains = self._extract_domains(text)
            ips = self._extract_ips(text)
            urls = self._extract_urls(text)
            for d in domains:
                scope.in_scope.append(ScopeEntry(target=d, asset_type=self._classify_asset(d), in_scope=True))
            for ip in ips:
                scope.in_scope.append(ScopeEntry(target=ip, asset_type=self._classify_asset(ip), in_scope=True))
            for url in urls:
                scope.in_scope.append(ScopeEntry(target=url, asset_type="url", in_scope=True))
            rules = self._extract_rules(text)
        else:
            rules = ProgramRules()
            for section in sections:
                if section.section_type == "in_scope":
                    domains = self._extract_domains(section.content)
                    ips = self._extract_ips(section.content)
                    urls = self._extract_urls(section.content)
                    for d in domains:
                        scope.in_scope.append(ScopeEntry(target=d, asset_type=self._classify_asset(d), in_scope=True))
                    for ip in ips:
                        scope.in_scope.append(ScopeEntry(target=ip, asset_type=self._classify_asset(ip), in_scope=True))
                    for url in urls:
                        scope.in_scope.append(ScopeEntry(target=url, asset_type="url", in_scope=True))

                elif section.section_type == "out_scope":
                    domains = self._extract_domains(section.content)
                    ips = self._extract_ips(section.content)
                    urls = self._extract_urls(section.content)
                    for d in domains:
                        scope.out_of_scope.append(ScopeEntry(target=d, asset_type=self._classify_asset(d), in_scope=False))
                    for ip in ips:
                        scope.out_of_scope.append(ScopeEntry(target=ip, asset_type=self._classify_asset(ip), in_scope=False))
                    for url in urls:
                        scope.out_of_scope.append(ScopeEntry(target=url, asset_type="url", in_scope=False))

                elif section.section_type == "rules":
                    rules = self._extract_rules(section.content)

        self.log(f"Parsed scope: {len(scope.in_scope)} in-scope, {len(scope.out_of_scope)} out-of-scope assets")
        return scope, rules

    def parse_pdf(self, pdf_path: str) -> Tuple[BugBountyScope, ProgramRules]:
        """Parse a PDF engagement document."""
        self.log(f"Parsing PDF: {pdf_path}")
        text = self._extract_pdf_text(pdf_path)
        name = Path(pdf_path).stem.replace("_", " ").replace("-", " ").title()
        return self.parse_text(text, source_name=name)

    def parse_file(self, file_path: str) -> Tuple[BugBountyScope, ProgramRules]:
        """Auto-detect format and parse any engagement document."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        ext = path.suffix.lower()
        self.log(f"Parsing file: {path.name} (format: {ext})")

        if ext == ".pdf":
            return self.parse_pdf(file_path)
        elif ext == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            scope = BugBountyScope.from_dict(data)
            rules = ProgramRules()
            # Extract rules from JSON if present
            if "rules" in data:
                r = data["rules"]
                rules.max_rps = r.get("max_rps", 10.0)
                rules.testing_hours = tuple(r["testing_hours"]) if r.get("testing_hours") else None
                rules.excluded_vuln_types = r.get("excluded_vuln_types", rules.excluded_vuln_types)
                rules.no_automated_tools = r.get("no_automated_tools", False)
                rules.require_manual_verification = r.get("require_manual_verification", False)
            return scope, rules
        elif ext in (".txt", ".md", ".rst", ".text"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            name = path.stem.replace("_", " ").replace("-", " ").title()
            return self.parse_text(text, source_name=name)
        else:
            # Try as text
            self.log(f"Unknown extension {ext}, trying as plain text", "WARN")
            text = path.read_text(encoding="utf-8", errors="ignore")
            name = path.stem.replace("_", " ").replace("-", " ").title()
            return self.parse_text(text, source_name=name)

    def parse_and_load(self, file_path: str, scope_manager: Optional[ScopeManager] = None) -> Tuple[BugBountyScope, ProgramRules]:
        """Parse a file and optionally load into a ScopeManager."""
        scope, rules = self.parse_file(file_path)
        if scope_manager:
            scope_manager.active_scope = scope
            scope_manager.rules = rules
            self.log(f"Loaded scope into ScopeManager: {scope.program_name}")
        return scope, rules
