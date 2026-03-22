"""
VIPER 4.0 - Wappalyzer Technology Fingerprinting Engine
=========================================================
Pure-Python implementation of Wappalyzer-style technology detection.
Loads data/wappalyzer_technologies.json and matches against HTTP responses.

Pattern fields in the technology DB:
    headers  - {header_name: "regex_pattern"} or {header_name: "literal"}
    cookies  - {cookie_name: "regex_pattern"}
    html     - "regex" or ["regex", ...]
    scripts  - "regex" or ["regex", ...]
    meta     - {meta_name: "regex_pattern"}
    implies  - "Tech" or ["Tech", ...]
    excludes - "Tech" or ["Tech", ...]

Patterns can include version extraction: "pattern\\;version:\\1"
Confidence modifiers: "pattern\\;confidence:50"

No external dependencies. Stdlib only.
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple


_DEFAULT_TECH_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "wappalyzer_technologies.json"
)


def _parse_pattern(raw: str) -> Tuple[Optional[re.Pattern], Optional[str], int]:
    """
    Parse a Wappalyzer pattern string into (compiled_regex, version_group, confidence).

    Patterns can have modifiers separated by \\;
        "pattern\\;version:\\1\\;confidence:80"
    """
    if not raw:
        return None, None, 100

    parts = raw.split("\\;")
    pattern_str = parts[0]
    version_tpl = None
    confidence = 100

    for part in parts[1:]:
        if part.startswith("version:"):
            version_tpl = part[8:]
        elif part.startswith("confidence:"):
            try:
                confidence = int(part[11:])
            except ValueError:
                pass

    try:
        compiled = re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return None, version_tpl, confidence

    return compiled, version_tpl, confidence


def _extract_version(match: re.Match, version_tpl: Optional[str]) -> Optional[str]:
    """Extract version string from regex match using Wappalyzer version template."""
    if not version_tpl or not match:
        return None

    version = version_tpl
    for i in range(10):
        placeholder = f"\\{i}"
        if placeholder in version:
            try:
                group_val = match.group(i)
                version = version.replace(placeholder, group_val or "")
            except (IndexError, AttributeError):
                version = version.replace(placeholder, "")

    version = version.strip()
    return version if version else None


def _ensure_list(val) -> list:
    """Normalize a value to a list."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return val
    return [val]


class Wappalyzer:
    """Technology fingerprinting engine using Wappalyzer pattern database."""

    def __init__(self, tech_file: str = None):
        self.tech_file = tech_file or _DEFAULT_TECH_FILE
        self.categories: Dict[str, dict] = {}
        self.technologies: Dict[str, dict] = {}
        self._compiled: Dict[str, dict] = {}  # Pre-compiled patterns
        self._load()

    def _load(self):
        """Load and parse the Wappalyzer technologies database."""
        if not os.path.exists(self.tech_file):
            raise FileNotFoundError(f"Wappalyzer DB not found: {self.tech_file}")

        with open(self.tech_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.categories = data.get("categories", {})
        self.technologies = data.get("technologies", {})

        # Pre-compile patterns for each technology
        for tech_name, tech_data in self.technologies.items():
            self._compiled[tech_name] = self._compile_tech(tech_data)

    def _compile_tech(self, tech_data: dict) -> dict:
        """Pre-compile all regex patterns for a technology."""
        compiled = {
            "headers": {},
            "cookies": {},
            "html": [],
            "scripts": [],
            "meta": {},
            "url": [],
        }

        # Headers: {header_name: "pattern"}
        for hdr, pattern in (tech_data.get("headers") or {}).items():
            parsed = _parse_pattern(str(pattern))
            if parsed[0]:
                compiled["headers"][hdr.lower()] = parsed

        # Cookies: {cookie_name: "pattern"}
        for cookie, pattern in (tech_data.get("cookies") or {}).items():
            if pattern:
                parsed = _parse_pattern(str(pattern))
                compiled["cookies"][cookie] = parsed
            else:
                # Empty pattern = just check cookie existence
                compiled["cookies"][cookie] = (None, None, 100)

        # HTML patterns
        for pattern in _ensure_list(tech_data.get("html")):
            parsed = _parse_pattern(str(pattern))
            if parsed[0]:
                compiled["html"].append(parsed)

        # Script src patterns
        for pattern in _ensure_list(tech_data.get("scripts")):
            parsed = _parse_pattern(str(pattern))
            if parsed[0]:
                compiled["scripts"].append(parsed)

        # Meta tags: {meta_name: "pattern"}
        for meta_name, pattern in (tech_data.get("meta") or {}).items():
            for p in _ensure_list(pattern):
                parsed = _parse_pattern(str(p))
                if parsed[0]:
                    if meta_name not in compiled["meta"]:
                        compiled["meta"][meta_name] = []
                    compiled["meta"][meta_name].append(parsed)

        # URL patterns
        for pattern in _ensure_list(tech_data.get("url")):
            parsed = _parse_pattern(str(pattern))
            if parsed[0]:
                compiled["url"].append(parsed)

        return compiled

    def _get_category_names(self, cat_ids: list) -> list:
        """Resolve category IDs to names."""
        names = []
        for cid in (cat_ids or []):
            cat = self.categories.get(str(cid), {})
            name = cat.get("name")
            if name:
                names.append(name)
        return names

    def fingerprint(self, url: str, headers: dict, body: str,
                    scripts: list = None, cookies: dict = None,
                    meta_tags: dict = None) -> list:
        """
        Fingerprint technologies from HTTP response data.

        Args:
            url: The request URL
            headers: Response headers dict (keys will be lowercased)
            body: Response HTML body
            scripts: List of <script src="..."> URLs found in HTML
            cookies: Dict of cookie names -> values
            meta_tags: Dict of <meta name="..."> -> content values

        Returns:
            List of detected technologies:
            [{"name", "version", "categories", "confidence", "detected_by"}, ...]
        """
        # Normalize headers to lowercase keys
        headers_lower = {}
        if headers:
            for k, v in headers.items():
                headers_lower[k.lower().replace("_", "-")] = str(v)

        # Extract scripts from HTML if not provided
        if scripts is None and body:
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', body, re.IGNORECASE)

        # Extract meta tags from HTML if not provided
        if meta_tags is None and body:
            meta_tags = {}
            for match in re.finditer(
                r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
                body, re.IGNORECASE
            ):
                meta_tags[match.group(1).lower()] = match.group(2)
            # Also match content before name
            for match in re.finditer(
                r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\']',
                body, re.IGNORECASE
            ):
                meta_tags[match.group(2).lower()] = match.group(1)

        # Extract cookies from Set-Cookie headers if not provided
        if cookies is None:
            cookies = {}
            set_cookie = headers_lower.get("set-cookie", "")
            if set_cookie:
                for cookie_str in set_cookie.split(","):
                    parts = cookie_str.strip().split(";")[0]
                    if "=" in parts:
                        name, val = parts.split("=", 1)
                        cookies[name.strip()] = val.strip()

        scripts = scripts or []
        meta_tags = meta_tags or {}
        cookies = cookies or {}
        body = body or ""

        detections: Dict[str, dict] = {}  # tech_name -> best detection

        for tech_name, compiled in self._compiled.items():
            best_confidence = 0
            best_version = None
            detected_by = []

            # Check URL patterns
            for regex, ver_tpl, conf in compiled["url"]:
                if regex:
                    m = regex.search(url)
                    if m:
                        v = _extract_version(m, ver_tpl)
                        if v:
                            best_version = v
                        best_confidence = max(best_confidence, conf)
                        detected_by.append("url")

            # Check headers
            for hdr_name, (regex, ver_tpl, conf) in compiled["headers"].items():
                hdr_val = headers_lower.get(hdr_name, "")
                if not hdr_val:
                    continue
                if regex:
                    m = regex.search(hdr_val)
                    if m:
                        v = _extract_version(m, ver_tpl)
                        if v:
                            best_version = v
                        best_confidence = max(best_confidence, conf)
                        detected_by.append(f"header:{hdr_name}")

            # Check cookies
            for cookie_name, (regex, ver_tpl, conf) in compiled["cookies"].items():
                cookie_val = cookies.get(cookie_name)
                if cookie_val is None:
                    continue
                if regex is None:
                    # Just existence check
                    best_confidence = max(best_confidence, conf)
                    detected_by.append(f"cookie:{cookie_name}")
                else:
                    m = regex.search(str(cookie_val))
                    if m:
                        v = _extract_version(m, ver_tpl)
                        if v:
                            best_version = v
                        best_confidence = max(best_confidence, conf)
                        detected_by.append(f"cookie:{cookie_name}")

            # Check HTML body
            for regex, ver_tpl, conf in compiled["html"]:
                m = regex.search(body)
                if m:
                    v = _extract_version(m, ver_tpl)
                    if v:
                        best_version = v
                    best_confidence = max(best_confidence, conf)
                    detected_by.append("html")
                    break  # One HTML match is enough

            # Check script sources
            for regex, ver_tpl, conf in compiled["scripts"]:
                for src in scripts:
                    m = regex.search(src)
                    if m:
                        v = _extract_version(m, ver_tpl)
                        if v:
                            best_version = v
                        best_confidence = max(best_confidence, conf)
                        detected_by.append(f"script:{src[:60]}")
                        break

            # Check meta tags
            for meta_name, patterns in compiled["meta"].items():
                meta_val = meta_tags.get(meta_name.lower(), "")
                if not meta_val:
                    continue
                for regex, ver_tpl, conf in patterns:
                    m = regex.search(meta_val)
                    if m:
                        v = _extract_version(m, ver_tpl)
                        if v:
                            best_version = v
                        best_confidence = max(best_confidence, conf)
                        detected_by.append(f"meta:{meta_name}")
                        break

            if best_confidence > 0:
                tech_data = self.technologies.get(tech_name, {})
                cat_ids = tech_data.get("cats", [])
                detections[tech_name] = {
                    "name": tech_name,
                    "version": best_version,
                    "categories": self._get_category_names(cat_ids),
                    "confidence": best_confidence,
                    "detected_by": detected_by,
                    "website": tech_data.get("website", ""),
                }

        # Resolve implied technologies
        resolved = dict(detections)
        seen = set(resolved.keys())
        queue = list(resolved.keys())

        while queue:
            tech_name = queue.pop(0)
            tech_data = self.technologies.get(tech_name, {})
            implies = _ensure_list(tech_data.get("implies"))
            for imp in implies:
                # Handle confidence modifier: "Tech\\;confidence:50"
                imp_parts = imp.split("\\;")
                imp_name = imp_parts[0].strip()
                imp_conf = 100
                for p in imp_parts[1:]:
                    if p.startswith("confidence:"):
                        try:
                            imp_conf = int(p[11:])
                        except ValueError:
                            pass

                if imp_name not in seen and imp_name in self.technologies:
                    imp_data = self.technologies[imp_name]
                    cat_ids = imp_data.get("cats", [])
                    resolved[imp_name] = {
                        "name": imp_name,
                        "version": None,
                        "categories": self._get_category_names(cat_ids),
                        "confidence": imp_conf,
                        "detected_by": [f"implied_by:{tech_name}"],
                        "website": imp_data.get("website", ""),
                    }
                    seen.add(imp_name)
                    queue.append(imp_name)

        # Remove excluded technologies
        for tech_name in list(resolved.keys()):
            tech_data = self.technologies.get(tech_name, {})
            excludes = _ensure_list(tech_data.get("excludes"))
            for exc in excludes:
                resolved.pop(exc, None)

        # Sort by confidence descending
        results = sorted(resolved.values(), key=lambda x: x["confidence"], reverse=True)
        return results

    def fingerprint_response(self, url: str, response_headers: dict,
                              response_body: str) -> list:
        """Convenience: fingerprint from URL + response headers + body."""
        return self.fingerprint(url=url, headers=response_headers, body=response_body)


# =============================================================================
# Module-level convenience
# =============================================================================

_default_wap: Optional[Wappalyzer] = None


def _get_wap() -> Wappalyzer:
    global _default_wap
    if _default_wap is None:
        _default_wap = Wappalyzer()
    return _default_wap


def fingerprint(url: str, headers: dict, body: str, **kwargs) -> list:
    """Quick fingerprint for a single response."""
    return _get_wap().fingerprint(url=url, headers=headers, body=body, **kwargs)


if __name__ == "__main__":
    w = Wappalyzer()
    print(f"[*] Wappalyzer loaded: {len(w.technologies)} technologies, {len(w.categories)} categories")

    # Test with sample HTML
    test_html = """
    <html>
    <head>
        <meta name="generator" content="WordPress 6.4.2">
        <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
    </head>
    <body>
        <div id="wp-content">Powered by WordPress</div>
    </body>
    </html>
    """
    test_headers = {
        "server": "nginx/1.24.0",
        "x-powered-by": "PHP/8.2.0",
    }

    results = w.fingerprint(
        url="https://example.com",
        headers=test_headers,
        body=test_html,
    )
    print(f"\n[*] Detected {len(results)} technologies:")
    for t in results[:10]:
        ver = f" v{t['version']}" if t['version'] else ""
        cats = ", ".join(t['categories'][:3]) or "uncategorized"
        print(f"    {t['name']}{ver} [{cats}] (confidence: {t['confidence']}%)")
