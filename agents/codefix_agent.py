"""CodeFix Agent — automated vulnerability remediation.

Uses the CodeFix Engine (Phase D) with tree-sitter-powered tools
for precise code navigation and LLM-driven ReACT fix loops.
"""

import logging
from typing import Dict, List, Optional

from core.codefix_engine import CodeFixEngine
from core.codefix_tools import CodefixTools

logger = logging.getLogger("viper.codefix_agent")


class CodeFixAgent:
    """Analyzes findings and generates code fixes using the ReACT engine."""

    def __init__(self, model_router=None):
        self.model_router = model_router
        self.engine = CodeFixEngine(model_router=model_router)
        self.tools = CodefixTools()
        self.available = True  # Always available (rule-based fallback if no LLM)

    async def suggest_fix(self, finding: dict, repo_path: str = None) -> dict:
        """
        Generate a fix suggestion for a finding.

        If repo_path is provided and model_router is available, runs the full
        ReACT loop. Otherwise returns a remediation suggestion.

        Args:
            finding: Vulnerability finding dict.
            repo_path: Optional path to the target repository.

        Returns:
            Dict with fix details (status, files_changed, suggestion, etc.)
        """
        vuln = finding.get("type", finding.get("vuln_type",
                           finding.get("finding_type", "unknown")))
        url = finding.get("url", "unknown")

        if repo_path:
            # Full engine: ReACT loop (LLM) or rule-based fallback
            try:
                result = await self.engine.fix_finding(finding, repo_path)
                return {
                    "finding": vuln,
                    "url": url,
                    "status": result["status"],
                    "files_changed": result.get("files_changed", []),
                    "patch_file": result.get("patch_file"),
                    "pr_url": result.get("pr_url"),
                    "error": result.get("error"),
                    "auto_fix": result["status"] == "fixed",
                    "suggestion": self._get_remediation(vuln),
                    "engine": "react_tree_sitter" if self.model_router else "rule_based",
                    "tree_sitter": self.tools.has_tree_sitter(),
                }
            except Exception as e:
                logger.error(f"CodeFix engine failed: {e}")
                return {
                    "finding": vuln,
                    "url": url,
                    "status": "error",
                    "error": str(e),
                    "auto_fix": False,
                    "suggestion": self._get_remediation(vuln),
                    "engine": "fallback",
                }

        # No repo_path — return suggestion only
        return {
            "finding": vuln,
            "url": url,
            "suggestion": self._get_remediation(vuln),
            "auto_fix": False,
            "status": "suggestion_only",
            "engine": "suggestion",
            "tree_sitter": self.tools.has_tree_sitter(),
        }

    async def fix_finding(self, finding: dict, repo_path: str) -> dict:
        """Direct access to the engine's fix_finding (full ReACT loop)."""
        return await self.engine.fix_finding(finding, repo_path)

    async def fix_and_pr(self, finding: dict, repo_path: str,
                         branch_prefix: str = "viper-fix/") -> dict:
        """Fix a finding and create a GitHub PR."""
        return await self.engine.fix_and_pr(finding, repo_path, branch_prefix)

    async def fix_findings(self, findings: List[dict],
                           repo_path: str) -> List[dict]:
        """Fix multiple findings sequentially."""
        return await self.engine.fix_findings(findings, repo_path)

    def _get_remediation(self, vuln_type: str) -> str:
        """Get a remediation suggestion string for a vulnerability type."""
        remediations = {
            "sqli": "Use parameterized queries / prepared statements",
            "xss": "Sanitize output with context-aware encoding",
            "lfi": "Validate and whitelist file paths, disable directory traversal",
            "ssti": "Use sandboxed template rendering, avoid user input in templates",
            "ssrf": "Whitelist allowed URLs/IPs, block internal ranges",
            "cors": "Restrict Access-Control-Allow-Origin to trusted domains",
            "idor": "Implement proper authorization checks on object access",
            "cmdi": "Avoid shell execution; use language-native APIs with input validation",
            "rce": "Avoid eval/exec; use safe alternatives with input validation",
            "secret": "Move secrets to environment variables or a secrets manager",
            "misconfiguration": "Set secure defaults (DEBUG=False, verify=True, etc.)",
            "dependency": "Upgrade to the patched version specified in the advisory",
            "csrf": "Implement anti-CSRF tokens on state-changing endpoints",
            "open_redirect": "Validate redirect URLs against a whitelist of allowed domains",
            "xxe": "Disable external entity processing in XML parsers",
        }
        return remediations.get(vuln_type, f"Review and remediate {vuln_type}")
