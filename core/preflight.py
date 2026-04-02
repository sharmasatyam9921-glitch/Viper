#!/usr/bin/env python3
"""
VIPER Startup Preflight Checker

Validates that required tools and environment variables are present
before starting a hunt.
"""
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

REQUIRED_TOOLS = ["httpx", "nuclei"]
OPTIONAL_TOOLS = ["subfinder", "amass", "naabu", "katana", "gau", "nmap", "ffuf"]
OPTIONAL_ENV_VARS = [
    "SHODAN_API_KEY", "NUCLEI_API_KEY", "SERPAPI_KEY", "TAVILY_API_KEY",
    "DISCORD_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "HACKERONE_API_TOKEN",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    required: bool = True

    @property
    def status(self) -> str:
        if self.passed:
            return "OK"
        return "FAIL" if self.required else "WARN"


@dataclass
class PreflightReport:
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if no required checks failed."""
        return all(c.passed or not c.required for c in self.checks)

    @property
    def failures(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.passed and c.required]

    @property
    def warnings(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.passed and not c.required]

    def format(self) -> str:
        lines = ["=== VIPER Preflight Check ==="]
        for c in self.checks:
            icon = "[OK]  " if c.passed else ("[FAIL]" if c.required else "[WARN]")
            lines.append(f"  {icon} {c.name}: {c.message}")
        lines.append("")
        lines.append("[OK] All checks passed" if self.passed else "[FAIL] Some required checks failed")
        return "\n".join(lines)

    def print_report(self):
        output = self.format()
        try:
            print(output)
        except UnicodeEncodeError:
            print(output.encode("ascii", errors="replace").decode("ascii"))
        print()


def check_python_version() -> CheckResult:
    """Check that Python >= 3.10 is in use."""
    v = sys.version_info
    version_str = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 10):
        return CheckResult("Python version", True, version_str)
    return CheckResult("Python version", False, f"Python 3.10+ required, got {version_str}")


def check_tool(tool: str, install_hint: str = "", required: bool = True) -> CheckResult:
    """Check whether an external tool is available in PATH."""
    path = shutil.which(tool)
    if path:
        return CheckResult(f"Tool: {tool}", True, f"found at {path}", required=required)
    hint = f" — {install_hint}" if install_hint else ""
    msg = f"{tool} not found in PATH{hint}"
    return CheckResult(f"Tool: {tool}", False, msg, required=required)


def check_ai_provider() -> CheckResult:
    """Check that at least one AI provider is configured."""
    import pathlib
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    use_cli = os.environ.get("VIPER_USE_CLI", "").lower() in ("true", "1", "yes")

    # Auto-detect Claude CLI in PATH or common npm location (Windows/Linux)
    claude_path = shutil.which("claude") or shutil.which("claude.CMD")
    if not claude_path:
        _npm_win = pathlib.Path.home() / "AppData" / "Roaming" / "npm" / "claude.CMD"
        _npm_lin = pathlib.Path.home() / ".npm-global" / "bin" / "claude"
        if _npm_win.exists():
            claude_path = str(_npm_win)
        elif _npm_lin.exists():
            claude_path = str(_npm_lin)

    if use_cli or claude_path:
        loc = claude_path or "claude (in PATH)"
        return CheckResult("AI Provider", True, f"Claude CLI detected: {loc}", required=False)
    if has_api_key:
        return CheckResult("AI Provider", True, "Anthropic API key set")
    return CheckResult(
        "AI Provider", False,
        "No ANTHROPIC_API_KEY or Claude CLI found — LLM features disabled",
        required=False,
    )


def check_env_var(var: str, description: str = "", required: bool = False) -> CheckResult:
    """Check whether an environment variable is set."""
    value = os.environ.get(var, "")
    if value:
        masked = value[:4] + "..." if len(value) > 4 else "set"
        return CheckResult(f"Env: {var}", True, masked, required=required)
    hint = f" ({description})" if description else ""
    return CheckResult(f"Env: {var}", False, f"not set{hint}", required=required)


def run_preflight(skip_optional: bool = False) -> Tuple[bool, "PreflightReport"]:
    """Run all preflight checks and return (passed, report)."""
    report = PreflightReport()

    report.checks.append(check_python_version())
    report.checks.append(check_ai_provider())

    for tool in REQUIRED_TOOLS:
        report.checks.append(check_tool(tool, required=True))

    if not skip_optional:
        for tool in OPTIONAL_TOOLS:
            report.checks.append(check_tool(tool, required=False))

    for var in OPTIONAL_ENV_VARS:
        report.checks.append(check_env_var(var, required=False))

    return report.passed, report
