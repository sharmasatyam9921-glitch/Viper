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
    """Check that at least one AI provider is configured.

    Mirrors ``ModelRouter.is_available`` so the message matches what the router actually
    accepts: Claude CLI (free OAuth), an Anthropic/OpenAI/DeepSeek/custom API key, a custom
    OpenAI-compatible endpoint (VIPER_API_BASE), or an Ollama model. VIPER runs LLM-free
    besides (recon + swarm + gate), so this is a warning, not a hard requirement."""
    import pathlib

    # Claude CLI (OAuth, free) — only relevant when not explicitly disabled.
    use_cli = os.environ.get("VIPER_USE_CLI", "").lower() in ("true", "1", "yes")
    cli_disabled = os.environ.get("VIPER_USE_CLI", "").lower() in ("false", "0", "no")
    claude_path = shutil.which("claude") or shutil.which("claude.CMD")
    if not claude_path:
        _npm_win = pathlib.Path.home() / "AppData" / "Roaming" / "npm" / "claude.CMD"
        _npm_lin = pathlib.Path.home() / ".npm-global" / "bin" / "claude"
        if _npm_win.exists():
            claude_path = str(_npm_win)
        elif _npm_lin.exists():
            claude_path = str(_npm_lin)
    if use_cli or (claude_path and not cli_disabled):
        loc = claude_path or "claude (in PATH)"
        return CheckResult("AI Provider", True, f"Claude CLI detected: {loc}", required=False)

    # API keys / custom endpoints handled by LiteLLM.
    key_labels = {
        "ANTHROPIC_API_KEY": "Anthropic API key",
        "OPENAI_API_KEY": "OpenAI API key",
        "DEEPSEEK_API_KEY": "DeepSeek API key",
        "VIPER_API_KEY": "custom API key",
        "VIPER_API_BASE": "custom OpenAI-compatible endpoint (VIPER_API_BASE)",
    }
    for env, label in key_labels.items():
        if os.environ.get(env):
            return CheckResult("AI Provider", True, f"{label} configured", required=False)

    # Ollama / any local model selected via VIPER_MODEL (no key needed).
    model = (os.environ.get("VIPER_MODEL", "") or "").lower()
    if "ollama" in model:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        return CheckResult("AI Provider", True, f"Ollama model configured ({host})", required=False)

    return CheckResult(
        "AI Provider", False,
        "No LLM backend found (Claude CLI, an API key, VIPER_API_BASE, or an ollama/* "
        "VIPER_MODEL) — LLM reasoning/reporting disabled; recon+swarm+gate still run",
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
