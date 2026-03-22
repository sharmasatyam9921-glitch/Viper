"""
VIPER 4.0 Approval Gate — CLI-based approval for phase transitions and dangerous tools.
Supports interactive (prompt user) and daemon (auto-approve) modes.
"""

import sys
from typing import Optional

from .agent_state import PhaseTransitionRequest, ToolConfirmationRequest

# ── ANSI colors (graceful fallback if terminal doesn't support them) ──────

_COLORS_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not _COLORS_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"

def _red(t: str) -> str: return _c("91", t)
def _yellow(t: str) -> str: return _c("93", t)
def _green(t: str) -> str: return _c("92", t)
def _cyan(t: str) -> str: return _c("96", t)
def _bold(t: str) -> str: return _c("1", t)
def _dim(t: str) -> str: return _c("2", t)


# ── Default dangerous tools ──────────────────────────────────────────────

DEFAULT_DANGEROUS_TOOLS = {
    "execute_nmap",
    "execute_naabu",
    "nuclei_scan",
    "execute_hydra",
    "kali_shell",
    "execute_code",
    "metasploit_console",
    "msf_restart",
    "brute_force",
    "post_exploit",
}


# ── Separator ─────────────────────────────────────────────────────────────

def _separator(char: str = "-", width: int = 60) -> str:
    return _dim(char * width)


# ── ApprovalGate ──────────────────────────────────────────────────────────

class ApprovalGate:
    """
    CLI-based approval gate for VIPER agent actions.

    In interactive mode, prompts the user before phase transitions and
    dangerous tool executions. In auto-approve (daemon) mode, approves
    everything silently.
    """

    def __init__(
        self,
        auto_approve: bool = False,
        dangerous_tools: Optional[set] = None,
    ):
        self.auto_approve = auto_approve
        self.dangerous_tools = dangerous_tools if dangerous_tools is not None else DEFAULT_DANGEROUS_TOOLS

    # ── Phase transitions ─────────────────────────────────────────────

    def is_dangerous_tool(self, tool_name: str) -> bool:
        """Return True if *tool_name* is in the dangerous-tools set."""
        return tool_name in self.dangerous_tools

    def check_phase_transition(
        self,
        request_or_from_phase,
        to_phase=None,
        *,
        interactive: bool = True,
    ) -> tuple:
        """
        Check whether a phase transition should proceed.

        Accepts either:
            check_phase_transition(PhaseTransitionRequest)
            check_phase_transition('recon', 'exploit', interactive=False)

        Returns:
            (decision, modification) where decision is 'approve'|'modify'|'abort'
        """
        # Handle two-string calling convention
        if isinstance(request_or_from_phase, str) and to_phase is not None:
            request_or_from_phase = PhaseTransitionRequest(
                from_phase=request_or_from_phase, to_phase=to_phase, reason="API call"
            )

        if not interactive:
            return ("approve", "")

        if self.auto_approve:
            return ("approve", "")

        print()
        print(_separator("="))
        print(_bold(_yellow("  PHASE TRANSITION REQUEST")))
        print(_separator("="))
        print(f"  From : {_cyan(request.from_phase)}")
        print(f"  To   : {_red(request.to_phase)}")
        print(f"  Reason: {request.reason}")

        if request.planned_actions:
            print(f"\n  {_bold('Planned actions:')}")
            for action in request.planned_actions:
                print(f"    - {action}")

        if request.risks:
            print(f"\n  {_bold(_red('Risks:'))}")
            for risk in request.risks:
                print(f"    ! {risk}")

        print(_separator("-"))
        print(f"  {_green('[y]')} Approve   {_yellow('[m]')} Modify   {_red('[n]')} Abort")
        print(_separator("-"))

        while True:
            try:
                choice = input("  Decision> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return ("abort", "")

            if choice in ("y", "yes", "approve"):
                return ("approve", "")
            elif choice in ("m", "modify"):
                try:
                    mod = input("  Modification> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return ("abort", "")
                return ("modify", mod)
            elif choice in ("n", "no", "abort"):
                return ("abort", "")
            else:
                print(f"  {_dim('Enter y, m, or n')}")

    # ── Tool execution ────────────────────────────────────────────────

    def check_tool_execution(
        self,
        tool_name: str,
        tool_args: dict,
        phase: str,
    ) -> tuple:
        """
        Check whether a tool execution should proceed.

        Returns:
            (decision, modified_args) where decision is 'approve'|'modify'|'reject'
            and modified_args is the (possibly modified) tool arguments dict.
        """
        # Safe tools pass through without prompting
        if tool_name not in self.dangerous_tools:
            return ("approve", tool_args)

        if self.auto_approve:
            return ("approve", tool_args)

        print()
        print(_separator("="))
        print(_bold(_red("  DANGEROUS TOOL EXECUTION")))
        print(_separator("="))
        print(f"  Tool  : {_red(tool_name)}")
        print(f"  Phase : {_cyan(phase)}")

        if tool_args:
            print(f"\n  {_bold('Arguments:')}")
            for k, v in tool_args.items():
                val_str = str(v)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                print(f"    {k}: {val_str}")

        print(_separator("-"))
        print(f"  {_green('[y]')} Approve   {_yellow('[m]')} Modify args   {_red('[n]')} Reject")
        print(_separator("-"))

        while True:
            try:
                choice = input("  Decision> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return ("reject", tool_args)

            if choice in ("y", "yes", "approve"):
                return ("approve", tool_args)
            elif choice in ("m", "modify"):
                modified = dict(tool_args) if tool_args else {}
                print(f"  {_dim('Enter key=value pairs, one per line. Empty line to finish.')}")
                while True:
                    try:
                        line = input("    > ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if not line:
                        break
                    if "=" in line:
                        k, v = line.split("=", 1)
                        modified[k.strip()] = v.strip()
                    else:
                        print(f"    {_dim('Format: key=value')}")
                return ("modify", modified)
            elif choice in ("n", "no", "reject"):
                return ("reject", tool_args)
            else:
                print(f"  {_dim('Enter y, m, or n')}")

    # ── Tool confirmation batch ───────────────────────────────────────

    def check_tool_confirmation(
        self,
        request: ToolConfirmationRequest,
    ) -> tuple:
        """
        Batch tool confirmation (for tool plans).

        Returns:
            (decision, approved_indices) where decision is 'approve'|'partial'|'reject'
            and approved_indices is a list of step indices to execute.
        """
        if self.auto_approve:
            return ("approve", list(range(len(request.tools))))

        print()
        print(_separator("="))
        print(_bold(_yellow("  TOOL PLAN CONFIRMATION")))
        print(_separator("="))
        print(f"  Mode      : {request.mode}")
        print(f"  Phase     : {_cyan(request.phase)}")
        print(f"  Iteration : {request.iteration}")
        print(f"  Reasoning : {request.reasoning}")

        if request.tools:
            print(f"\n  {_bold('Planned tools:')}")
            for i, tool in enumerate(request.tools):
                name = tool.get("tool_name", "?") if isinstance(tool, dict) else getattr(tool, "tool_name", "?")
                dangerous = name in self.dangerous_tools
                tag = _red("[DANGEROUS]") if dangerous else _green("[safe]")
                print(f"    {i+1}. {tag} {name}")

        print(_separator("-"))
        print(f"  {_green('[y]')} Approve all   {_yellow('[p]')} Partial (pick)   {_red('[n]')} Reject all")
        print(_separator("-"))

        while True:
            try:
                choice = input("  Decision> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return ("reject", [])

            if choice in ("y", "yes"):
                return ("approve", list(range(len(request.tools))))
            elif choice in ("p", "partial"):
                try:
                    indices_str = input("  Step numbers to approve (comma-separated)> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return ("reject", [])
                try:
                    indices = [int(x.strip()) - 1 for x in indices_str.split(",") if x.strip()]
                    indices = [i for i in indices if 0 <= i < len(request.tools)]
                except ValueError:
                    print(f"  {_dim('Invalid input')}")
                    continue
                return ("partial", indices)
            elif choice in ("n", "no"):
                return ("reject", [])
            else:
                print(f"  {_dim('Enter y, p, or n')}")

    # ── Ask user a question ───────────────────────────────────────────

    def ask_question(
        self,
        question: str,
        context: str = "",
        options: Optional[list] = None,
    ) -> str:
        """
        Ask the user a question and return their answer.
        In auto-approve mode, returns empty string (agent should handle gracefully).
        """
        if self.auto_approve:
            return ""

        print()
        print(_separator("="))
        print(_bold(_cyan("  AGENT QUESTION")))
        print(_separator("="))

        if context:
            print(f"  {_dim('Context:')} {context}")
            print()

        print(f"  {question}")

        if options:
            print()
            for i, opt in enumerate(options, 1):
                print(f"    {_bold(str(i))}. {opt}")
            print()
            print(_separator("-"))
            try:
                choice = input("  Answer (number or text)> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return ""
            # If numeric, map to option
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            except ValueError:
                pass
            return choice
        else:
            print(_separator("-"))
            try:
                answer = input("  Answer> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return ""
            return answer
