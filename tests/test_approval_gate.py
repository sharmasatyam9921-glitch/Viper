"""Tests for ApprovalGate — dangerous tool detection."""
import pytest
from core.approval_gate import ApprovalGate, DEFAULT_DANGEROUS_TOOLS, DANGEROUS_TOOLS


class TestIsDangerous:
    def test_execute_nmap_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("execute_nmap") is True

    def test_execute_naabu_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("execute_naabu") is True

    def test_nuclei_scan_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("nuclei_scan") is True

    def test_brute_force_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("brute_force") is True

    def test_post_exploit_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("post_exploit") is True

    def test_kali_shell_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("kali_shell") is True

    def test_execute_code_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("execute_code") is True

    def test_metasploit_console_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("metasploit_console") is True

    def test_sqlmap_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("sqlmap") is True

    def test_hydra_is_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("hydra") is True

    def test_safe_tool_not_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("get_page_source") is False

    def test_http_get_not_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("http_get") is False

    def test_whois_not_dangerous(self, approval_gate):
        assert approval_gate.is_dangerous("whois_lookup") is False


class TestIsDangerousArgPatterns:
    def test_nuclei_scan_with_critical_severity_is_dangerous(self, approval_gate):
        args = {"severity": "critical", "target": "example.com"}
        assert approval_gate.is_dangerous("nuclei_scan", args=args) is True

    def test_nuclei_scan_with_low_severity_is_still_dangerous(self, approval_gate):
        """nuclei_scan is in the base dangerous set regardless of args."""
        args = {"severity": "low"}
        assert approval_gate.is_dangerous("nuclei_scan", args=args) is True

    def test_execute_nmap_with_exploit_script_is_dangerous(self, approval_gate):
        args = {"flags": "--script exploit -p 80"}
        assert approval_gate.is_dangerous("execute_nmap", args=args) is True

    def test_execute_nmap_with_udp_scan_is_dangerous(self, approval_gate):
        args = {"flags": "-sU -p 161"}
        assert approval_gate.is_dangerous("execute_nmap", args=args) is True

    def test_kali_shell_with_reverse_shell_is_dangerous(self, approval_gate):
        args = {"command": "reverse_shell 10.0.0.1 4444"}
        assert approval_gate.is_dangerous("kali_shell", args=args) is True

    def test_safe_tool_with_safe_args_not_dangerous(self, approval_gate):
        args = {"url": "https://example.com", "method": "GET"}
        assert approval_gate.is_dangerous("http_request", args=args) is False


class TestAutoApproveMode:
    async def test_auto_approve_dangerous_tool_returns_true(self, approval_gate_auto):
        ok, returned_args = await approval_gate_auto.confirm_tool(
            "execute_nmap", {"flags": "-sV"}, rationale="scan test"
        )
        assert ok is True

    async def test_auto_approve_returns_args_unchanged(self, approval_gate_auto):
        original = {"target": "example.com", "port": "80"}
        ok, returned_args = await approval_gate_auto.confirm_tool(
            "nuclei_scan", original, rationale="vuln scan"
        )
        assert ok is True
        assert returned_args == original

    async def test_auto_approve_safe_tool_approved(self, approval_gate_auto):
        ok, _ = await approval_gate_auto.confirm_tool(
            "safe_tool", {}, rationale="benign"
        )
        assert ok is True

    async def test_non_dangerous_tool_always_approved(self, approval_gate):
        """Non-dangerous tools skip the gate entirely and return True."""
        ok, args = await approval_gate.confirm_tool(
            "safe_whois", {"domain": "example.com"}, rationale="recon"
        )
        assert ok is True


class TestApprovalGateInit:
    def test_default_dangerous_tools_nonempty(self):
        assert len(DEFAULT_DANGEROUS_TOOLS) > 0

    def test_dangerous_tools_set_nonempty(self):
        assert len(DANGEROUS_TOOLS) > 0

    def test_custom_dangerous_set_merged_with_defaults(self):
        custom = {"my_custom_dangerous_tool"}
        gate = ApprovalGate(dangerous_tools=custom)
        # custom tools are merged with DANGEROUS_TOOLS
        assert "my_custom_dangerous_tool" in gate.dangerous_tools
        # defaults should still be present after merge
        assert "sqlmap" in gate.dangerous_tools

    def test_auto_approve_flag_stored(self):
        gate = ApprovalGate(auto_approve=True)
        assert gate.auto_approve is True

    def test_non_auto_approve_flag_stored(self):
        gate = ApprovalGate(auto_approve=False)
        assert gate.auto_approve is False
