"""Tests for ChainWriter — attack chain graph persistence."""
import pytest
from unittest.mock import MagicMock
from core.chain_writer import ChainWriter, FindingType, TypedFinding


class TestFindingTypeEnum:
    def test_all_26_finding_types_exist(self):
        expected = [
            "service_identified", "vulnerability_confirmed", "exploit_success",
            "access_gained", "privilege_escalation", "credential_found",
            "data_accessed", "defense_detected", "defense_bypassed",
            "lateral_movement", "persistence_established", "information_disclosure",
            "configuration_issue", "authentication_bypass", "injection_confirmed",
            "file_access", "command_execution", "network_access", "secret_found",
            "misconfiguration", "data_exfiltration", "denial_of_service_success",
            "social_engineering_success", "remote_code_execution",
            "session_hijacked", "custom",
        ]
        actual_values = {ft.value for ft in FindingType}
        for e in expected:
            assert e in actual_values, f"FindingType '{e}' missing from enum"

    def test_finding_type_count_is_26(self):
        assert len(list(FindingType)) == 26

    def test_finding_type_from_string(self):
        ft = FindingType("vulnerability_confirmed")
        assert ft == FindingType.VULNERABILITY_CONFIRMED


class TestTypedFinding:
    def test_typed_finding_defaults(self):
        tf = TypedFinding(finding_type=FindingType.VULNERABILITY_CONFIRMED)
        assert tf.severity == "info"
        assert tf.confidence == 0.8
        assert tf.description == ""
        assert tf.related_cves == []
        assert tf.related_ips == []
        assert tf.evidence == ""

    def test_typed_finding_to_dict(self):
        tf = TypedFinding(
            finding_type=FindingType.INJECTION_CONFIRMED,
            severity="high",
            confidence=0.9,
            title="SQLi found",
            url="http://example.com/login",
        )
        d = tf.to_dict()
        assert d["finding_type"] == "injection_confirmed"
        assert d["severity"] == "high"
        assert d["confidence"] == 0.9
        assert d["title"] == "SQLi found"
        assert d["url"] == "http://example.com/login"

    def test_typed_finding_from_dict(self):
        data = {
            "finding_type": "exploit_success",
            "severity": "critical",
            "confidence": 1.0,
            "description": "RCE achieved",
            "related_cves": ["CVE-2021-44228"],
            "related_ips": ["10.0.0.1"],
            "evidence": "whoami output",
            "title": "RCE",
            "url": "http://target.com/api",
            "step_id": "step-abc",
        }
        tf = TypedFinding.from_dict(data)
        assert tf.finding_type == FindingType.EXPLOIT_SUCCESS
        assert tf.severity == "critical"
        assert tf.confidence == 1.0
        assert tf.related_cves == ["CVE-2021-44228"]

    def test_typed_finding_from_dict_unknown_type_defaults_to_custom(self):
        data = {"finding_type": "totally_unknown_type"}
        tf = TypedFinding.from_dict(data)
        assert tf.finding_type == FindingType.CUSTOM

    def test_typed_finding_evidence_truncated_at_5000(self):
        long_evidence = "x" * 10000
        tf = TypedFinding(
            finding_type=FindingType.CUSTOM,
            evidence=long_evidence,
        )
        d = tf.to_dict()
        assert len(d["evidence"]) <= 5000


class TestChainWriterLifecycle:
    def test_start_chain_returns_chain_id_string(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        assert isinstance(chain_id, str)
        assert len(chain_id) > 0

    def test_start_chain_uses_custom_session_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com", session_id="my-session-42")
        assert chain_id == "my-session-42"

    def test_start_chain_registers_in_active_chains(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        assert chain_id in chain_writer._active_chains

    def test_end_chain_removes_from_active(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.end_chain(chain_id, status="completed")
        assert chain_id not in chain_writer._active_chains

    def test_end_chain_returns_summary_dict(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        summary = chain_writer.end_chain(chain_id)
        assert summary["chain_id"] == chain_id
        assert "status" in summary
        assert "steps" in summary
        assert "findings" in summary

    def test_end_chain_not_found_returns_not_found(self, chain_writer):
        summary = chain_writer.end_chain("ghost-chain")
        assert summary["status"] == "not_found"

    def test_get_active_chains_empty_initially(self, chain_writer):
        chains = chain_writer.get_active_chains()
        assert chains == []

    def test_get_active_chains_shows_started_chain(self, chain_writer):
        chain_writer.start_chain(target="example.com")
        chains = chain_writer.get_active_chains()
        assert len(chains) == 1
        assert chains[0]["target"] == "example.com"


class TestChainWriterSteps:
    def test_add_step_returns_step_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        step_id = chain_writer.add_step(chain_id, tool="nmap")
        assert isinstance(step_id, str)
        assert step_id.startswith("step-")

    def test_add_step_recorded_in_chain(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.add_step(chain_id, tool="nuclei", input_data="scan", output_data="results")
        assert len(chain_writer._active_chains[chain_id]["steps"]) == 1

    def test_add_step_multiple_steps(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.add_step(chain_id, tool="nmap")
        chain_writer.add_step(chain_id, tool="nuclei")
        chain_writer.add_step(chain_id, tool="sqlmap")
        assert len(chain_writer._active_chains[chain_id]["steps"]) == 3


class TestChainWriterFindings:
    def test_add_finding_returns_finding_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        fid = chain_writer.add_finding(
            chain_id, finding_type="sqli", severity="high", title="SQLi in login"
        )
        assert fid.startswith("cfind-")

    def test_add_finding_recorded_in_chain(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.add_finding(chain_id, finding_type="xss", severity="medium")
        assert len(chain_writer._active_chains[chain_id]["findings"]) == 1

    def test_add_typed_finding_returns_finding_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        tf = TypedFinding(
            finding_type=FindingType.VULNERABILITY_CONFIRMED,
            severity="high",
            title="XSS",
        )
        fid = chain_writer.add_typed_finding(chain_id, tf)
        assert fid.startswith("tfind-")

    def test_add_typed_findings_batch(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        findings = [
            TypedFinding(finding_type=FindingType.VULNERABILITY_CONFIRMED, severity="high"),
            TypedFinding(finding_type=FindingType.INJECTION_CONFIRMED, severity="critical"),
        ]
        ids = chain_writer.add_typed_findings_batch(chain_id, findings)
        assert len(ids) == 2
        assert all(fid.startswith("tfind-") for fid in ids)


class TestChainWriterDecisionsAndFailures:
    def test_add_decision_returns_decision_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        dec_id = chain_writer.add_decision(chain_id, decision="escalate", reasoning="sqli found")
        assert dec_id.startswith("dec-")

    def test_add_decision_recorded_in_chain(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.add_decision(chain_id, decision="pivot")
        assert len(chain_writer._active_chains[chain_id]["decisions"]) == 1

    def test_add_failure_returns_failure_id(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        fail_id = chain_writer.add_failure(chain_id, failure_type="timeout", message="timed out")
        assert fail_id.startswith("fail-")

    def test_end_chain_counts_all_items(self, chain_writer):
        chain_id = chain_writer.start_chain(target="example.com")
        chain_writer.add_step(chain_id, tool="nmap")
        chain_writer.add_step(chain_id, tool="nuclei")
        chain_writer.add_finding(chain_id, finding_type="xss")
        chain_writer.add_decision(chain_id, decision="escalate")
        chain_writer.add_failure(chain_id, message="timeout")
        summary = chain_writer.end_chain(chain_id)
        assert summary["steps"] == 2
        assert summary["findings"] == 1
        assert summary["decisions"] == 1
        assert summary["failures"] == 1
