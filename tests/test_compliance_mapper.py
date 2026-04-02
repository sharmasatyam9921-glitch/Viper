"""Tests for ComplianceMapper — CWE to compliance standard mapping."""
import pytest
from core.compliance_mapper import CWE_COMPLIANCE, VULN_TO_CWE, enrich_finding, format_compliance_section


class TestCWEComplianceData:
    def test_cwe_compliance_dict_nonempty(self):
        assert len(CWE_COMPLIANCE) > 0

    def test_xss_cwe_79_present(self):
        assert "CWE-79" in CWE_COMPLIANCE

    def test_sqli_cwe_89_present(self):
        assert "CWE-89" in CWE_COMPLIANCE

    def test_path_traversal_cwe_22_present(self):
        assert "CWE-22" in CWE_COMPLIANCE

    def test_cmdi_cwe_78_present(self):
        assert "CWE-78" in CWE_COMPLIANCE

    def test_csrf_cwe_352_present(self):
        assert "CWE-352" in CWE_COMPLIANCE

    def test_ssrf_cwe_918_present(self):
        assert "CWE-918" in CWE_COMPLIANCE

    def test_xxe_cwe_611_present(self):
        assert "CWE-611" in CWE_COMPLIANCE

    def test_deserialization_cwe_502_present(self):
        assert "CWE-502" in CWE_COMPLIANCE

    def test_auth_bypass_cwe_287_present(self):
        assert "CWE-287" in CWE_COMPLIANCE

    def test_hardcoded_creds_cwe_798_present(self):
        assert "CWE-798" in CWE_COMPLIANCE

    def test_xss_has_owasp_mapping(self):
        assert "owasp" in CWE_COMPLIANCE["CWE-79"]
        assert "Injection" in CWE_COMPLIANCE["CWE-79"]["owasp"]

    def test_xss_has_pci_dss_mapping(self):
        assert "pci_dss" in CWE_COMPLIANCE["CWE-79"]

    def test_sqli_has_nist_mapping(self):
        assert "nist" in CWE_COMPLIANCE["CWE-89"]

    def test_auth_bypass_has_hipaa_mapping(self):
        assert "hipaa" in CWE_COMPLIANCE["CWE-287"]

    def test_auth_bypass_has_soc2_mapping(self):
        assert "soc2" in CWE_COMPLIANCE["CWE-287"]

    def test_encryption_cwe_311_has_hipaa(self):
        assert "hipaa" in CWE_COMPLIANCE["CWE-311"]


class TestVulnToCWEMapping:
    def test_vuln_to_cwe_nonempty(self):
        assert len(VULN_TO_CWE) > 0

    def test_xss_maps_to_cwe_79(self):
        assert VULN_TO_CWE["xss"] == "CWE-79"

    def test_xss_reflected_maps_to_cwe_79(self):
        assert VULN_TO_CWE["xss_reflected"] == "CWE-79"

    def test_sqli_maps_to_cwe_89(self):
        assert VULN_TO_CWE["sqli"] == "CWE-89"

    def test_sqli_blind_maps_to_cwe_89(self):
        assert VULN_TO_CWE["sqli_blind"] == "CWE-89"

    def test_lfi_maps_to_cwe_22(self):
        assert VULN_TO_CWE["lfi"] == "CWE-22"

    def test_path_traversal_maps_to_cwe_22(self):
        assert VULN_TO_CWE["path_traversal"] == "CWE-22"

    def test_cmdi_maps_to_cwe_78(self):
        assert VULN_TO_CWE["cmdi"] == "CWE-78"

    def test_ssrf_maps_to_cwe_918(self):
        assert VULN_TO_CWE["ssrf"] == "CWE-918"

    def test_cors_maps_to_cwe_200(self):
        assert VULN_TO_CWE["cors"] == "CWE-200"

    def test_auth_bypass_maps_to_cwe_287(self):
        assert VULN_TO_CWE["auth_bypass"] == "CWE-287"

    def test_ssti_maps_to_cwe_94(self):
        assert VULN_TO_CWE["ssti"] == "CWE-94"

    def test_default_creds_maps_to_cwe_798(self):
        assert VULN_TO_CWE["default_creds"] == "CWE-798"


class TestEnrichFinding:
    def test_enrich_xss_finding_adds_compliance(self):
        finding = {"type": "xss", "url": "http://example.com/search"}
        enriched = enrich_finding(finding)
        assert "compliance" in enriched
        assert "owasp" in enriched["compliance"]

    def test_enrich_sqli_finding_adds_cwe(self):
        finding = {"type": "sqli", "url": "http://example.com/login"}
        enriched = enrich_finding(finding)
        assert enriched.get("cwe") == "CWE-89"

    def test_enrich_lfi_adds_pci_dss(self):
        finding = {"type": "lfi"}
        enriched = enrich_finding(finding)
        assert "pci_dss" in enriched.get("compliance", {})

    def test_enrich_ssrf_adds_owasp_a10(self):
        finding = {"type": "ssrf"}
        enriched = enrich_finding(finding)
        owasp = enriched.get("compliance", {}).get("owasp", "")
        assert "A10" in owasp or "SSRF" in owasp or "Request Forgery" in owasp

    def test_enrich_unknown_type_no_compliance(self):
        finding = {"type": "unknown_vuln_xyz"}
        enriched = enrich_finding(finding)
        assert "compliance" not in enriched

    def test_enrich_uses_vuln_type_key(self):
        """Finding with 'vuln_type' key instead of 'type' should also work."""
        finding = {"vuln_type": "xss"}
        enriched = enrich_finding(finding)
        assert "compliance" in enriched

    def test_enrich_explicit_cwe_overrides_lookup(self):
        finding = {"type": "sqli", "cwe": "CWE-79"}  # wrong CWE deliberately
        enriched = enrich_finding(finding)
        # explicit cwe takes precedence
        assert enriched.get("cwe") == "CWE-79"

    def test_enrich_returns_copy_not_mutating_original(self):
        finding = {"type": "xss"}
        original_keys = set(finding.keys())
        enrich_finding(finding)
        assert set(finding.keys()) == original_keys

    def test_enrich_auth_bypass_adds_hipaa(self):
        finding = {"type": "auth_bypass"}
        enriched = enrich_finding(finding)
        assert "hipaa" in enriched.get("compliance", {})

    def test_enrich_cors_adds_owasp(self):
        finding = {"type": "cors"}
        enriched = enrich_finding(finding)
        assert "owasp" in enriched.get("compliance", {})


class TestFormatComplianceSection:
    def test_empty_findings_returns_no_mappings_msg(self):
        result = format_compliance_section([])
        assert "no compliance" in result.lower() or "available" in result.lower()

    def test_xss_finding_includes_owasp_in_output(self):
        findings = [{"type": "xss"}]
        result = format_compliance_section(findings)
        assert "OWASP" in result

    def test_sqli_includes_pci_dss(self):
        findings = [{"type": "sqli"}]
        result = format_compliance_section(findings)
        assert "PCI" in result

    def test_multiple_findings_aggregate_standards(self):
        findings = [
            {"type": "xss"},
            {"type": "auth_bypass"},
        ]
        result = format_compliance_section(findings)
        assert "OWASP" in result
        assert "HIPAA" in result

    def test_output_contains_compliance_header(self):
        findings = [{"type": "sqli"}]
        result = format_compliance_section(findings)
        assert "Compliance" in result

    def test_unknown_findings_no_output(self):
        findings = [{"type": "totally_unknown_vuln_type"}]
        result = format_compliance_section(findings)
        assert "no compliance" in result.lower() or "available" in result.lower()
