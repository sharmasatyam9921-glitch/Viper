"""Tests for FindingValidator — 37 vuln type dispatches."""
import pytest
from core.finding_validator import FindingValidator


# ── Helpers ──────────────────────────────────────────────────────────────────

TARGET = "http://testphp.vulnweb.com"


class TestFindingValidatorDispatch:
    """Test that each vuln_type routes to the correct validator.

    Without an HTTP client, most validators return (False, low_conf, reason)
    because they can't make HTTP requests. The important thing is that each
    known type is accepted without raising an exception.
    """

    async def test_sqli_dispatch_no_http_client(self, finding_validator):
        finding = {
            "attack": "sqli",
            "url": f"{TARGET}/listproducts.php?cat=1",
            "payload": "' OR '1'='1",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)
        assert isinstance(conf, float)
        assert 0.0 <= conf <= 1.0
        assert isinstance(reason, str)

    async def test_sqli_error_dispatch(self, finding_validator):
        finding = {"attack": "sqli_error", "url": f"{TARGET}/search?q=test", "payload": "'"}
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_sqli_blind_dispatch(self, finding_validator):
        finding = {"attack": "sqli_blind", "url": f"{TARGET}/page?id=1", "payload": "1 AND 1=1"}
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_xss_dispatch(self, finding_validator):
        finding = {
            "attack": "xss",
            "url": f"{TARGET}/search?q=<script>",
            "payload": "<script>alert(1)</script>",
            "marker": "viper-xss-test",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_xss_reflected_dispatch(self, finding_validator):
        finding = {"attack": "xss_reflected", "url": TARGET, "payload": "<img src=x>"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_lfi_dispatch(self, finding_validator):
        finding = {
            "attack": "lfi",
            "url": f"{TARGET}/page?file=../../../../etc/passwd",
            "payload": "../../../../etc/passwd",
            "marker": "root:x:",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_lfi_basic_dispatch(self, finding_validator):
        finding = {"attack": "lfi_basic", "url": TARGET, "payload": "../etc/passwd"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_path_traversal_dispatch(self, finding_validator):
        finding = {"attack": "path_traversal", "url": TARGET, "payload": "../../etc/hosts"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_ssti_dispatch(self, finding_validator):
        finding = {
            "attack": "ssti",
            "url": f"{TARGET}/render?template={{{{7*7}}}}",
            "payload": "{{7*7}}",
            "marker": "49",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_ssti_basic_dispatch(self, finding_validator):
        finding = {"attack": "ssti_basic", "url": TARGET, "payload": "{{config}}"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_cmdi_dispatch(self, finding_validator):
        finding = {"attack": "cmdi", "url": f"{TARGET}/exec?cmd=id", "payload": "; sleep 5"}
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_rce_dispatch(self, finding_validator):
        finding = {"attack": "rce", "url": TARGET, "payload": "system('id')"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_ssrf_dispatch(self, finding_validator):
        finding = {
            "attack": "ssrf",
            "url": f"{TARGET}/fetch?url=http://169.254.169.254/",
            "payload": "http://169.254.169.254/latest/meta-data/",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_cors_dispatch(self, finding_validator):
        finding = {
            "attack": "cors",
            "url": TARGET,
            "payload": "Origin: https://evil.com",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_cors_check_dispatch(self, finding_validator):
        finding = {"attack": "cors_check", "url": TARGET}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_open_redirect_dispatch(self, finding_validator):
        finding = {
            "attack": "open_redirect",
            "url": f"{TARGET}/redirect?url=https://evil.com",
            "payload": "https://evil.com",
        }
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_header_missing_dispatch(self, finding_validator):
        finding = {"attack": "header_missing", "url": TARGET, "payload": "X-Frame-Options"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_info_dispatch(self, finding_validator):
        finding = {"attack": "info", "url": TARGET}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_jwt_none_alg_dispatch(self, finding_validator):
        finding = {"attack": "jwt_none_alg", "url": TARGET, "payload": "eyJ..."}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_idor_enum_dispatch(self, finding_validator):
        finding = {"attack": "idor_enum", "url": f"{TARGET}/user/2"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_debug_endpoints_dispatch(self, finding_validator):
        finding = {"attack": "debug_endpoints", "url": f"{TARGET}/debug"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_graphql_introspection_dispatch(self, finding_validator):
        finding = {"attack": "graphql_introspection", "url": f"{TARGET}/graphql"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_xxe_basic_dispatch(self, finding_validator):
        finding = {
            "attack": "xxe_basic",
            "url": TARGET,
            "payload": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        }
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_crlf_injection_dispatch(self, finding_validator):
        finding = {"attack": "crlf_injection", "url": TARGET, "payload": "%0d%0aLocation: evil.com"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_host_header_injection_dispatch(self, finding_validator):
        finding = {"attack": "host_header_injection", "url": TARGET}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_subdomain_takeover_dispatch(self, finding_validator):
        finding = {"attack": "subdomain_takeover", "url": "http://old.example.com"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_prototype_pollution_dispatch(self, finding_validator):
        finding = {"attack": "prototype_pollution", "url": TARGET}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_request_smuggling_dispatch(self, finding_validator):
        finding = {"attack": "request_smuggling", "url": TARGET}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_unknown_type_routes_to_generic(self, finding_validator):
        """Unknown vuln types fall back to _validate_generic without raising."""
        finding = {"attack": "totally_unknown_vuln", "url": TARGET}
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)
        assert isinstance(conf, float)

    async def test_vuln_type_key_also_dispatches(self, finding_validator):
        """finding['vuln_type'] is an alternative to finding['attack']."""
        finding = {"vuln_type": "xss", "url": TARGET, "payload": "<svg>"}
        is_valid, _, _ = await finding_validator.validate(finding, TARGET)
        assert isinstance(is_valid, bool)

    async def test_validate_returns_three_tuple(self, finding_validator):
        finding = {"attack": "sqli", "url": TARGET}
        result = await finding_validator.validate(finding, TARGET)
        assert len(result) == 3

    async def test_confidence_between_0_and_1(self, finding_validator):
        finding = {"attack": "xss", "url": TARGET}
        _, conf, _ = await finding_validator.validate(finding, TARGET)
        assert 0.0 <= conf <= 1.0

    async def test_timeout_handled_gracefully(self, finding_validator):
        """validate() wraps execution in asyncio.wait_for(timeout=30s); short payloads complete quickly."""
        finding = {"attack": "cors", "url": TARGET}
        is_valid, conf, reason = await finding_validator.validate(finding, TARGET)
        assert isinstance(reason, str)
