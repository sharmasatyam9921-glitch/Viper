"""Recon/attack-surface artifacts are separated from vulnerability findings."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hack_mode import HackResult, _is_surface  # noqa: E402


def test_recon_artifacts_are_surface():
    for vt in ("endpoint:http://t/a", "dns_a:1.2.3.4", "subdomain:x.t",
               "open_port:443", "historical_url:http://t/x", "technology:nginx",
               "shodan_port:80"):
        assert _is_surface({"vuln_type": vt}), vt


def test_real_findings_are_not_surface():
    for vt in ("sqli:id", "xss_text:q", "cors_wildcard", "idor:bola:/x",
               "github_secret:aws", "shodan_cve:CVE-2021-1234", "rce:cmdi:id",
               "env_exposed:/.env", "information_disclosure:listing:/ftp"):
        assert not _is_surface({"vuln_type": vt}), vt


def test_hackresult_counts_separate_surface_from_findings():
    r = HackResult(target="t", profile="p", hunt_id="h", audit_path=Path("a"))
    r.findings = [{"vuln_type": "sqli:id"}, {"vuln_type": "cors_wildcard"}]
    r.surface = [{"vuln_type": "endpoint:http://t/a"}, {"vuln_type": "dns_a:1.1.1.1"}]
    assert r.findings_count == 2          # vulns only
    assert r.surface_count == 2
    d = r.to_dict()
    assert d["findings_count"] == 2 and d["surface_count"] == 2
