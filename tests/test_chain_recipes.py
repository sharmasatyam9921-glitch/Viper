"""Attack-chain correlation: recipes, distinctness, submittable-iff-components."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.chain_recipes import RECIPES, correlate_chains  # noqa: E402


def _f(vt, **kw):
    d = {"vuln_type": vt, "url": "http://t/x", "title": vt, "evidence": "",
         "submittable": False}
    d.update(kw)
    return d


def _ids(chains):
    return {c["vuln_type"] for c in chains}


def test_ssrf_cloud_metadata_escalates_to_critical():
    chains = correlate_chains([_f("ssrf:url", evidence="cloud-metadata marker instance-id present")])
    assert "chain:ssrf_cloud_creds" in _ids(chains)
    c = next(c for c in chains if c["vuln_type"] == "chain:ssrf_cloud_creds")
    assert c["severity"] == "critical" and c["chain_of"] == ["ssrf:url"]


def test_exposure_plus_secret_chain():
    chains = correlate_chains([
        _f("git_exposed:/.git", title="exposed .git"),
        _f("secret:aws", title="AWS key in JS"),
    ])
    assert "chain:exposure_to_secret" in _ids(chains)


def test_open_redirect_oauth_chain():
    chains = correlate_chains([_f("open_redirect:next"), _f("jwt:alg_none")])
    assert "chain:open_redirect_oauth_ato" in _ids(chains)


def test_xss_plus_cors_credentials_chain():
    chains = correlate_chains([
        _f("xss_text:q"),
        _f("cors_misconfig", evidence="reflects origin with credentials true"),
    ])
    assert "chain:xss_session_ato" in _ids(chains)


def test_lfi_logpoison_chain():
    chains = correlate_chains([_f("lfi:file", evidence="read /var/log/apache/access.log")])
    assert "chain:lfi_to_rce" in _ids(chains)


def test_bola_pii_chain():
    chains = correlate_chains([_f("idor:bola:/api/users/5", evidence="leaked email alice@x.io")])
    assert "chain:bola_pii" in _ids(chains)


def test_no_chain_when_components_absent():
    assert correlate_chains([_f("clickjacking"), _f("cookie_flags")]) == []


def test_two_component_recipe_needs_two_distinct_findings():
    # a single finding that looks like BOTH halves must NOT self-satisfy a chain
    only_one = [_f("git_exposed:/.git", evidence="contains secret aws key")]
    assert "chain:exposure_to_secret" not in _ids(correlate_chains(only_one))


def test_chain_submittable_iff_all_components_submittable():
    confirmed = correlate_chains([
        _f("git_exposed:/.git", submittable=True, validation_confidence=0.9),
        _f("secret:aws", submittable=True, validation_confidence=0.8),
    ])
    c = next(c for c in confirmed if c["vuln_type"] == "chain:exposure_to_secret")
    assert c["submittable"] and c["validation_confidence"] == 0.8   # min of components

    mixed = correlate_chains([
        _f("git_exposed:/.git", submittable=True),
        _f("secret:aws", submittable=False),
    ])
    c2 = next(c for c in mixed if c["vuln_type"] == "chain:exposure_to_secret")
    assert not c2["submittable"] and c2["needs_manual_verification"]


def test_recipe_library_is_well_formed():
    for r in RECIPES:
        assert r.id and r.severity in ("critical", "high", "medium", "low")
        assert r.requires and r.cwe.startswith("CWE-")
