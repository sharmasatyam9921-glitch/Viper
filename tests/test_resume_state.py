"""--resume must carry a finding forward WITHOUT losing the fields the gate re-confirms on
(vuln_type / parameter / payload / oob_token) or the chain-of-custody hash. resume_state is
the single source of truth for that serialization; HackMode.resume reconstructs from it."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.resume_state import (  # noqa: E402
    finding_from_resume_payload, finding_to_resume_payload,
)


def _coordinator_payload(f, technique):
    """Mimic swarm_coordinator: persist the resume subset + title + technique."""
    p = finding_to_resume_payload(f)
    p.setdefault("title", f.get("title") or f.get("type") or technique)
    p["technique"] = technique
    return p


def test_roundtrip_preserves_gate_reconfirm_fields():
    f = {"type": "ldap_injection", "vuln_type": "ldap_injection:cn",
         "title": "LDAP injection in 'cn'", "url": "http://t/s?cn=*)(uid=*",
         "parameter": "cn", "payload": "*)(uid=*", "evidence": "engine error",
         "cwe": "CWE-90", "severity": "high", "confidence": 0.8}
    back = finding_from_resume_payload(_coordinator_payload(f, "query_injection"))
    for k in ("type", "vuln_type", "url", "parameter", "payload", "cwe", "severity"):
        assert back[k] == f[k], k


def test_roundtrip_preserves_oob_token():
    f = {"type": "ssrf", "vuln_type": "ssrf:blind:url", "url": "http://t/f?url=x",
         "parameter": "url", "payload": "http://canary.oob", "oob_token": "cafe1234",
         "severity": "high"}
    back = finding_from_resume_payload(_coordinator_payload(f, "ssrf"))
    assert back["oob_token"] == "cafe1234"


def test_legacy_payload_still_reconstructs():
    # A pre-upgrade audit log only stored title + technique + url.
    back = finding_from_resume_payload(
        {"title": "sqli: id param", "technique": "sqli_probe", "url": "http://t/?id=1"})
    assert back["type"] == "sqli"
    assert back["vuln_type"] == "sqli_probe:sqli: id param"
    assert back["url"] == "http://t/?id=1"
    assert back["severity"] == "info"


def test_custody_hash_is_stable_across_reconstruction():
    from core.chain_of_custody import hash_finding
    f = {"type": "xss", "vuln_type": "xss:q", "url": "http://t/?q=x",
         "parameter": "q", "payload": "<svg onload=1>", "severity": "medium"}
    p = _coordinator_payload(f, "xss_probe")
    a = hash_finding(finding_from_resume_payload(p))
    b = hash_finding(finding_from_resume_payload(p))
    assert a == b       # deterministic -> the resumed manifest verifies


def test_non_sensitive_only_no_proof_requests_carried():
    # proof_requests (may hold redacted auth) must NOT be in the resume payload.
    f = {"type": "idor", "vuln_type": "idor:id", "url": "http://t/o/1",
         "proof_requests": [{"headers": {"authorization": "Bearer x"}}],
         "parameter": "id", "severity": "high"}
    p = finding_to_resume_payload(f)
    assert "proof_requests" not in p
    assert "authorization" not in str(p).lower()


def test_hackmode_resume_reconstructs_full_finding(tmp_path):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "hunts",
                                 db_path=tmp_path / "v.db", ts=100)
    audit.event("hunt.started", target="http://t/",
                payload={"profile": {"name": "LabProfile"}})
    f = {"type": "ldap_injection", "vuln_type": "ldap_injection:cn", "title": "LDAP inj",
         "url": "http://t/s?cn=*)(uid=*", "parameter": "cn", "payload": "*)(uid=*",
         "severity": "high"}
    audit.event("finding.published", phase="vuln", target="http://t/", severity="high",
                payload=_coordinator_payload(f, "query_injection"))
    hunt_id = audit.hunt_id

    hm = HackMode.resume(hunt_id, hunts_dir=tmp_path / "hunts", db_path=tmp_path / "v.db",
                         profile=LabProfile(), narrator=Narrator(quiet=True))
    recovered = hm._state.get("findings", [])
    assert recovered, "resume dropped the published finding"
    r = recovered[0]
    assert r["parameter"] == "cn" and r["payload"] == "*)(uid=*"
    assert r["vuln_type"] == "ldap_injection:cn"     # NOT the lossy technique:title shape
