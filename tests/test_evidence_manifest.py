"""A swarm hunt writes a signed chain-of-custody manifest of its submittable findings,
each SHA-256 hashed over its full content (incl. the gate's proof_requests), so the
confirming evidence the human submits is tamper-evident."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.chain_of_custody import ChainOfCustody  # noqa: E402


def test_custody_manifest_signs_and_detects_tampering(tmp_path):
    coc = ChainOfCustody(session_key="fixed-key", custody_dir=tmp_path)
    coc.record_finding("f1", {"vuln_type": "xss:q",
                              "proof_requests": [{"url": "http://t/x", "status": 200}]},
                       target="t")
    coc.generate_evidence_manifest(session_id="s1")
    mpath = tmp_path / "s1_manifest.json"
    assert mpath.exists()
    assert coc.verify_manifest(str(mpath))              # signature valid

    data = json.loads(mpath.read_text())
    data["entries"][0]["hash"] = "0" * 64               # tamper a recorded hash
    mpath.write_text(json.dumps(data))
    assert not coc.verify_manifest(str(mpath))          # HMAC no longer matches


def test_recorded_hash_covers_proof_requests(tmp_path):
    coc = ChainOfCustody(session_key="k", custody_dir=tmp_path)
    finding = {"vuln_type": "sqli:id",
               "proof_requests": [{"method": "GET", "url": "http://t/x?id=1'", "status": 500}]}
    entry = coc.record_finding("f", finding, target="t")
    canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"))
    assert entry["hash"] == hashlib.sha256(canonical.encode()).hexdigest()
    # altering the captured proof request changes the finding's hash (tamper-evident)
    tampered = json.loads(json.dumps(finding))
    tampered["proof_requests"][0]["url"] = "http://t/x?id=harmless"
    canonical2 = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical2.encode()).hexdigest() != entry["hash"]


def _hackmode(tmp_path):
    from core.audit_logger import AuditLogger
    from core.hack_mode import HackMode
    from core.hack_profile import LabProfile
    from core.narrator import Narrator
    audit = AuditLogger.for_hunt("t", hunts_dir=tmp_path / "h", db_path=tmp_path / "v.db")
    return HackMode(target="http://t/", profile=LabProfile(),
                    narrator=Narrator(quiet=True), audit=audit)


class _Res:
    def __init__(self, findings):
        self.findings = findings


def _manifest_path(hm):
    return Path(hm.audit.jsonl_path).parent / f"{hm.audit.hunt_id}_manifest.json"


def test_hackmode_writes_manifest_for_submittable_only(tmp_path):
    hm = _hackmode(tmp_path)
    findings = [
        {"vuln_type": "xss:q", "submittable": True,
         "proof_requests": [{"method": "GET", "url": "http://t/x", "status": 200}]},
        {"vuln_type": "csrf", "submittable": False},        # a lead — excluded
    ]
    hm._write_evidence_manifest(_Res(findings))
    mpath = _manifest_path(hm)
    assert mpath.exists()
    manifest = json.loads(mpath.read_text())
    assert manifest["total_findings"] == 1                  # only the submittable one
    assert manifest["entries"][0]["hash"]                   # SHA-256 recorded
    assert manifest["signature"]                            # HMAC-signed


def test_hackmode_no_submittable_writes_no_manifest(tmp_path):
    hm = _hackmode(tmp_path)
    hm._write_evidence_manifest(_Res([{"vuln_type": "x", "submittable": False}]))
    assert not _manifest_path(hm).exists()
