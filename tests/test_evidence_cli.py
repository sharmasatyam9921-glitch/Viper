"""`viper.py evidence verify` — re-verify a hunt's chain-of-custody manifest."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.chain_of_custody import ChainOfCustody  # noqa: E402
from core.evidence_cli import run_evidence_cli  # noqa: E402

_F1 = {"vuln_type": "ssrf:url", "url": "http://t/f",
       "proof_requests": [{"method": "GET", "url": "http://t/f?url=meta", "status": 200}]}
_F2 = {"vuln_type": "jwt:weak_key", "url": "http://t/api"}


def _build(tmp_path, key="k"):
    coc = ChainOfCustody(session_key=key, custody_dir=tmp_path)
    coc.record_finding("ssrf:url#0", _F1, target="t")
    coc.record_finding("jwt:weak_key#1", _F2, target="t")
    coc.generate_evidence_manifest(session_id="s1")
    manifest = tmp_path / "s1_manifest.json"
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([_F1, _F2]))
    return str(manifest), str(findings)


def test_verify_matching_findings_passes(tmp_path, capsys):
    manifest, findings = _build(tmp_path)
    rc = run_evidence_cli(["verify", manifest, findings])
    out = capsys.readouterr().out
    assert rc == 0
    assert "2/2 finding(s) match" in out and "OK — evidence integrity verified" in out


def test_tampered_finding_fails(tmp_path, capsys):
    manifest, findings = _build(tmp_path)
    Path(findings).write_text(json.dumps([_F1, {**_F2, "url": "http://evil/"}]))
    rc = run_evidence_cli(["verify", manifest, findings])
    out = capsys.readouterr().out
    assert rc == 1
    assert "1/2 finding(s) match" in out and "UNVERIFIED" in out


def test_hmac_signature_with_key(tmp_path, capsys):
    manifest, findings = _build(tmp_path, key="secret-k")
    assert run_evidence_cli(["verify", manifest, findings, "--key", "secret-k"]) == 0
    assert "HMAC signature: VALID" in capsys.readouterr().out
    assert run_evidence_cli(["verify", manifest, "--key", "wrong"]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_usage_and_bad_paths(tmp_path, capsys):
    assert run_evidence_cli([]) == 2
    assert run_evidence_cli(["verify", str(tmp_path / "nope.json")]) == 2
