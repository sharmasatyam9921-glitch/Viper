"""`viper.py verify` — re-confirm saved findings via the gate."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.verify_cli import _load_findings, run_verify_cli  # noqa: E402


def test_load_findings_accepts_dict_list_and_envelope(tmp_path):
    f1 = tmp_path / "one.json"
    f1.write_text('{"vuln_type":"x","url":"http://t/"}', encoding="utf-8")
    assert len(_load_findings(str(f1))) == 1
    f2 = tmp_path / "arr.json"
    f2.write_text('[{"vuln_type":"a"},{"vuln_type":"b"}]', encoding="utf-8")
    assert len(_load_findings(str(f2))) == 2
    f3 = tmp_path / "env.json"
    f3.write_text('{"findings":[{"vuln_type":"a"}]}', encoding="utf-8")
    assert len(_load_findings(str(f3))) == 1


def test_verify_marks_trusted_bola_submittable(capsys, tmp_path):
    # an engine-provenance BOLA finding is trusted by the gate WITHOUT network
    f = tmp_path / "f.json"
    f.write_text(json.dumps({"vuln_type": "idor:bola:/api/orders/1",
                             "url": "http://t/api/orders/1",
                             "owner": "A", "attacker": "B"}), encoding="utf-8")
    rc = run_verify_cli([str(f)])
    out = capsys.readouterr().out
    assert rc == 0 and "1 submittable" in out and "SUBMITTABLE" in out


def test_verify_no_url_finding_is_lead(capsys, tmp_path):
    f = tmp_path / "f.json"
    f.write_text('{"vuln_type":"sqli:id"}', encoding="utf-8")   # no url -> lead
    rc = run_verify_cli([str(f)])
    out = capsys.readouterr().out
    assert rc == 0 and "0 submittable" in out and "lead" in out


def test_verify_missing_file_returns_1(capsys):
    rc = run_verify_cli(["/no/such/file.json"])
    assert rc == 1 and "could not read" in capsys.readouterr().out
