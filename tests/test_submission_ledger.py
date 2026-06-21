"""Cross-hunt duplicate suppression."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.submission_ledger import SubmissionLedger, signature  # noqa: E402


def _f(vt, url, param=None):
    return {"vuln_type": vt, "url": url, "parameter": param}


def test_signature_collapses_object_ids_in_path():
    a = signature(_f("idor:bola:/api/orders/123", "http://t/api/orders/123"))
    b = signature(_f("idor:bola:/api/orders/999", "http://t/api/orders/999"))
    assert a == b                                    # same endpoint, different object


def test_signature_distinguishes_class_param_host():
    base = _f("sqli:id", "http://t/item?id=1", "id")
    assert signature(base) != signature(_f("xss:id", "http://t/item?id=1", "id"))
    assert signature(base) != signature(_f("sqli:q", "http://t/item?id=1", "q"))
    assert signature(base) != signature(_f("sqli:id", "http://other/item?id=1", "id"))


def test_is_duplicate_after_record(tmp_path):
    led = SubmissionLedger(tmp_path / "l.json")
    f = _f("sqli:id", "http://t/item?id=1", "id")
    assert not led.is_duplicate(f)
    led.record(f)
    assert led.is_duplicate(f)
    # same class+endpoint, different object id -> still a duplicate
    assert led.is_duplicate(_f("sqli:id", "http://t/item?id=2", "id"))


def test_partition_new_handles_prior_and_intra_batch(tmp_path):
    led = SubmissionLedger(tmp_path / "l.json")
    led.record(_f("xss:q", "http://t/s?q=1", "q"))      # from a prior hunt
    batch = [
        _f("xss:q", "http://t/s?q=9", "q"),             # dup of prior
        _f("sqli:id", "http://t/item?id=1", "id"),      # new
        _f("sqli:id", "http://t/item?id=2", "id"),      # intra-batch dup of the above
    ]
    new, dups = led.partition_new(batch)
    assert len(new) == 1 and new[0]["vuln_type"] == "sqli:id"
    assert len(dups) == 2


def test_persistence_round_trip(tmp_path):
    p = tmp_path / "l.json"
    led = SubmissionLedger(p)
    led.record(_f("secret:aws", "http://t/main.js"))
    led.save()
    again = SubmissionLedger(p)
    assert again.is_duplicate(_f("secret:aws", "http://t/main.js"))


def test_record_counts_repeat_sightings(tmp_path):
    led = SubmissionLedger(tmp_path / "l.json")
    f = _f("cors", "http://t/api")
    led.record(f)
    led.record(f)
    assert led._seen[signature(f)]["count"] == 2
