"""Tests for core.payload_library."""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import payload_library as pl


def setup_function(_):
    # Each test starts from a clean cache so patches to the file path apply.
    pl.reload()


def teardown_function(_):
    # Restore the real cache for subsequent test modules.
    pl.reload()


# --- real file -------------------------------------------------------------

def test_loads_real_file():
    payloads = pl.get_payloads("sql_injection")
    assert payloads, "expected sql_injection payloads from the real file"
    assert all(isinstance(p, dict) for p in payloads)
    assert all("payload" in p for p in payloads)


def test_payload_count_positive():
    assert pl.payload_count() > 0


def test_known_vuln_classes_present():
    # A representative spread of the scorer's vuln classes should resolve.
    for vuln_class in ("xss", "ssrf", "lfi", "rce", "cors", "open_redirect"):
        assert pl.get_payloads(vuln_class), f"{vuln_class} missing payloads"


# --- unknown class ---------------------------------------------------------

def test_unknown_class_returns_empty():
    assert pl.get_payloads("not_a_real_class") == []


def test_meta_key_not_exposed_as_class():
    # The leading-underscore "_meta" block must not be returned as payloads.
    assert pl.get_payloads("_meta") == []


# --- merge_payloads --------------------------------------------------------

def test_merge_dedups_and_preserves_defaults_first():
    defaults = ["' OR '1'='1", "custom-default-payload"]
    merged = pl.merge_payloads(defaults, "sql_injection")

    # Defaults come first, in order.
    assert merged[: len(defaults)] == defaults
    # The default that also exists in the library appears exactly once.
    assert merged.count("' OR '1'='1") == 1
    # No duplicates overall.
    assert len(merged) == len(set(merged))
    # Library actually contributed extra payloads.
    assert len(merged) > len(defaults)


def test_merge_collapses_duplicate_defaults():
    merged = pl.merge_payloads(["dup", "dup", "x"], "xss")
    assert merged[:2] == ["dup", "x"]


def test_merge_unknown_class_returns_only_defaults():
    defaults = ["a", "b"]
    assert pl.merge_payloads(defaults, "not_a_real_class") == defaults


def test_merge_waf_only_filters_non_bypass():
    full = pl.merge_payloads([], "sql_injection")
    waf = pl.merge_payloads([], "sql_injection", waf_only=True)
    assert waf, "expected at least one waf_bypass payload for sql_injection"
    # waf_only is a strict subset of the full set.
    assert set(waf) <= set(full)
    assert len(waf) < len(full)


def test_merge_returns_new_list():
    defaults = ["a"]
    merged = pl.merge_payloads(defaults, "xss")
    merged.append("mutated")
    assert defaults == ["a"], "merge must not mutate the caller's list"


def test_get_payloads_returns_copy():
    first = pl.get_payloads("xss")
    first.append({"payload": "junk"})
    assert len(pl.get_payloads("xss")) == len(first) - 1


# --- corrupt / missing file ------------------------------------------------

def test_corrupt_file_degrades_to_empty(tmp_path):
    bad = tmp_path / "payloads.json"
    bad.write_text("{ this is not valid json ", encoding="utf-8")
    with patch.object(pl, "_PAYLOADS_PATH", bad):
        pl.reload()
        assert pl.get_payloads("sql_injection") == []
        assert pl.payload_count() == 0
        # Merge still works, returning just the defaults.
        assert pl.merge_payloads(["x"], "sql_injection") == ["x"]


def test_missing_file_degrades_to_empty(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    with patch.object(pl, "_PAYLOADS_PATH", missing):
        pl.reload()
        assert pl.get_payloads("xss") == []
        assert pl.payload_count() == 0


def test_non_dict_root_degrades_to_empty(tmp_path):
    weird = tmp_path / "payloads.json"
    weird.write_text("[1, 2, 3]", encoding="utf-8")
    with patch.object(pl, "_PAYLOADS_PATH", weird):
        pl.reload()
        assert pl.payload_count() == 0


def test_malformed_entries_filtered(tmp_path):
    # Non-list class values are skipped; non-dict entries are dropped.
    f = tmp_path / "payloads.json"
    f.write_text(
        '{"xss": [{"payload": "<script>"}, "string-entry", 42], '
        '"bad_class": "not-a-list"}',
        encoding="utf-8",
    )
    with patch.object(pl, "_PAYLOADS_PATH", f):
        pl.reload()
        assert pl.get_payloads("xss") == [{"payload": "<script>"}]
        assert pl.get_payloads("bad_class") == []
