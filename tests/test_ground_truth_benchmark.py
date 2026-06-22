"""Ground-truth benchmark: VIPER confirms seeded vulns, flags zero decoys."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.ground_truth import DECOYS, GROUND_TRUTH, start_app  # noqa: E402
from benchmarks.harness import _run_viper, score  # noqa: E402


def test_viper_zero_false_positives_and_full_recall_on_ground_truth():
    srv, base = start_app()
    try:
        confirmed = asyncio.run(_run_viper(base))
        s = score("VIPER", confirmed, 0.0)
        # the headline property: NEVER confirm a decoy (precision 1.00)
        assert s.fp == 0, f"false positives on decoys: {s.false_positives}"
        assert s.precision == 1.0
        # and it confirms the great majority of the seeded vulns
        assert s.recall >= 0.83, f"missed: {s.missed}"
    finally:
        srv.shutdown()


def test_ground_truth_manifest_shape():
    # 6 seeded vulns + 5 same-class decoys, all distinct paths
    assert len(GROUND_TRUTH) == 6
    assert len(DECOYS) == 5
    vuln_paths = {p for p, _ in GROUND_TRUTH}
    assert vuln_paths.isdisjoint(set(DECOYS))
