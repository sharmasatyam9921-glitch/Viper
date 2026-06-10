"""VIPER benchmark harness.

Run VIPER against a suite of challenge targets, score each run, and emit an
XBOW-style scorecard (overall solve rate + per-category breakdown).

Public API:
    from harness import Challenge, RunResult, Score
    from harness.targets import TargetManager
    from harness.runner import ViperRunner
    from harness.scorer import score
"""

from .models import Challenge, Expect, RunResult, Score, Target

__all__ = ["Challenge", "Expect", "RunResult", "Score", "Target"]
