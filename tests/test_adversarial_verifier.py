"""Adversarial self-verifier: re-runs the gate's confirmation and demotes any
submittable finding that does not reproduce — only ever demoting, so it can improve
precision but never cost recall on a deterministic true positive."""
from __future__ import annotations

import asyncio
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adversarial_verifier import refute_unreproducible  # noqa: E402
from core.gate_benchmark import BENCHMARK, HttpResp, _fetch, _injected  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402


def _xss_vuln(m, url, h):
    return HttpResp(200, {"content-type": "text/html"}, f"<h1>{_injected(url)}</h1>", url)


def _xss_safe(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<h1>{html.escape(_injected(url))}</h1>", url)


_XSS = {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}


def test_refuter_never_demotes_a_benchmark_true_positive():
    # The recall guarantee: EVERY labeled-vuln scenario the gate confirms must survive
    # the refutation pass (deterministic responders re-confirm every round).
    for sc in BENCHMARK:
        if sc.label != "vuln":
            continue
        fetch = _fetch(sc.responder)
        annotated = asyncio.run(validate_findings(
            [dict(sc.finding)], fetch=fetch, bola_config=sc.bola_config,
            min_confidence=sc.min_confidence))
        assert annotated[0]["submittable"], f"{sc.cls}:{sc.name} not submittable pre-refute"
        n = asyncio.run(refute_unreproducible(
            annotated, fetch=fetch, bola_config=sc.bola_config,
            min_confidence=sc.min_confidence))
        assert n == 0 and annotated[0]["submittable"], \
            f"refuter WRONGLY demoted a true positive: {sc.cls}:{sc.name}"


def test_refuter_demotes_a_non_reproducing_confirmation():
    # Confirmed once (vuln responder) but does not reproduce (safe responder) -> demote.
    annotated = asyncio.run(validate_findings([dict(_XSS)], fetch=_fetch(_xss_vuln)))
    assert annotated[0]["submittable"]
    n = asyncio.run(refute_unreproducible(annotated, fetch=_fetch(_xss_safe)))
    assert n == 1
    assert annotated[0]["submittable"] is False
    assert annotated[0]["refuted"] is True
    assert "REFUTED" in annotated[0]["validation_reason"]


def test_refuter_requires_reproduction_in_every_round():
    annotated = asyncio.run(validate_findings([dict(_XSS)], fetch=_fetch(_xss_vuln)))
    # reproduces under the vuln responder across multiple rounds -> kept
    n = asyncio.run(refute_unreproducible(annotated, fetch=_fetch(_xss_vuln), rounds=3))
    assert n == 0 and annotated[0]["submittable"]


def test_refuter_ignores_non_submittable_findings():
    lead = {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q",
            "submittable": False, "validated": False}
    n = asyncio.run(refute_unreproducible([lead], fetch=_fetch(_xss_safe)))
    assert n == 0 and lead["submittable"] is False        # untouched, not "demoted"


def test_refuter_fails_open_on_retest_error():
    annotated = asyncio.run(validate_findings([dict(_XSS)], fetch=_fetch(_xss_vuln)))
    assert annotated[0]["submittable"]

    async def boom(*a, **k):
        raise RuntimeError("network down")
    # a re-test ERROR is not a refutation — the finding is left as the gate left it
    n = asyncio.run(refute_unreproducible(annotated, fetch=boom))
    assert n == 0 and annotated[0]["submittable"] is True


def test_refuter_fails_open_on_inconclusive_retest():
    # A re-test that cannot run (fetch returns None -> "re-fetch failed") is
    # INCONCLUSIVE, not a refutation — a rate-limited / unreachable target must never
    # demote a real finding.
    annotated = asyncio.run(validate_findings([dict(_XSS)], fetch=_fetch(_xss_vuln)))
    assert annotated[0]["submittable"]

    async def none_fetch(*a, **k):
        return None
    n = asyncio.run(refute_unreproducible(annotated, fetch=none_fetch))
    assert n == 0 and annotated[0]["submittable"] is True


def test_oob_confirmed_finding_survives_refutation():
    from core.oob.canary import new_token

    class _Store:
        def has_interaction(self, tok):
            return True

        def interactions_for(self, tok):
            return [{"token": tok}]

    finding = {"vuln_type": "ssrf:blind", "url": "http://t/", "oob_token": new_token(),
               "submittable": True, "validated": True, "validation_confidence": 0.95}

    async def any_fetch(*a, **k):
        return None
    n = asyncio.run(refute_unreproducible([finding], fetch=any_fetch, oob_store=_Store()))
    assert n == 0 and finding["submittable"] is True      # the OOB interaction persists
