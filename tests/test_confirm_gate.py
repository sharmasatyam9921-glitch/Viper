"""Three-gate confirmer: differential signal + reproducibility, FP-averse."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.confirm_gate import (  # noqa: E402
    ThreeGateConfirmer,
    _set_param,
    confirm_finding,
)
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from urllib.parse import parse_qs, urlsplit  # noqa: E402


def _injected(url):
    q = parse_qs(urlsplit(url).query)
    for v in q.values():
        if v:
            return v[0]
    return ""


def _confirm(responder, finding, *, clock=None, retests=1, marker=None):
    async def fetch(method, url, *, timeout=10.0):
        return responder(url)
    conf = ThreeGateConfirmer(fetch, retests=retests,
                              clock=clock or (lambda: 0.0))
    return asyncio.run(conf.confirm(finding, benign="1", marker=marker))


def test_set_param_adds_and_replaces():
    assert _set_param("http://t/s?q=1", "q", "X") == "http://t/s?q=X"
    assert _set_param("http://t/s", "q", "X") == "http://t/s?q=X"
    # replaces the named param, preserves the others in order
    assert _set_param("http://t/s?a=1&q=2&b=3", "q", "X") == "http://t/s?a=1&q=X&b=3"
    # empty/None name -> unchanged
    assert _set_param("http://t/s?q=1", "", "X") == "http://t/s?q=1"


def test_length_only_signal_is_a_lead():
    # Body size shifts materially but nothing stronger fires -> length lead.
    def resp(url):
        return HttpResp(200, {}, "x" * 80 if "BIG" in url else "y", url)
    v = _confirm(resp, {"url": "http://t/s?q=1", "parameter": "q",
                        "payload": "BIG"})
    assert v.signal == "length" and v.reproduced
    assert not v.is_real and v.confidence == 0.45


def test_attack_failure_fails_closed():
    # Baseline is fine, the attack request errors out -> no verdict, fail closed.
    # (compare the DECODED param value — the quote is %27-encoded in the URL).
    def resp(url):
        return None if "'" in _injected(url) else HttpResp(200, {}, "ok", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1'"})
    assert not v.is_real and "attack request failed" in v.reason


def test_confirm_finding_convenience_wrapper():
    async def fetch(method, url, *, timeout=10.0):
        v = _injected(url)
        return HttpResp(500 if "'" in v else 200, {}, "db error" if "'" in v else "ok", url)
    v = asyncio.run(confirm_finding(
        {"url": "http://t/x?id=1", "parameter": "id", "payload": "1'"}, fetch))
    assert v.is_real and v.signal == "status"


def test_reflection_alone_is_a_lead_not_real():
    # Generic reflection (a raw echo) is a strong LEAD, not is_real: an echo
    # inside an error message is not proof. The context-aware XSS re-check decides.
    def resp(url):
        return HttpResp(200, {}, f"echo {_injected(url)} end", url)
    v = _confirm(resp, {"url": "http://t/s?q=1", "parameter": "q",
                        "payload": "VIPERXYZ"})
    assert v.signal == "reflection" and v.reproduced
    assert not v.is_real and v.confidence == 0.49


def test_baseline_failure_fails_closed_even_with_attack_signal():
    # Baseline errors (None) but the attack reflects the payload -> must NOT
    # confirm: without a control response there is no valid differential.
    def resp(url):
        if "VIPERXYZ" in url:
            return HttpResp(200, {}, "echo VIPERXYZ end", url)
        return None                       # benign baseline fails
    v = _confirm(resp, {"url": "http://t/s?q=1", "parameter": "q",
                        "payload": "VIPERXYZ"})
    assert not v.is_real and "baseline" in v.reason


def test_min_confidence_is_floored_so_weak_signal_never_real():
    # Even if a caller lowers min_confidence, reflection (0.49) stays a lead.
    async def fetch(method, url, *, timeout=10.0):
        return HttpResp(200, {}, f"echo {_injected(url)} end", url)
    conf = ThreeGateConfirmer(fetch, min_confidence=0.1)
    v = asyncio.run(conf.confirm({"url": "http://t/s?q=1", "parameter": "q",
                                  "payload": "VIPERXYZ"}))
    assert not v.is_real and conf.min_confidence == 0.5


def test_transient_reflection_not_reproduced_is_lead():
    state = {"n": 0}
    def resp(url):
        body = "nothing"
        if "VIPERXYZ" in url:
            state["n"] += 1
            if state["n"] == 1:       # reflects only on the first attack hit
                body = "echo VIPERXYZ end"
        return HttpResp(200, {}, body, url)
    v = _confirm(resp, {"url": "http://t/s?q=1", "parameter": "q",
                        "payload": "VIPERXYZ"})
    assert not v.is_real and not v.reproduced
    assert v.confidence <= 0.3


def test_status_error_differential_is_real():
    def resp(url):
        v = _injected(url)
        if "'" in v:
            return HttpResp(500, {}, "db error", url)
        return HttpResp(200, {}, "ok", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1'"})
    assert v.is_real and v.signal == "status" and v.confidence == 0.80


def test_inert_server_no_signal():
    def resp(url):
        return HttpResp(200, {}, "constant body", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1'"})
    assert not v.is_real and v.signal is None


def test_marker_is_strongest_signal():
    def resp(url):
        body = "page"
        if "SLEEPME" in url:
            body = "page OOB-PROOF-123"
        return HttpResp(200, {}, body, url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "SLEEPME"}, marker="OOB-PROOF-123")
    assert v.is_real and v.signal == "marker" and v.confidence == 0.85


def test_timing_reproduced_is_real():
    # constant body/status -> only timing can fire. Fake clock: baseline fast,
    # both attack runs slow. Each _timed_get consumes 2 clock reads.
    seq = iter([0.0, 0.01,   # baseline  -> 0.01
                0.0, 1.0,    # attack    -> 1.0
                0.0, 1.0])   # re-test    -> 1.0
    def resp(url):
        return HttpResp(200, {}, "same", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1 AND SLEEP(5)"}, clock=lambda: next(seq))
    assert v.is_real and v.signal == "timing" and v.confidence == 0.60


def test_timing_not_reproduced_is_lead():
    seq = iter([0.0, 0.01,   # baseline -> 0.01
                0.0, 1.0,    # attack   -> 1.0 (slow)
                0.0, 0.0])   # re-test  -> 0.0 (fast: tarpit/jitter, not real)
    def resp(url):
        return HttpResp(200, {}, "same", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1 AND SLEEP(5)"}, clock=lambda: next(seq))
    assert not v.is_real and not v.reproduced and v.confidence <= 0.3


def test_missing_payload_is_insufficient():
    def resp(url):
        return HttpResp(200, {}, "x", url)
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id"})
    assert not v.is_real and "insufficient" in v.reason


def test_missing_parameter_is_insufficient():
    def resp(url):
        return HttpResp(200, {}, "x", url)
    v = _confirm(resp, {"url": "http://t/x", "payload": "1'"})
    assert not v.is_real and "parameter" in v.reason


def test_no_response_fails_closed():
    def resp(url):
        return None
    v = _confirm(resp, {"url": "http://t/x?id=1", "parameter": "id",
                        "payload": "1'"})
    assert not v.is_real and "baseline" in v.reason
