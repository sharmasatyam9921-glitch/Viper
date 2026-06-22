"""Attack-path graph — FP-resistance is the focus of these tests."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.attack_path import find_paths  # noqa: E402


def _conf(vt, **kw):
    return {"vuln_type": vt, "submittable": True, "title": vt, **kw}


def _lead(vt, **kw):
    return {"vuln_type": vt, "submittable": False, "title": vt, **kw}


# --- grounding: never speculate without a confirmed finding ----------------

def test_no_confirmed_findings_yields_no_paths():
    assert find_paths([]) == []
    assert find_paths([_lead("ssrf"), _lead("sqli")]) == []   # leads don't ground


def test_lead_alone_never_creates_a_path():
    # an SSRF that is only a candidate must NOT produce a cloud-takeover path
    assert find_paths([_lead("ssrf:blind")]) == []


# --- fully-confirmed (no speculation) --------------------------------------

def test_confirmed_rce_is_a_fully_confirmed_critical_path():
    paths = find_paths([_conf("rce:cmdi")])
    rce = [p for p in paths if p.goal == "rce"]
    assert rce and rce[0].fully_confirmed
    assert rce[0].potential_hops == 0 and rce[0].confirmed_hops == 1
    assert all(h.kind == "confirmed" for h in rce[0].hops)


def test_confirmed_idor_fully_confirms_pii_read():
    paths = find_paths([_conf("idor")])
    pii = [p for p in paths if p.goal == "pii_read"]
    assert pii and pii[0].fully_confirmed


# --- partial: confirmed prefix, potential tail, clearly typed --------------

def test_confirmed_ssrf_is_partial_path_with_typed_potential_hops():
    paths = find_paths([_conf("ssrf:confirmed")])
    # SSRF grounds 'internal'; cloud takeover needs 2 potential hops
    ct = [p for p in paths if p.goal == "cloud_takeover"]
    assert ct, "expected a potential cloud-takeover path from confirmed SSRF"
    p = ct[0]
    assert not p.fully_confirmed
    assert p.confirmed_hops == 1 and p.potential_hops >= 1
    assert p.hops[0].kind == "confirmed" and p.hops[0].dst == "internal"
    assert any(h.kind == "potential" for h in p.hops)
    assert "[potential]" in p.narrative


def test_confirmed_secret_partial_path_to_account_takeover():
    paths = find_paths([_conf("secret:aws")])
    ato = [p for p in paths if p.goal == "account_takeover"]
    assert ato and not ato[0].fully_confirmed
    assert ato[0].hops[0].dst == "credentials" and ato[0].hops[0].kind == "confirmed"


# --- ranking + mixed evidence ----------------------------------------------

def test_fully_confirmed_ranks_above_partial():
    # confirmed RCE (fully-confirmed crit) + confirmed SSRF (partial crit)
    paths = find_paths([_conf("rce"), _conf("ssrf")])
    assert paths[0].fully_confirmed                      # the RCE path sorts first


def test_leads_mixed_with_confirmed_do_not_add_edges():
    # a confirmed SSRF + a LEAD sqli: the sqli must not create a db_access edge
    paths = find_paths([_conf("ssrf"), _lead("sqli")])
    # no path should traverse db_access (which only the lead sqli could ground)
    assert not any(any(h.dst == "db_access" for h in p.hops) for p in paths)
