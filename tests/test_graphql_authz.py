"""Enhancement: GraphQL FIELD-LEVEL AUTHORIZATION (BOLA/BFLA over GraphQL) — a new
gate-confirmed class. Opt-in + two-identity: the operator supplies a read-only query that
returns their own private data; the gate confirms a bypass only when the owner's private
marker appears for the owner AND a different attacker identity, but NOT anonymously (public
data is not a bypass). Stays a lead without two sessions. Read-only — mutations refused."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_engine import SwarmAgent  # noqa: E402
from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln import graphql as gql  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402

_M = "alice@victim.io"
_CFG = {"owner_headers": {"Cookie": "s=alice"}, "attacker_headers": {"Cookie": "s=bob"},
        "owner_markers": [_M]}
_QUERY = "{ user(id:1){ email } }"
_DATA = '{"data":{"user":{"email":"%s"}}}' % _M
_NULL = '{"data":{"user":null}}'


def _candidate():
    return {"type": "graphql_authz", "vuln_type": "graphql_authz",
            "url": "http://t/graphql", "graphql_query": _QUERY, "severity": "high"}


def _gate(mode):
    async def fetch(method, url, *, headers=None, body=None, timeout=10, **kw):
        c = (headers or {}).get("Cookie", "")
        if mode == "bypass":
            has = "s=alice" in c or "s=bob" in c
        elif mode == "ok":
            has = "s=alice" in c
        else:  # public
            has = True
        return HttpResp(200, {}, _DATA if has else _NULL, url)
    return fetch


def test_confirmed_when_attacker_reads_owner_field():
    out = asyncio.run(validate_findings([_candidate()], bola_config=_CFG,
                                        default_target="http://t/", fetch=_gate("bypass")))
    assert out[0]["submittable"] is True
    assert "authorization bypass" in out[0]["validation_reason"]


def test_lead_when_authz_holds():
    out = asyncio.run(validate_findings([_candidate()], bola_config=_CFG,
                                        default_target="http://t/", fetch=_gate("ok")))
    assert not out[0]["submittable"]


def test_lead_when_field_is_public():
    out = asyncio.run(validate_findings([_candidate()], bola_config=_CFG,
                                        default_target="http://t/", fetch=_gate("public")))
    assert not out[0]["submittable"]
    assert "public" in out[0]["validation_reason"]


def test_lead_without_two_account_config():
    out = asyncio.run(validate_findings([_candidate()], default_target="http://t/",
                                        fetch=_gate("bypass")))
    assert not out[0]["submittable"]


def test_mutation_is_refused():
    f = _candidate()
    f["graphql_query"] = "mutation { deleteUser(id:1) }"
    out = asyncio.run(validate_findings([f], bola_config=_CFG, default_target="http://t/",
                                        fetch=_gate("bypass")))
    assert not out[0]["submittable"]
    assert "mutation" in out[0]["validation_reason"]


# --- worker emits the opt-in candidate only when the operator supplies a query -----------
def test_worker_emits_candidate_on_operator_query():
    async def fake_probe(base, path, timeout):
        return [{"type": "graphql_introspection", "vuln_type": "graphql_introspection:/graphql",
                 "url": base + path, "severity": "medium"}]

    agent = SwarmAgent(agent_id="t", objective="x", target="http://t/", technique="graphql",
                       payload={"graphql_query": _QUERY}, timeout_s=6.0)
    with patch.object(gql, "_probe_path", fake_probe):
        out = asyncio.run(gql.run(agent))
    authz = [f for f in out if f["vuln_type"] == "graphql_authz"]
    assert authz and authz[0]["graphql_query"] == _QUERY


def test_worker_no_candidate_without_operator_query():
    async def fake_probe(base, path, timeout):
        return [{"type": "graphql_introspection", "vuln_type": "graphql_introspection:/graphql",
                 "url": base + path, "severity": "medium"}]

    agent = SwarmAgent(agent_id="t", objective="x", target="http://t/", technique="graphql",
                       payload={}, timeout_s=6.0)
    with patch.object(gql, "_probe_path", fake_probe):
        out = asyncio.run(gql.run(agent))
    assert not any(f["vuln_type"] == "graphql_authz" for f in out)


def test_lead_when_authz_error_echoes_marker_but_returns_no_data():
    # Adversarial FP: attacker's authZ error message echoes the marker (GraphQL errors are
    # HTTP 200) but no data crossed identities -> must stay a LEAD (marker matched only in
    # non-null `data`).
    async def fetch(method, url, *, headers=None, body=None, timeout=10, **kw):
        c = (headers or {}).get("Cookie", "")
        if "s=alice" in c:
            return HttpResp(200, {}, _DATA, url)
        return HttpResp(200, {},
                        '{"errors":[{"message":"Not authorized to access %s"}],"data":null}' % _M,
                        url)
    out = asyncio.run(validate_findings([_candidate()], bola_config=_CFG,
                                        default_target="http://t/", fetch=fetch))
    assert not out[0]["submittable"]


def test_lead_when_marker_is_reflected_from_the_query():
    # If the marker appears in the query itself, an error echo could false-confirm -> lead.
    f = _candidate()
    f["graphql_query"] = '{ user(email:"%s"){ ssn } }' % _M   # marker IS in the query
    out = asyncio.run(validate_findings([f], bola_config=_CFG, default_target="http://t/",
                                        fetch=_gate("bypass")))
    assert not out[0]["submittable"]
    assert "query itself" in out[0]["validation_reason"]
