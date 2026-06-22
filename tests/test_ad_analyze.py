"""Active Directory attack-surface analysis (offline, fixture-verified)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ad import analyze_directory  # noqa: E402
from core.ad.analyze import (  # noqa: E402
    adcs_esc1,
    asrep_roastable,
    kerberoastable,
    unconstrained_delegation,
)


def _user(name, **attrs):
    e = {"sAMAccountName": name, "objectClass": ["top", "person", "user"]}
    e.update(attrs)
    return e


def test_kerberoastable_requires_spn_and_enabled():
    svc = _user("svc_sql", servicePrincipalName=["MSSQL/db01"], userAccountControl=512)
    disabled = _user("svc_old", servicePrincipalName=["HTTP/x"], userAccountControl=514)
    plain = _user("alice", userAccountControl=512)
    out = kerberoastable([svc, disabled, plain])
    assert len(out) == 1 and out[0]["principal"] == "svc_sql"


def test_asrep_roastable_flag():
    u = _user("bob", userAccountControl=0x400000 | 512)
    assert asrep_roastable([u, _user("c", userAccountControl=512)])[0]["principal"] == "bob"


def test_unconstrained_delegation_flag():
    c = {"sAMAccountName": "WEB01$", "objectClass": ["computer"],
         "userAccountControl": 0x80000 | 4096}
    out = unconstrained_delegation([c])
    assert out and out[0]["severity"] == "high"


def test_adcs_esc1_requires_all_conditions():
    vuln = {"name": "VulnTemplate", "msPKI-Certificate-Name-Flag": 0x1,
            "pkiExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "enrollmentRights": ["CORP\\Domain Users"]}
    # missing client-auth EKU -> not ESC1
    safe = {"name": "Safe", "msPKI-Certificate-Name-Flag": 0x1,
            "pkiExtendedKeyUsage": ["1.3.6.1.4.1.311.20.2.2"],
            "enrollmentRights": ["CORP\\Domain Users"]}
    # subject not enrollee-supplied -> not ESC1
    safe2 = {"name": "Safe2", "msPKI-Certificate-Name-Flag": 0x0,
             "pkiExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
             "enrollmentRights": ["CORP\\Domain Users"]}
    out = adcs_esc1([vuln, safe, safe2])
    assert len(out) == 1 and out[0]["severity"] == "critical"
    assert out[0]["principal"] == "VulnTemplate"


def test_analyze_directory_combines():
    entries = [
        _user("svc", servicePrincipalName=["HTTP/a"], userAccountControl=512),
        _user("noauth", userAccountControl=0x400000 | 512),
        _user("admin", memberOf=["CN=Domain Admins,CN=Users,DC=corp"], userAccountControl=512),
    ]
    out = analyze_directory(entries)
    vts = {f["vuln_type"].split(":")[1] for f in out}
    assert {"kerberoastable", "asrep_roastable", "privileged_user"} <= vts
    assert all(f["type"] == "ad" for f in out)
