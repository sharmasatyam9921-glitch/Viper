"""Pure Active Directory attack-surface analysis over LDAP entries.

Each function takes a list of directory entries (dicts of LDAP attributes, as a
collector would return them) and returns finding dicts. No network — the live
LDAP collection is the operator's/relay's job against an authorized DC.

Entry attributes are read case-insensitively; multi-valued attrs may be a list or
a single value; ``userAccountControl`` may be int or str.
"""
from __future__ import annotations

from typing import Iterable, List

# userAccountControl bit flags.
UF_DONT_REQUIRE_PREAUTH = 0x400000      # AS-REP roastable
UF_TRUSTED_FOR_DELEGATION = 0x80000     # unconstrained delegation
UF_ACCOUNTDISABLE = 0x0002
# msPKI-Certificate-Name-Flag.
ENROLLEE_SUPPLIES_SUBJECT = 0x1
# EKUs that grant authentication.
_AUTH_EKUS = {"1.3.6.1.5.5.7.3.2",          # Client Authentication
              "1.3.6.1.5.2.3.4",            # PKINIT Client Authentication
              "2.5.29.37.0"}                 # Any Purpose


def _get(entry: dict, attr: str):
    low = attr.lower()
    for k, v in entry.items():
        if k.lower() == low:
            return v
    return None


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _uac(entry: dict) -> int:
    v = _get(entry, "userAccountControl")
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _name(entry: dict) -> str:
    return str(_get(entry, "sAMAccountName") or _get(entry, "cn")
               or _get(entry, "name") or _get(entry, "distinguishedName") or "?")


def _is_user(entry: dict) -> bool:
    oc = [str(x).lower() for x in _as_list(_get(entry, "objectClass"))]
    return "user" in oc and "computer" not in oc


def _f(vuln_type, name, severity, cwe, evidence) -> dict:
    return {"type": "ad", "vuln_type": vuln_type, "title": vuln_type.replace(":", " "),
            "severity": severity, "cwe": cwe, "principal": name,
            "confidence": 0.8, "needs_manual_verification": True, "evidence": evidence}


def kerberoastable(entries: Iterable[dict]) -> List[dict]:
    out = []
    for e in entries:
        if not _is_user(e) or _uac(e) & UF_ACCOUNTDISABLE:
            continue
        spns = [s for s in _as_list(_get(e, "servicePrincipalName")) if s]
        if spns:
            n = _name(e)
            out.append(_f(f"ad:kerberoastable:{n}", n, "medium", "CWE-262",
                          f"service account '{n}' exposes SPN(s) {spns[:3]} — its "
                          "password hash is offline-crackable (Kerberoasting)."))
    return out


def asrep_roastable(entries: Iterable[dict]) -> List[dict]:
    out = []
    for e in entries:
        if _is_user(e) and (_uac(e) & UF_DONT_REQUIRE_PREAUTH) \
                and not (_uac(e) & UF_ACCOUNTDISABLE):
            n = _name(e)
            out.append(_f(f"ad:asrep_roastable:{n}", n, "medium", "CWE-308",
                          f"user '{n}' does not require Kerberos pre-auth — an "
                          "AS-REP hash can be requested and cracked offline."))
    return out


def unconstrained_delegation(entries: Iterable[dict]) -> List[dict]:
    out = []
    for e in entries:
        if (_uac(e) & UF_TRUSTED_FOR_DELEGATION) and not (_uac(e) & UF_ACCOUNTDISABLE):
            n = _name(e)
            out.append(_f(f"ad:unconstrained_delegation:{n}", n, "high", "CWE-266",
                          f"'{n}' is trusted for UNCONSTRAINED delegation — it can "
                          "capture any authenticating user's TGT (path to Domain Admin)."))
    return out


def adcs_esc1(templates: Iterable[dict]) -> List[dict]:
    """ESC1: a cert template that lets a low-priv enrollee supply the subject AND
    has a client-auth EKU — request a cert as any user (incl. a Domain Admin)."""
    out = []
    privileged = ("domain admins", "enterprise admins", "authenticated users",
                  "domain users", "domain computers", "everyone")
    for t in templates:
        name_flag = _get(t, "msPKI-Certificate-Name-Flag")
        try:
            flag = int(name_flag)
        except (TypeError, ValueError):
            flag = 0
        ekus = {str(x) for x in _as_list(_get(t, "pkiExtendedKeyUsage"))}
        enrollers = {str(x).lower() for x in _as_list(_get(t, "enrollmentRights"))}
        low_priv_can_enroll = any(p in e for p in privileged for e in enrollers)
        if (flag & ENROLLEE_SUPPLIES_SUBJECT) and (ekus & _AUTH_EKUS) \
                and low_priv_can_enroll:
            n = str(_get(t, "name") or _get(t, "cn") or "?")
            out.append(_f(f"ad:adcs_esc1:{n}", n, "critical", "CWE-269",
                          f"certificate template '{n}' allows an enrollee-supplied "
                          "subject + client-auth EKU with low-privilege enrollment "
                          "(ESC1) — request a cert as any user and escalate to DA."))
    return out


def privileged_users(entries: Iterable[dict]) -> List[dict]:
    out = []
    for e in entries:
        groups = [str(g).lower() for g in _as_list(_get(e, "memberOf"))]
        if any("domain admins" in g or "enterprise admins" in g for g in groups):
            n = _name(e)
            out.append(_f(f"ad:privileged_user:{n}", n, "info", "CWE-266",
                          f"'{n}' is a member of a high-privilege group "
                          "(Domain/Enterprise Admins)."))
    return out


def analyze_directory(entries: Iterable[dict], templates: Iterable[dict] = ()) -> List[dict]:
    entries = list(entries)
    out: List[dict] = []
    out += kerberoastable(entries)
    out += asrep_roastable(entries)
    out += unconstrained_delegation(entries)
    out += adcs_esc1(list(templates))
    out += privileged_users(entries)
    return out
