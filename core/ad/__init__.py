"""Active Directory attack-surface analysis (offline, fixture-verifiable).

``analyze_directory`` takes LDAP directory entries (collected by the operator /
the relay against an AUTHORIZED Domain Controller — that live collection needs a
DC and is out of scope here) and flags the classic escalation surface:
Kerberoastable SPNs, AS-REP-roastable accounts, unconstrained delegation, ADCS
ESC1 templates, and privileged-group membership. The ANALYSIS is pure and
deterministic, so it is unit-tested against fixture entries; only the live LDAP
collection requires an AD lab (e.g. GOAD).
"""
from __future__ import annotations

from .analyze import (  # noqa: F401
    adcs_esc1,
    analyze_directory,
    asrep_roastable,
    kerberoastable,
    privileged_users,
    unconstrained_delegation,
)
