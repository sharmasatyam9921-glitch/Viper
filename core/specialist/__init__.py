"""Specialist, human-style testing techniques for VIPER.

These are the high-value methods that automated scanners can't do because they
need *state* — multiple authenticated identities, multi-step flows, and
business-context reasoning. Currently:

  * bola_engine — two-account Broken Object Level Authorization (BOLA/IDOR)
    testing: capture one user's object references, replay them as a second
    user, and confirm cross-user data access. This is the #1 real bug-bounty
    class and the gold-standard manual methodology.
"""

from .bola_engine import Session, find_bola, id_bearing_urls

__all__ = ["Session", "find_bola", "id_bearing_urls"]
