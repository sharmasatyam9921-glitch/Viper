"""Specialist, human-style testing techniques for VIPER.

These are the high-value methods that automated scanners can't do because they
need *state* — multiple authenticated identities, multi-step flows, and
business-context reasoning. Currently:

  * bola_engine — two-account Broken Object Level Authorization (BOLA/IDOR)
    testing: capture one user's object references, replay them as a second
    user, and confirm cross-user data access. This is the #1 real bug-bounty
    class and the gold-standard manual methodology.
  * temp_mail — disposable-mailbox provider (mail.tm) used to provision the two
    test accounts the BOLA flow needs: create throwaway inboxes and poll them
    for the verification email during an authorized engagement.
"""

from .bola_engine import Session, find_bola, id_bearing_urls
from .bola_runner import run_bola
from .burp_import import (
    BurpItem,
    load_burp,
    object_urls,
    parse_burp_xml,
    session_headers,
)
from .temp_mail import (
    MailTmProvider,
    TempMailbox,
    extract_links,
    new_mailbox,
    verification_link,
)

__all__ = [
    "Session", "find_bola", "id_bearing_urls", "run_bola",
    "BurpItem", "load_burp", "parse_burp_xml", "object_urls", "session_headers",
    "MailTmProvider", "TempMailbox", "new_mailbox",
    "extract_links", "verification_link",
]
