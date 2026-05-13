"""Post-exploit phase workers.

  flag_hunter       Web-page + filesystem flag pattern grep
                    (the only non-gated worker — runs even without
                    a confirmed foothold, useful for web CTFs)
  linpeas           Wrap pentest privesc helpers for Linux footholds
  windows_privesc   Wrap pentest privesc helpers for Windows footholds
  ad_enum           Active Directory enumeration after creds
  gtfobins          SUID / sudo binary -> escalation lookup

All workers except `flag_hunter` are gated by the coordinator's
approval check.
"""

from __future__ import annotations

from . import (  # noqa: F401
    ad_enum,
    flag_hunter,
    gtfobins,
    linpeas,
    windows_privesc,
)

__all__ = [
    "ad_enum", "flag_hunter", "gtfobins", "linpeas", "windows_privesc",
]
