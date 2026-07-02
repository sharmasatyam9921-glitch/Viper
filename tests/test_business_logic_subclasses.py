"""Business-logic subclass playbook (patterns + hot params per sub-flaw)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.payload_library import get_business_logic_subclasses  # noqa: E402
from core.logic_modeler import LogicModeler  # noqa: E402

_FILE = Path(__file__).resolve().parents[1] / "core" / "selfimprove" / "business_logic_subclasses.json"


def test_taxonomy_has_the_key_subflaws():
    subs = get_business_logic_subclasses()
    assert {"password_reset", "idor_horizontal", "privilege_escalation",
            "captcha_bypass", "credential_stuffing", "payment_tampering",
            "auth_bypass"} <= set(subs)
    for name, info in subs.items():
        assert info["patterns"] and info["params"]        # actionable content
        assert info["parent"] and info["severity"]


def test_password_reset_carries_reset_token_params():
    subs = get_business_logic_subclasses()
    assert "token" in subs["password_reset"]["params"]
    assert "coupon" in subs["payment_tampering"]["params"]
    assert "role" in subs["privilege_escalation"]["params"]


def test_playbook_exposed_via_logic_modeler():
    assert LogicModeler.subclass_playbook()["captcha_bypass"]["parent"] == "auth_bypass"


def test_file_is_pii_free_knowledge_only():
    blob = json.loads(_FILE.read_text(encoding="utf-8"))
    s = json.dumps(blob).lower()
    # taxonomy + params + pattern prose only — no payloads / creds / case ids
    assert "password:" not in s and "http" not in s.replace("https", "")
    import re
    assert not re.search(r"[a-z]+-20\d\d-\d", s)
