"""
Pool of authenticated sessions for VIPER. Persists Playwright storage_state
JSONs and exposes them as ready-to-use cookie headers for downstream
harnesses (idor_sweep, bola_scanner).

State files live under state/auto_signup/<program>_<label>.json
(written by AutoSignup). The pool also caches a manifest at
state/auto_signup/<program>_pool.json:

    {
      "program": "circle-bbp",
      "accounts": [
        {"label": "a", "email": "...+circle_a-abc@gmail.com",
         "storage_state": "state/auto_signup/circle-bbp_a.json",
         "created_at": 1730000000.0},
        ...
      ]
    }

Cookies expire — `validate(rule)` walks the manifest and removes accounts
whose stored cookies no longer authenticate.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .auto_signup import AutoSignup, SignupPlan, SignupResult


@dataclass
class StoredAccount:
    label: str
    email: str
    storage_state: str
    cookie_header: str = ""
    created_at: float = 0.0
    metadata: dict = field(default_factory=dict)
    roe_compliant: bool = True  # False if signed up with provider-override


@dataclass
class AccountPool:
    program: str
    state_dir: Path = Path("state/auto_signup")
    accounts: list[StoredAccount] = field(default_factory=list)

    @classmethod
    def load(cls, program: str, state_dir: Path | None = None) -> "AccountPool":
        sd = state_dir or Path("state/auto_signup")
        sd.mkdir(parents=True, exist_ok=True)
        manifest = sd / f"{program}_pool.json"
        if manifest.exists():
            data = json.loads(manifest.read_text())
            return cls(
                program=program, state_dir=sd,
                accounts=[StoredAccount(**a) for a in data.get("accounts", [])],
            )
        return cls(program=program, state_dir=sd)

    def save(self) -> None:
        manifest = self.state_dir / f"{self.program}_pool.json"
        manifest.write_text(json.dumps({
            "program": self.program,
            "accounts": [asdict(a) for a in self.accounts],
        }, indent=2))

    def add_from_signup(self, result: SignupResult, *,
                        roe_compliant: bool = True) -> None:
        if not result.success:
            raise RuntimeError(f"Cannot add failed signup: {result.error}")
        # Replace by label if exists.
        self.accounts = [a for a in self.accounts if a.label != result.label]
        self.accounts.append(StoredAccount(
            label=result.label,
            email=result.email,
            storage_state=result.storage_state_path,
            cookie_header=result.cookie_header,
            created_at=time.time(),
            roe_compliant=roe_compliant,
        ))
        self.save()

    def get(self, label: str) -> StoredAccount | None:
        for a in self.accounts:
            if a.label == label:
                return a
        return None

    def ensure(
        self, label: str, plan_factory: Callable[[], SignupPlan],
        *, validator: Callable[[StoredAccount], bool] | None = None,
        signup: AutoSignup | None = None,
    ) -> StoredAccount:
        """
        Return an existing valid account for `label`, or create one.

        validator: optional fn that takes a StoredAccount and returns True if
        the cookie still authenticates. If not provided, no validation.
        """
        existing = self.get(label)
        if existing and (validator is None or validator(existing)):
            return existing
        if existing:
            self.accounts.remove(existing)
        plan = plan_factory()
        result = (signup or AutoSignup()).run(plan, label=label)
        self.add_from_signup(result)
        added = self.get(label)
        assert added is not None
        return added

    def authenticated_pair(self, validator: Callable[[StoredAccount], bool] | None = None
                           ) -> tuple[StoredAccount, StoredAccount]:
        """Return (a, b) pair, raising if either is missing/invalid."""
        a = self.get("a")
        b = self.get("b")
        if not a or not b:
            raise RuntimeError(
                f"Pool missing accounts. Have labels: "
                f"{[acc.label for acc in self.accounts]}"
            )
        if validator and (not validator(a) or not validator(b)):
            raise RuntimeError("One or both accounts have expired cookies.")
        return a, b
