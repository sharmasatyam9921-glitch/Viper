# VIPER Auto-Signup

End-to-end automation for the "give me two authenticated sessions to test
IDOR / BOLA" workflow that bug bounty hunters do constantly by hand.

## Components

```
core/temp_account.py    # Burner / aliased email providers + ROE table
core/auto_signup.py     # Playwright-driven signup form filler
core/account_pool.py    # Persistent pool of (label, email, cookie) tuples
core/bola_scanner.py    # BOLA / BFLA scanner consuming the pool
```

## Provider selection

`temp_account.ProviderRegistry.pick(rules)` decides which inbox provider to
use based on program rules:

| Program rule | Provider | Notes |
|---|---|---|
| `requires_owned_email=True` | `GmailAliasProvider` | uses real Gmail with `+alias`; reads via IMAP |
| `requires_owned_email=False` | `MailTmProvider` | mail.tm public API, no auth |

Known programs are listed in `temp_account._KNOWN_PROGRAMS`. Add new
entries as you encounter them.

## Setup

```bash
pip install playwright python-dotenv
playwright install chromium
```

In `.env`:

```ini
# For programs that allow disposable inboxes — nothing extra needed.

# For strict programs (Circle, Coinbase, etc):
GMAIL_USER=yourname@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx   # google.com/apppasswords (16 chars)

# Per-program signup password (each program may have different policy)
CIRCLE_SIGNUP_PASSWORD=Strong-pw-12+chars-with-symbols!
```

## Signup flow

```python
from core.auto_signup import AutoSignup, SignupPlan
from core.account_pool import AccountPool

plan = SignupPlan(
    program="circle-bbp",
    signup_url="https://app-sandbox.circle.com/signup",
    fields={
        "first_name": "viper",   # AutoSignup appends "_h1" per Circle rules
        "last_name": "ashborn",
        "company": "viper-research",
        "password": "redacted-strong-pw",
    },
    verify_subject_hint="verify",
    verify_link_contains="circle.com",
    post_verify_url_contains="app-sandbox.circle.com",
)

pool = AccountPool.load("circle-bbp")
result = AutoSignup(headless=False).run(plan, label="a")
pool.add_from_signup(result)
```

The `headless=False` default is intentional — keep the browser visible so
you can intervene on a captcha (which you must solve yourself; we don't
attempt to bypass).

## ROE enforcement

Before any signup, `AutoSignup._enforce_roe()` mutates the plan to satisfy
the program's `ProgramRules`:

* `requires_h1_marker=True` + `name_suffix="_h1"` → `"viper" → "viper_h1"`
  applied to `first_name` and `last_name` fields.
* `requires_owned_email=True` → forces `GmailAliasProvider`.

If the program isn't in the registry, default rules are permissive
(temp emails OK, no name suffix). Add explicit entries for strict programs.

## Captcha policy

We do **not** bypass captchas. If the signup form requires one, the browser
opens visibly and waits for you to solve it. The verification-link harvest
only starts after you've submitted the form.

## Downstream consumers

After signup, `state/auto_signup/<program>_pool.json` contains:

```json
{
  "program": "circle-bbp",
  "accounts": [
    {"label": "a", "email": "...", "storage_state": "...", "cookie_header": "...", "created_at": ...},
    {"label": "b", "email": "...", "storage_state": "...", "cookie_header": "...", "created_at": ...}
  ]
}
```

Harnesses read from the pool with `--from-pool` (idor_sweep) or by
calling `AccountPool.load(program)` directly (bola_scanner).

## Adding a new program

1. Edit `core/temp_account._KNOWN_PROGRAMS` with a `ProgramRules` entry.
2. Write a wrapper at `state/<program>/auth/<program>_signup.py` modelled
   on `state/bb_circle/auth/circle_signup.py`.
3. Run it. Iterate on selector hints in `auto_signup._selectors_for` if
   the form fields don't match defaults.

## Testing

```bash
python -m pytest tests/test_temp_account.py -v
```

11 unit tests cover the ROE table, provider selection, alias generation,
and link extraction. The Playwright integration is not unit-tested
(too brittle); integration tests would mock the browser.
