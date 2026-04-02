# Pre-Commit Checklist

MANDATORY: Run through this checklist BEFORE every `git commit`. Do NOT skip any step.

## 1. Secret Scan

```bash
git diff --cached -U0 | grep -iE '(sk-[a-zA-Z0-9]{20}|ghp_|AKIA|xoxb-|password\s*=\s*["\x27][^"\x27]{8}|api_key\s*=\s*["\x27]|sharma\.satyam|@gmail\.com|@wearehackerone|viperpass|TestPassword|webhook\.discord|hooks\.slack)'
```

If ANY match is a real credential (not a regex pattern or placeholder), **STOP and remove it**.

## 2. No Sensitive Files

These must NEVER be staged:

- `.env`, `.env.*` — environment secrets
- `credentials/` — platform passwords
- `programs/targets.json` — real target domains
- `recon/*_targets.txt`, `recon/*_subs.txt` — target lists
- `data/*_hunt_results.json` — hunt data with findings
- `CLAUDE.local.md` — local config with API paths
- `scopes/` — platform scope files
- `archive/hunt_sessions/` — may contain hardcoded creds

Run: `git diff --cached --name-only | grep -iE '(\.env|credentials/|targets\.json|_targets\.txt|_subs\.txt|hunt_results|CLAUDE\.local|scopes/|hunt_sessions/)'`

If any match, **unstage them**: `git reset HEAD <file>`

## 3. Import Verification

```bash
python -c "from viper_core import ViperCore; print('OK')"
```

Must print `OK`. If it fails, do NOT commit.

## 4. Test Suite

```bash
python -m pytest tests/ -x --tb=short -q
```

Must show `N passed, 0 failed`. If any test fails, fix before committing.

## 5. No Broken References

After archiving or deleting files, verify nothing imports them:

```bash
git diff --cached --name-only --diff-filter=D | while read f; do
  base=$(basename "$f" .py)
  grep -r "import $base\|from.*$base" --include="*.py" . | grep -v __pycache__ | grep -v archive/
done
```

If any imports reference deleted files, fix them first.

## 6. Commit Message Standards

- First line: imperative mood, <72 chars (e.g., "Fix X", "Add Y", not "Fixed X" or "Adding Y")
- Body: explain WHY, not WHAT (the diff shows what)
- End with: `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`
- Use HEREDOC format for multi-line messages

## 7. No Third-Party References

```bash
git diff --cached -U0 | grep -iE '(redamon|pentagi|redteam-agent)'
```

VIPER is an original project. Never reference, attribute, or name third-party tools/repos in code, comments, docstrings, or commit messages. If found, **rewrite to describe the feature generically**.

## 8. Push Confirmation

Always ask the user before `git push`. Never auto-push.
