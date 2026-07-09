"""`viper.py evidence verify <manifest.json> [findings.json] [--key KEY]`

Verify a hunt's chain-of-custody evidence manifest. Two independent checks:

  * HASH INTEGRITY (needs the original findings): re-hash each finding with the same
    canonical SHA-256 the hunt used and cross-check it against the manifest's recorded
    hashes — so an operator can PROVE a finding they're about to submit (and its
    captured proof-request) matches exactly what the hunt confirmed. Any edit to a
    finding after the hunt changes its hash and shows up as UNVERIFIED.
  * HMAC SIGNATURE (needs the session key via --key): confirms the manifest itself
    wasn't altered. The key is minted per hunt and not persisted, so this is only
    available when the operator saved it; the hash check stands on its own.

Read-only; no network, no gate. Exit 0 iff every provided finding is accounted for in
the manifest (and, when --key is given, the signature is valid).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_evidence_cli(argv: List[str]) -> int:
    if not argv or argv[0] != "verify" or len(argv) < 2:
        print("usage: viper.py evidence verify <manifest.json> [findings.json] [--key KEY]")
        return 2
    args = argv[1:]
    key = None
    if "--key" in args:
        i = args.index("--key")
        key = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    manifest_path = args[0]
    findings_path = args[1] if len(args) > 1 else None

    from core.chain_of_custody import ChainOfCustody, hash_finding
    try:
        manifest = _load(manifest_path)
    except Exception as e:  # noqa: BLE001
        print(f"error: could not read manifest {manifest_path!r}: {e}")
        return 2
    entries = manifest.get("entries") or []
    recorded = {e.get("hash") for e in entries if isinstance(e, dict)}
    print(f"manifest: session={manifest.get('session_id') or '?'} "
          f"generated={manifest.get('generated_at') or '?'} "
          f"entries={len(entries)} signature={'present' if manifest.get('signature') else 'MISSING'}")

    ok = True

    if key is not None:
        coc = ChainOfCustody(session_key=key)
        sig_ok = coc.verify_manifest(manifest_path)
        print(f"HMAC signature: {'VALID' if sig_ok else 'INVALID — manifest altered or wrong key'}")
        ok = ok and sig_ok

    if findings_path:
        try:
            data = _load(findings_path)
        except Exception as e:  # noqa: BLE001
            print(f"error: could not read findings {findings_path!r}: {e}")
            return 2
        findings = data if isinstance(data, list) else (data.get("findings") or [])
        findings = [f for f in findings if isinstance(f, dict)]
        matched, tampered = [], []
        seen_hashes = set()
        for f in findings:
            h = hash_finding(f)
            (matched if h in recorded else tampered).append(f)
            seen_hashes.add(h)
        missing = recorded - seen_hashes           # in the manifest but not provided
        print(f"hash check: {len(matched)}/{len(findings)} finding(s) match the manifest")
        for f in tampered:
            print(f"  UNVERIFIED (not in manifest — edited or new): "
                  f"{(f.get('vuln_type') or f.get('type') or '?')} {f.get('url') or ''}".rstrip())
        if missing:
            print(f"  {len(missing)} manifest entr(ies) had no matching finding in the file")
        ok = ok and not tampered
    elif key is None:
        print("(pass a findings.json to re-verify each finding's hash, and/or --key for "
              "the HMAC signature)")

    print("RESULT:", "OK — evidence integrity verified" if ok else
          "FAILED — integrity could not be confirmed")
    return 0 if ok else 1
