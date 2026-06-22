"""Static APK secret/endpoint audit (dependency-free; an APK is a zip).

Scans every text-ish entry of the APK for hardcoded credentials (reusing VIPER's
secret scanner — full pattern set + entropy + placeholder filtering, so EXAMPLE/
placeholder keys are not flagged) and embedded backend/cloud endpoints (Firebase
DBs, cloud storage, Google API keys). Deterministic file analysis — a real key in
the APK IS the finding, so no HTTP re-test is needed.
"""
from __future__ import annotations

import logging
import re
import zipfile
from typing import List

logger = logging.getLogger("viper.mobile.apk_audit")

_MAX_ENTRY = 4_000_000          # cap bytes read per entry
# Binary assets unlikely to carry readable secrets — skip for speed.
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ttf", ".otf", ".woff",
             ".woff2", ".mp3", ".mp4", ".ogg", ".so", ".ico", ".bmp")
_FIREBASE = re.compile(r"https?://[a-z0-9.-]+\.firebaseio\.com", re.I)
_BACKENDS = re.compile(
    r"https?://[a-z0-9.-]+\.(?:appspot\.com|s3\.amazonaws\.com|"
    r"blob\.core\.windows\.net|storage\.googleapis\.com)\b", re.I)
# Canonical doc/placeholder keys are not real secrets (matched against the secret
# and its immediate context — word markers only, so a real key wrapped in XML
# tags is NOT filtered).
_PLACEHOLDER = re.compile(
    r"EXAMPLE|YOUR[_-]?(?:API|KEY|TOKEN|SECRET)|XXXX+|CHANGE[_-]?ME|PLACEHOLDER|"
    r"REDACTED|DUMMY|SAMPLE[_-]?KEY", re.I)


def audit_apk(path: str) -> List[dict]:
    """Return secret/endpoint findings for an APK at `path`. [] if unreadable."""
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:   # noqa: BLE001
        logger.warning("not a readable APK/zip: %s", exc)
        return []
    from core.secret_scanner import SecretScanner
    sc = SecretScanner(verbose=False)
    findings: List[dict] = []
    seen: set = set()

    def _add(f: dict):
        key = (f["vuln_type"], f["evidence"])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    with zf:
        for name in zf.namelist():
            if name.lower().endswith(_SKIP_EXT) or name.endswith("/"):
                continue
            try:
                data = zf.read(name)[:_MAX_ENTRY]
            except Exception:
                continue
            text = data.decode("utf-8", "ignore")
            # 1. hardcoded secrets (reuse the full FP-averse scanner)
            try:
                for sf in sc._scan_content(text, f"apk://{name}", name):
                    blob = ((getattr(sf, "match_preview", "") or "") + " "
                            + (getattr(sf, "context", "") or ""))
                    if _PLACEHOLDER.search(blob):
                        continue          # canonical EXAMPLE / placeholder key
                    stype = getattr(sf, "secret_type", "secret")
                    ent = getattr(sf, "entropy", 0.0)
                    _add({
                        "type": "mobile",
                        "vuln_type": f"mobile:hardcoded_secret:{stype}",
                        "title": f"Hardcoded {stype} in APK ({name})",
                        "severity": "high",
                        "url": f"apk://{name}",
                        "cwe": "CWE-798",
                        "confidence": 0.9,
                        "needs_manual_verification": True,
                        "evidence": f"a {stype} (entropy {ent:.1f}) is embedded in {name}",
                    })
            except Exception as exc:   # noqa: BLE001
                logger.debug("secret scan failed for %s: %s", name, exc)
            # 2. embedded backends (attack surface / data exposure). Hardcoded API
            #    keys (incl. Google AIza...) are already caught by the secret scanner.
            for m in _FIREBASE.finditer(text):
                _add(_endpoint_finding("firebase", m.group(0), name,
                                       "Firebase database URL", "CWE-200", "medium"))
            for m in _BACKENDS.finditer(text):
                _add(_endpoint_finding("backend", m.group(0), name,
                                       "embedded cloud backend", "CWE-200", "info"))
    return findings


def _endpoint_finding(kind, value, name, what, cwe, sev) -> dict:
    return {
        "type": "mobile",
        "vuln_type": f"mobile:{kind}",
        "title": f"{what} embedded in APK ({name})",
        "severity": sev,
        "url": f"apk://{name}",
        "cwe": cwe,
        "confidence": 0.7,
        "needs_manual_verification": True,
        "evidence": f"{what} {value[:80]} embedded in {name}",
    }
