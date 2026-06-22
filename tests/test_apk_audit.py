"""Static APK secret/endpoint audit (dependency-free; APK = zip)."""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mobile.apk_audit import audit_apk  # noqa: E402

# A real-shaped AWS key (high entropy, not a placeholder) — test fixture only.
_AWS = "AKIA2E0K8Z9QXVB7N3RT"
_FB = "https://acme-prod.firebaseio.com"
_GKEY = "AIzaSyB1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456"


def _make_apk(tmp_path, files: dict) -> str:
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return str(p)


def test_audit_finds_hardcoded_secret_and_endpoints(tmp_path):
    apk = _make_apk(tmp_path, {
        "res/values/strings.xml": f'<resources><string name="k">{_AWS}</string>'
                                  f'<string name="db">{_FB}</string></resources>',
        "assets/config.json": f'{{"gmaps":"{_GKEY}"}}',
        "res/drawable/logo.png": b"\x89PNG\r\n\x1a\n binary junk",   # skipped
    })
    out = audit_apk(apk)
    vts = {f["vuln_type"] for f in out}
    assert "mobile:hardcoded_secret:aws_access_key" in vts
    assert "mobile:hardcoded_secret:google_api_key" in vts   # caught by secret scanner
    assert "mobile:firebase" in vts
    # nothing attributed to the skipped binary asset
    assert not any("logo.png" in f["evidence"] for f in out)


def test_clean_apk_has_no_findings(tmp_path):
    apk = _make_apk(tmp_path, {
        "res/values/strings.xml": "<resources><string name=\"app\">Acme</string></resources>",
        "classes.dex": b"dex\n035\x00 harmless bytes",
    })
    assert audit_apk(apk) == []


def test_placeholder_key_is_not_flagged(tmp_path):
    apk = _make_apk(tmp_path, {
        "assets/example.env": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nAPI=YOUR_API_KEY_HERE",
    })
    out = audit_apk(apk)
    assert not any(v.startswith("mobile:hardcoded_secret") for v in
                   {f["vuln_type"] for f in out})


def test_unreadable_file_returns_empty(tmp_path):
    p = tmp_path / "not.apk"
    p.write_text("definitely not a zip", encoding="utf-8")
    assert audit_apk(str(p)) == []
