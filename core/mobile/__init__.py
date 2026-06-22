"""Mobile app analysis (dependency-free static checks).

``apk_audit`` opens an APK (a zip) and scans every entry for hardcoded secrets and
embedded cloud/backend endpoints — the high-value, tool-free MASTG checks
(M10 hardcoded secrets, exposed backends). Full decompilation (jadx) and binary
AndroidManifest parsing (androguard) are out of scope here and degrade gracefully.
"""
from __future__ import annotations

from .apk_audit import audit_apk  # noqa: F401
