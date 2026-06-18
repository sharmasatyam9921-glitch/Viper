"""False-positive regression tests for the LFI swarm worker.

Audit scenario (confirmed FP): a non-vulnerable Linux/sysadmin knowledge-base
search endpoint whose `file` param is a FULL-TEXT DOC SEARCH, not a filesystem
read. The KB corpus contains a tutorial article "Understanding /etc/passwd" whose
body shows the canonical line ``root:x:0:0:root:/root:/bin/bash``. The benign
control value ``index`` matches a generic getting-started article (no passwd
line, so the baseline guard does NOT skip the param). The LFI payload
``../../../../../../../../etc/passwd`` full-text-matches the passwd tutorial and
the page reflects that benign documentation snippet — no file is ever read off
disk. The old single-substring match flagged it as LFI.

The hardened worker adds a SECOND, keyword-only control (the trigger keyword
WITHOUT traversal). If that keyword control ALSO returns the signature, the
endpoint is keyword/search-driven and the param is skipped.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.swarm_workers  # noqa: F401
from core.swarm_engine import SwarmAgent
from core.swarm_workers import get_worker_runner
from core.swarm_workers.vuln._http import HttpResp


def _agent(target="http://127.0.0.1/kb/search?file=index", timeout=5.0):
    return SwarmAgent(
        agent_id="t", objective="x", target=target,
        technique="lfi", payload={}, timeout_s=timeout,
    )


def _run(fake, agent=None):
    async def go():
        with patch("core.swarm_workers.vuln.lfi.fetch", side_effect=fake):
            return await get_worker_runner("vuln", "lfi")(agent or _agent())
    return asyncio.run(go())


# The canonical line a /etc/passwd tutorial article would display.
_PASSWD_TUTORIAL_LINE = "root:x:0:0:root:/root:/bin/bash"


def _kb_search_value(url):
    """Extract the raw `file` search term from a KB-search URL."""
    from urllib.parse import urlsplit, parse_qs, unquote
    qs = parse_qs(urlsplit(url).query)
    raw = qs.get("file", [""])[0]
    # tolerate %2f / ....// style encodings: decode then strip traversal noise
    return unquote(raw)


# --- (a) the confirmed false positive ---------------------------------------

def test_kb_search_doc_echo_false_positive_not_flagged():
    """Full-text doc-search endpoint that echoes a passwd-tutorial line.

    This is the audit's confirmed FP. The endpoint is keyword-driven: any search
    term whose text appears in the corpus surfaces the matching article. The
    string ``etc/passwd`` matches a tutorial whose body shows ONE canonical
    passwd line — there is no filesystem read. Pre-fix the worker flagged it;
    post-fix the second keyword-only control unmasks the search behavior and the
    param is skipped.
    """

    def article_for(term):
        t = term.lower()
        # Full-text doc search over the corpus. The "Understanding /etc/passwd"
        # tutorial article is indexed under several terms — its title and body
        # mention "etc", "passwd", and the full "/etc/passwd" path — so ANY of
        # those search terms (including the bare topical keyword "etc") surface
        # it. This is exactly why a single substring match is unsafe here.
        if any(kw in t for kw in ("etc", "passwd")):
            return (
                "<html><body><h1>Understanding /etc/passwd</h1>"
                "<p>Each line maps a user account. Example:</p>"
                f"<pre>{_PASSWD_TUTORIAL_LINE}</pre>"
                "<p>The fields are name:password:UID:GID:gecos:home:shell.</p>"
                "</body></html>"
            )
        # Generic getting-started article for `index` (no passwd line).
        return (
            "<html><body><h1>Getting started</h1>"
            "<p>Welcome to the knowledge base. Browse our articles.</p>"
            "</body></html>"
        )

    async def fake(method, url, **kw):
        term = _kb_search_value(url)
        return HttpResp(200, {"content-type": "text/html"}, article_for(term), url)

    findings = _run(fake)
    assert findings == [], (
        "knowledge-base doc-search endpoint must NOT be flagged as LFI: "
        f"got {findings!r}"
    )


# --- (b) genuine LFI still fires --------------------------------------------

def test_real_passwd_read_true_positive_still_fires():
    """A genuinely vulnerable endpoint that reads the real /etc/passwd off disk.

    The traversal payload returns a STRUCTURALLY-real passwd file (multiple
    distinct accounts with monotonic UIDs and valid shells). Crucially, the
    keyword-only control (``etc/passwd`` with NO traversal) does NOT read a file
    — it 404s / returns the app's normal page — so the worker can prove the
    signature is traversal-specific and still reports the finding.
    """
    real_passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    )

    async def fake(method, url, **kw):
        term = _kb_search_value(url)
        # Only an actual path-traversal sequence reads the real file off disk.
        if "../" in term or "..%2f" in url.lower() or "....//" in term:
            if "etc/passwd" in term.lower():
                return HttpResp(200, {"content-type": "text/plain"}, real_passwd, url)
            if "win.ini" in term.lower():
                return HttpResp(
                    200, {"content-type": "text/plain"},
                    "; for 16-bit app support\n[fonts]\n[extensions]\nfoo=bar\n", url,
                )
        # Keyword-only control or benign value: normal app page, no file read.
        return HttpResp(200, {"content-type": "text/html"},
                        "<html><body>file not found</body></html>", url)

    findings = _run(_run_fake := fake)
    assert findings, "expected a real LFI finding for an actual /etc/passwd read"
    f = findings[0]
    assert f["cwe"] == "CWE-22"
    assert f["vuln_type"].startswith("lfi:")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
