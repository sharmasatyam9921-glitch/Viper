"""Cloud storage exposure worker + gate re-check (HTTP, no cloud SDK)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.swarm_validation import validate_findings  # noqa: E402
from core.swarm_workers.vuln._http import HttpResp  # noqa: E402
from core.swarm_workers.vuln.cloud_exposure import classify, run as ce_run  # noqa: E402

_PUBLIC_S3 = ('<?xml version="1.0"?><ListBucketResult '
              'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>acme-backups'
              '</Name><Contents><Key>prod-db.sql</Key></Contents></ListBucketResult>')
_PRIVATE = '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>'
_AZURE = ('<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>secret.txt'
          '</Name></Blob></Blobs></EnumerationResults>')
_NOSUCH = '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>'


class _Agent:
    def __init__(self, t):
        self.target = t
        self.timeout_s = 8.0
        self.payload = {}


def _fetch(body, status=200):
    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        return HttpResp(status, {}, body, url)
    return fake


def test_classify_distinguishes_exposure_types():
    assert classify(HttpResp(200, {}, _PUBLIC_S3, ""))[0] == "public_bucket_listing"
    assert classify(HttpResp(200, {}, _AZURE, ""))[0] == "azure_public_container"
    assert classify(HttpResp(404, {}, _NOSUCH, ""))[0] == "bucket_takeover"
    assert classify(HttpResp(403, {}, _PRIVATE, "")) is None      # private -> nothing
    assert classify(HttpResp(200, {}, "<html>welcome</html>", "")) is None


def test_worker_flags_public_bucket(monkeypatch):
    from core.swarm_workers.vuln import cloud_exposure as mod
    monkeypatch.setattr(mod, "fetch", _fetch(_PUBLIC_S3, 200))
    out = asyncio.run(ce_run(_Agent("http://acme-backups.s3.amazonaws.com/")))
    assert len(out) == 1 and out[0]["vuln_type"] == "cloud_exposure:public_bucket_listing"


def test_worker_no_finding_on_private(monkeypatch):
    from core.swarm_workers.vuln import cloud_exposure as mod
    monkeypatch.setattr(mod, "fetch", _fetch(_PRIVATE, 403))
    assert asyncio.run(ce_run(_Agent("http://x.s3.amazonaws.com/"))) == []


def test_gate_confirms_public_bucket():
    f = {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"}
    out = asyncio.run(validate_findings([f], fetch=_fetch(_PUBLIC_S3)))
    assert out[0]["submittable"] and out[0]["validation_confidence"] == 0.85


def test_gate_rejects_now_private_bucket():
    f = {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"}
    out = asyncio.run(validate_findings([f], fetch=_fetch(_PRIVATE, 403)))
    assert not out[0]["submittable"]
