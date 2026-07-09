"""HAR / Postman collection import (read-only, operator-supplied).

An operator who has already exercised an authenticated API — in their browser
(DevTools -> "Save all as HAR") or in Postman (export a v2.1 collection) — holds the
richest endpoint + parameter map there is: one no unauthenticated crawler can reproduce.
This module turns that export into an :class:`ImportedSurface` the confirmed vuln workers
can probe (endpoints + query/body param NAMES), folded into a hunt exactly like the
authenticated-crawl surface.

SECRET-HANDLING BOUNDARY — strictly read-only and NON-SENSITIVE:
  * it extracts request URLs, query/body PARAMETER NAMES, and request-header NAMES only;
  * header and cookie VALUES (which carry the operator's auth tokens / session) are NEVER
    read into the surface or persisted — authentication stays with the operator's existing
    session config, not a file VIPER writes; and
  * the caller scopes the surface to the in-scope host (:meth:`ImportedSurface.scoped`)
    before use, so importing a whole browsing session can't drag out-of-scope hosts into a
    hunt.

Dependency-free (json + urllib + re); never raises on malformed input — returns an empty
surface instead.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger("viper.har_import")

# Header names whose VALUES we must never persist (auth/session material). We still record
# the NAME (knowing the API expects e.g. X-Api-Key is useful) — only the value is dropped,
# which this module does unconditionally for every header.
_SENSITIVE_HEADER = re.compile(
    r"^(authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|"
    r"proxy-authorization|www-authenticate)$", re.I)

_ENDPOINT_CAP, _PARAM_CAP, _HEADER_CAP = 500, 300, 120


def _norm_host(netloc: str) -> str:
    """Lowercase host without a default port (so example.com:443 == example.com)."""
    netloc = (netloc or "").lower()
    if netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif netloc.endswith(":443"):
        netloc = netloc[:-4]
    return netloc


@dataclass
class ImportedSurface:
    endpoints: List[str] = field(default_factory=list)   # full URLs (query kept for mining)
    params: Set[str] = field(default_factory=set)        # query + body param names
    header_names: Set[str] = field(default_factory=set)  # request header NAMES (values dropped)
    _seen: Set[str] = field(default_factory=set, repr=False)

    def add_endpoint(self, url: str) -> None:
        if not url or not isinstance(url, str):
            return
        p = urlsplit(url)
        if not p.scheme.startswith("http"):
            return
        clean = url.split("#", 1)[0]
        for k in parse_qs(p.query).keys():
            if len(self.params) < _PARAM_CAP:
                self.params.add(k)
        if clean not in self._seen and len(self.endpoints) < _ENDPOINT_CAP:
            self._seen.add(clean)
            self.endpoints.append(clean)

    def add_param(self, name: str) -> None:
        s = (name or "").strip()
        if s and len(s) <= 64 and len(self.params) < _PARAM_CAP:
            self.params.add(s)

    def add_header_name(self, name: str) -> None:
        s = (name or "").strip()
        if s and len(self.header_names) < _HEADER_CAP:
            self.header_names.add(s)

    def hosts(self) -> Set[str]:
        return {_norm_host(urlsplit(u).netloc) for u in self.endpoints}

    def scoped(self, host: str) -> "ImportedSurface":
        """A copy keeping only endpoints on `host` (exact host match). Params/header names
        are host-agnostic surface, so they carry over unchanged."""
        h = str(host or "")
        want = _norm_host(urlsplit(h if "//" in h else "//" + h).netloc)
        out = ImportedSurface(params=set(self.params), header_names=set(self.header_names))
        for u in self.endpoints:
            if _norm_host(urlsplit(u).netloc) == want:
                out.add_endpoint(u)
        return out


def _record_header_names(headers, surf: ImportedSurface) -> None:
    """headers: list of {name/key: ...}. Only the NAME is taken; the value is ignored."""
    if not isinstance(headers, list):
        return
    for h in headers:
        if isinstance(h, dict):
            surf.add_header_name(h.get("name") or h.get("key") or "")


def parse_har(obj: dict) -> ImportedSurface:
    surf = ImportedSurface()
    try:
        entries = obj.get("log", {}).get("entries", [])
    except AttributeError:
        return surf
    if not isinstance(entries, list):
        return surf
    for e in entries:
        if not isinstance(e, dict):
            continue
        req = e.get("request") or {}
        if not isinstance(req, dict):
            continue
        surf.add_endpoint(req.get("url") or "")
        for qs in (req.get("queryString") or []):
            if isinstance(qs, dict):
                surf.add_param(qs.get("name") or "")
        post = req.get("postData") or {}
        if isinstance(post, dict):
            for pp in (post.get("params") or []):
                if isinstance(pp, dict):
                    surf.add_param(pp.get("name") or "")
        _record_header_names(req.get("headers"), surf)
    return surf


def _postman_url(url) -> str:
    """A Postman `request.url` is a raw string OR {raw, host[], path[], query[{key}]}."""
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        raw = url.get("raw")
        if isinstance(raw, str) and raw:
            return raw
        host = url.get("host")
        path = url.get("path")
        host_s = ".".join(host) if isinstance(host, list) else (host or "")
        path_s = "/".join(str(x) for x in path) if isinstance(path, list) else (path or "")
        if host_s:
            scheme = "https://"
            return f"{scheme}{host_s}/{path_s}"
    return ""


def parse_postman(obj: dict) -> ImportedSurface:
    surf = ImportedSurface()

    def walk(items):
        if not isinstance(items, list):
            return
        for it in items:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):        # a folder — recurse
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            url = req.get("url")
            surf.add_endpoint(_postman_url(url))
            if isinstance(url, dict):
                for q in (url.get("query") or []):
                    if isinstance(q, dict):
                        surf.add_param(q.get("key") or "")
            _record_header_names(req.get("header"), surf)
            body = req.get("body") or {}
            if isinstance(body, dict):
                for pp in (body.get("urlencoded") or []) + (body.get("formdata") or []):
                    if isinstance(pp, dict):
                        surf.add_param(pp.get("key") or "")
    walk(obj.get("item"))
    return surf


def load_surface(text_or_obj) -> Tuple[str, ImportedSurface]:
    """Auto-detect and parse a HAR or Postman export. Returns (kind, surface).
    Raises ValueError on unrecognized input; never raises on merely-empty content."""
    if isinstance(text_or_obj, (dict, list)):
        obj = text_or_obj
    else:
        try:
            obj = json.loads(text_or_obj)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"not valid JSON: {exc}") from exc
    if isinstance(obj, dict) and isinstance(obj.get("log"), dict) \
            and "entries" in obj["log"]:
        return "har", parse_har(obj)
    if isinstance(obj, dict) and (
            isinstance(obj.get("item"), list)
            or "postman" in str((obj.get("info") or {}).get("schema", "")).lower()):
        return "postman", parse_postman(obj)
    raise ValueError("unrecognized export: expected a HAR (log.entries) or a "
                     "Postman v2.1 collection (item[])")


def load_surface_file(path: str) -> Tuple[str, ImportedSurface]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return load_surface(fh.read())
