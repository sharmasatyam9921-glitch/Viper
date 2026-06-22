"""Per-class precision/recall scorecard for the validation gate.

Runs the gate over a labeled benchmark of *vulnerable* and *safe* responders for
each weakness class, then reports a confusion matrix and precision/recall per
class.

The gate's contract is FP-averse: a safe responder must NEVER be marked
``submittable`` (per-class precision target = 1.0, i.e. zero false positives).
Recall is the secondary metric — a missed vuln degrades to an unconfirmed lead a
human can still review, which is the safe failure direction.

Run as a script::

    python -m core.gate_benchmark          # print the scorecard
    python -m core.gate_benchmark --strict # exit 1 if any class has a false positive

Each scenario reuses the same vulnerable/safe responder models the gate's unit
tests assert against, so the scorecard tracks the gate's real behaviour rather
than a parallel re-implementation.
"""
from __future__ import annotations

import asyncio
import html as _html
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from core.swarm_validation import validate_findings
from core.swarm_workers.vuln._http import HttpResp

# --- shared fixtures -------------------------------------------------------

_AKIA = "AKIA2E0K8Z9QXVB7N3RT"          # AKIA + 16, no EXAMPLE/placeholder
_PWHASH = '[{"id":1,"email":"a@b.co","passwordHash":"$2b$10$abcdefghijklmno"}]'
_A_MARKER = "alice@victim.io"
_BOLA_CFG = {"owner_headers": {"Cookie": "s=alice"}, "owner_markers": [_A_MARKER],
             "attacker_headers": {"Cookie": "s=bob"}}


def _injected(url: str) -> str:
    q = parse_qs(urlsplit(url).query)
    for v in q.values():
        if v:
            return v[0]
    return ""


def _fetch(responder):
    async def fake(method, url, *, headers=None, timeout=10.0, **kw):
        return responder(method, url, headers or {})
    return fake


# --- responders: each models one server's behaviour ------------------------

def _xss_live(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<h1>Results for {_injected(url)}</h1>", url)


def _xss_escaped(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<h1>Results for {_html.escape(_injected(url))}</h1>", url)


def _xss_textarea(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f"<form><textarea>{_injected(url)}</textarea></form>", url)


def _xss_attribute(m, url, h):
    return HttpResp(200, {"content-type": "text/html"},
                    f'<input type="text" value="{_injected(url)}">', url)


def _sqli_real(m, url, h):
    v = _injected(url)
    if v.count("'") % 2 == 1 or v.count('"') % 2 == 1:
        return HttpResp(500, {}, "You have an error in your SQL syntax near", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_waf(m, url, h):
    v = _injected(url)
    if "'" in v or '"' in v:
        return HttpResp(403, {}, "Request blocked by Web Application Firewall: "
                        "incorrect syntax near the submitted token", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_dsl(m, url, h):
    v = _injected(url)
    if v.count("'") % 2 == 1:
        return HttpResp(500, {}, "ParseException: near \"'\": syntax error", url)
    return HttpResp(200, {}, "ok", url)


def _sqli_inert(m, url, h):
    return HttpResp(200, {}, "ordinary content, no DB error", url)


def _ssti_engine(m, url, h):
    import re as _re
    v = _injected(url)
    am = _re.search(r"\$\{(\d+)\*(\d+)\}", v)
    if am:
        return HttpResp(200, {}, f"Result: {int(am.group(1)) * int(am.group(2))}", url)
    if any(op in v for op in ('"+"', '"~"', '.concat(')):
        words = _re.findall(r'"(\w+)"', v)
        if len(words) >= 2:
            return HttpResp(200, {}, "Result: " + "".join(words), url)
    return HttpResp(200, {}, f"Result: {v}", url)


def _ssti_calculator(m, url, h):
    import re as _re
    v = _injected(url)
    mm = _re.search(r"(\d+)\*(\d+)", v)
    return HttpResp(200, {}, f"Result: {int(mm.group(1)) * int(mm.group(2))}" if mm
                    else f"Result: {v}", url)


def _lfi_passwd(m, url, h):
    v = _injected(url)
    if "etc/passwd" in v and "../" in v:
        return HttpResp(200, {}, "root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n", url)
    return HttpResp(200, {}, "no such doc", url)


def _lfi_prose(m, url, h):
    return HttpResp(200, {}, "The file starts with root:x:0:0:root:/root (one line).", url)


def _lfi_html_doc(m, url, h):
    v = _injected(url)
    if "etc/passwd" in v:
        return HttpResp(200, {"content-type": "text/html"},
                        "<html>root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</html>", url)
    return HttpResp(200, {"content-type": "text/html"}, "<html>no match</html>", url)


def _secret_live(m, url, h):
    return HttpResp(200, {"content-type": "application/javascript"},
                    f'var k="{_AKIA}";', url)


def _secret_placeholder(m, url, h):
    return HttpResp(200, {"content-type": "application/javascript"},
                    'var k="AKIAIOSFODNN7EXAMPLE";', url)


def _secret_changelog(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    f"v1.2: rotated key {_AKIA}", url)


def _ac_pwhash(m, url, h):
    return HttpResp(200, {"content-type": "application/json"}, _PWHASH, url)


def _ac_public_email(m, url, h):
    return HttpResp(200, {"content-type": "application/json"},
                    '{"name":"Acme Co","email":"contact@acme.example"}', url)


def _ac_publishable(m, url, h):
    return HttpResp(200, {"content-type": "application/json"},
                    '{"api_key":"pk_live_51ABCdefGHIjklMNOpqr"}', url)


def _ac_forbidden(m, url, h):
    return HttpResp(403, {}, "Forbidden", url)


def _cors_creds(m, url, h):
    return HttpResp(200, {"access-control-allow-origin": h.get("Origin", ""),
                          "access-control-allow-credentials": "true"}, "{}", url)


def _cors_no_creds(m, url, h):
    return HttpResp(200, {"access-control-allow-origin": h.get("Origin", "")},
                    '{"price":1}', url)


def _cors_static(m, url, h):
    return HttpResp(200, {"content-type": "text/css",
                          "access-control-allow-origin": h.get("Origin", ""),
                          "access-control-allow-credentials": "true"}, "body{}", url)


def _env_real(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    f"DB_PASSWORD=s3cret\nAWS_KEY={_AKIA}\n", url)


def _env_example(m, url, h):
    return HttpResp(200, {"content-type": "text/plain"},
                    "DB_PASSWORD=changeme\nAWS_KEY=YOUR_KEY_HERE\n", url)


def _dir_real(m, url, h):
    return HttpResp(200, {}, "<html><h1>Index of /ftp</h1><a href='x'>x</a></html>", url)


def _dir_prose(m, url, h):
    links = "".join(f'<a href="/p{i}">page {i}</a>' for i in range(12))
    return HttpResp(200, {}, f"<html><h2>Our index of services</h2>{links}</html>", url)


def _bola_cross_read(m, url, h):
    ck = (h or {}).get("Cookie", "")
    if "s=alice" in ck or "s=bob" in ck:           # both authed see A's object
        return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
    return HttpResp(401, {}, "", url)              # anon control -> not public


def _bola_proper_authz(m, url, h):
    ck = (h or {}).get("Cookie", "")
    if "s=alice" in ck:
        return HttpResp(200, {}, '{"owner":"%s"}' % _A_MARKER, url)
    return HttpResp(403, {}, "", url)              # attacker forbidden -> no cross-read


def _ok(m, url, h):
    return HttpResp(200, {}, "x", url)


def _hh_reflect(m, url, h):
    xfh = h.get("X-Forwarded-Host")
    if xfh:                                    # builds a redirect from the spoofed host
        return HttpResp(302, {"location": f"https://{xfh}/login"}, "", url)
    return HttpResp(200, {}, "home", url)


def _hh_safe(m, url, h):
    return HttpResp(200, {}, "home", url)      # never reflects the host header


def _takeover(m, url, h):
    return HttpResp(404, {}, "<html>There isn't a GitHub Pages site here.</html>", url)


def _takeover_safe(m, url, h):
    return HttpResp(404, {}, "<html>404 Not Found - page missing</html>", url)


def _s3_public(m, url, h):
    return HttpResp(200, {}, '<?xml version="1.0"?><ListBucketResult xmlns='
                    '"http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name>'
                    '<Contents><Key>db-backup.sql</Key></Contents></ListBucketResult>', url)


def _s3_private(m, url, h):
    return HttpResp(403, {}, '<?xml version="1.0"?><Error><Code>AccessDenied'
                    '</Code></Error>', url)


# --- the labeled benchmark -------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    cls: str            # weakness class label for grouping
    label: str          # "vuln" (should be submittable) | "safe" (must not be)
    name: str           # human-readable scenario id
    finding: dict
    responder: object
    bola_config: dict = None


BENCHMARK = [
    # xss
    Scenario("xss", "vuln", "live markup in content",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_live),
    Scenario("xss", "safe", "html-escaped reflection",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_escaped),
    Scenario("xss", "safe", "reflection inside <textarea>",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_textarea),
    Scenario("xss", "safe", "reflection inside attribute value",
             {"vuln_type": "xss_text:q", "url": "http://t/s?q=x", "parameter": "q"}, _xss_attribute),

    # sqli
    Scenario("sqli", "vuln", "unbalanced quote -> 500 DB error",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_real),
    Scenario("sqli", "safe", "WAF 403 mentioning SQL",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_waf),
    Scenario("sqli", "safe", "DSL parser generic syntax error",
             {"vuln_type": "sqli:q", "url": "http://t/search?q=docs", "parameter": "q"}, _sqli_dsl),
    Scenario("sqli", "safe", "inert content, no DB error",
             {"vuln_type": "sqli:id", "url": "http://t/x?id=1", "parameter": "id"}, _sqli_inert),

    # ssti
    Scenario("ssti", "vuln", "template engine evals ${8*8} and string ops",
             {"vuln_type": "ssti", "url": "http://t/x?n=1", "parameter": "n"}, _ssti_engine),
    Scenario("ssti", "safe", "calculator evals bare arithmetic too",
             {"vuln_type": "ssti", "url": "http://t/order?qty=1", "parameter": "qty"}, _ssti_calculator),

    # lfi
    Scenario("lfi", "vuln", "multi-account /etc/passwd via traversal",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_passwd),
    Scenario("lfi", "safe", "doc quoting only the canonical root line",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_prose),
    Scenario("lfi", "safe", "man-page tutorial returned as HTML",
             {"vuln_type": "lfi:file", "parameter": "file",
              "url": "http://t/x?file=../../../../etc/passwd"}, _lfi_html_doc),

    # secrets
    Scenario("secrets", "vuln", "live AWS key in JS",
             {"vuln_type": "secret:aws", "url": "http://t/main.js"}, _secret_live),
    Scenario("secrets", "safe", "AWS canonical EXAMPLE key",
             {"vuln_type": "secret:aws", "url": "http://t/main.js"}, _secret_placeholder),
    Scenario("secrets", "safe", "rotated key in CHANGELOG",
             {"vuln_type": "secret:aws", "url": "http://t/CHANGELOG.txt"}, _secret_changelog),

    # access_control
    Scenario("access_control", "vuln", "unauth password hashes",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/api/Users"},
             _ac_pwhash),
    Scenario("access_control", "safe", "public profile exposing email",
             {"vuln_type": "access_control:missing_authorization",
              "url": "http://t/api/public-profile"}, _ac_public_email),
    Scenario("access_control", "safe", "Stripe publishable key in SPA config",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/config.json"},
             _ac_publishable),
    Scenario("access_control", "safe", "endpoint returns 403",
             {"vuln_type": "access_control:missing_authorization", "url": "http://t/api/Users"},
             _ac_forbidden),

    # cors
    Scenario("cors", "vuln", "reflects arbitrary origin + credentials",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/api"}, _cors_creds),
    Scenario("cors", "safe", "reflects origin, no credentials",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/ticker"}, _cors_no_creds),
    Scenario("cors", "safe", "reflect+creds on static .css asset",
             {"vuln_type": "cors_origin_reflect", "url": "http://t/brand.css"}, _cors_static),

    # env_exposed
    Scenario("env_exposed", "vuln", "live /.env with real secrets",
             {"vuln_type": "env_exposed:/.env", "url": "http://t/.env"}, _env_real),
    Scenario("env_exposed", "safe", ".env.example with placeholders",
             {"vuln_type": "env_exposed:/.env.example", "url": "http://t/.env.example"}, _env_example),

    # dir_listing
    Scenario("dir_listing", "vuln", "real Apache autoindex",
             {"vuln_type": "information_disclosure:listing:/ftp", "url": "http://t/ftp"}, _dir_real),
    Scenario("dir_listing", "safe", "prose page mentioning 'index of'",
             {"vuln_type": "information_disclosure:listing:/x", "url": "http://t/services"}, _dir_prose),

    # idor / bola escalation
    Scenario("idor", "vuln", "single-session IDOR escalates to two-account BOLA",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"},
             _bola_cross_read, _BOLA_CFG),
    Scenario("idor", "safe", "attacker forbidden -> proper authz",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"},
             _bola_proper_authz, _BOLA_CFG),
    Scenario("idor", "safe", "single session, no two-account config",
             {"vuln_type": "idor:user", "url": "http://t/api/users/5"}, _ok),

    # cmdi (offline: real re-test can't reproduce -> safe direction only)
    Scenario("cmdi", "safe", "non-reproducible / unreachable target",
             {"vuln_type": "rce:cmdi:id", "url": "http://127.0.0.1:9/x?id=1", "parameter": "id"},
             _ok),

    # host header injection
    Scenario("host_header", "vuln", "spoofed X-Forwarded-Host reflected into Location",
             {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
              "parameter": "X-Forwarded-Host"}, _hh_reflect),
    Scenario("host_header", "safe", "host header not reflected",
             {"vuln_type": "host_header:x-forwarded-host", "url": "http://t/",
              "parameter": "X-Forwarded-Host"}, _hh_safe),

    # subdomain takeover
    Scenario("subdomain_takeover", "vuln", "GitHub Pages unclaimed fingerprint",
             {"vuln_type": "subdomain_takeover:github_pages", "url": "http://t/"},
             _takeover),
    Scenario("subdomain_takeover", "safe", "generic 404 (not a takeover)",
             {"vuln_type": "subdomain_takeover:github_pages", "url": "http://t/"},
             _takeover_safe),

    # cloud storage exposure
    Scenario("cloud_exposure", "vuln", "public listable S3 bucket",
             {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"},
             _s3_public),
    Scenario("cloud_exposure", "safe", "private bucket (AccessDenied)",
             {"vuln_type": "cloud_exposure:public_bucket_listing", "url": "http://t/"},
             _s3_private),

    # web cache deception (gate trusts the worker's two-identity cache proof)
    Scenario("web_cache_deception", "vuln", "anon retrieved victim data from cache",
             {"vuln_type": "web_cache_deception:/account",
              "url": "http://t/account/x.css", "cache_confirmed": True}, _ok),
    Scenario("web_cache_deception", "safe", "unconfirmed cache candidate",
             {"vuln_type": "web_cache_deception:/account",
              "url": "http://t/account/x.css"}, _ok),
]


# --- scoring ---------------------------------------------------------------

@dataclass
class ClassScore:
    cls: str
    tp: int = 0   # vuln correctly marked submittable
    fp: int = 0   # safe wrongly marked submittable  <-- the dangerous error
    tn: int = 0   # safe correctly held back
    fn: int = 0   # vuln missed (degraded to lead)
    fps: list = field(default_factory=list)   # names of safe scenarios that leaked

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def support(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


def _evaluate(sc: Scenario) -> bool:
    out = asyncio.run(validate_findings(
        [dict(sc.finding)], fetch=_fetch(sc.responder), bola_config=sc.bola_config))
    return bool(out[0].get("submittable"))


def run_benchmark(scenarios=None):
    """Run the gate over every scenario; return {cls: ClassScore}."""
    scenarios = scenarios if scenarios is not None else BENCHMARK
    scores: dict[str, ClassScore] = {}
    for sc in scenarios:
        submittable = _evaluate(sc)
        cs = scores.setdefault(sc.cls, ClassScore(sc.cls))
        if sc.label == "vuln":
            if submittable:
                cs.tp += 1
            else:
                cs.fn += 1
        else:  # safe
            if submittable:
                cs.fp += 1
                cs.fps.append(sc.name)
            else:
                cs.tn += 1
    return scores


def overall(scores) -> ClassScore:
    tot = ClassScore("OVERALL")
    for cs in scores.values():
        tot.tp += cs.tp
        tot.fp += cs.fp
        tot.tn += cs.tn
        tot.fn += cs.fn
        tot.fps.extend(f"{cs.cls}:{n}" for n in cs.fps)
    return tot


def format_scorecard(scores) -> str:
    tot = overall(scores)
    lines = [
        "VIPER validation-gate precision scorecard",
        "(safe responders must never be submittable; precision target = 1.00)",
        "",
        f"{'class':<16} {'prec':>6} {'recall':>7} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}",
        "-" * 52,
    ]
    for cls in sorted(scores):
        cs = scores[cls]
        flag = "  <-- FP!" if cs.fp else ""
        lines.append(f"{cls:<16} {cs.precision:>6.2f} {cs.recall:>7.2f} "
                     f"{cs.tp:>3} {cs.fp:>3} {cs.tn:>3} {cs.fn:>3}{flag}")
    lines.append("-" * 52)
    lines.append(f"{'OVERALL':<16} {tot.precision:>6.2f} {tot.recall:>7.2f} "
                 f"{tot.tp:>3} {tot.fp:>3} {tot.tn:>3} {tot.fn:>3}")
    if tot.fps:
        lines.append("")
        lines.append("FALSE POSITIVES (safe responders marked submittable):")
        for n in tot.fps:
            lines.append(f"  - {n}")
    else:
        lines.append("")
        lines.append("No false positives: every safe responder was correctly held back.")
    return "\n".join(lines)


def main(argv=None) -> int:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    strict = "--strict" in argv
    scores = run_benchmark()
    print(format_scorecard(scores))
    if strict and overall(scores).fp:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
