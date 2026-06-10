"""WorldModel — the agent's evolving beliefs about one target (per-hunt).

This is the structural spine PLAN.md Section 7.2 calls for: a single object that
*is* the belief state and is updated on every observation. It wraps (does not
replace) ``core.agent_state.TargetInfo`` for the structural facts (ports,
services, technologies, vulns) and adds:

  * ``beliefs`` — a ``key -> Belief`` map with a confidence per belief,
  * attack-surface facts ``TargetInfo`` lacks (endpoints, parameters, auth/WAF),
  * ``update(Observation)`` — idempotent + monotonic (replaying the same
    observation never duplicates facts or inflates confidence), and
  * ``to_prompt_section()`` — a structured, confidence-annotated view to feed the
    planner/think-engine instead of a free-text blob.

Idempotency is structural: ``TargetInfo.merge_from`` dedups lists, belief
confidence updates use ``max(existing, new)``, and ``snapshot()`` excludes
volatile fields (timestamps/source). So::

    wm.update(obs); s = wm.snapshot(); wm.update(obs); assert wm.snapshot() == s

holds by construction.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .agent_state import TargetInfo


# ---------------------------------------------------------------------------
# Belief + Observation
# ---------------------------------------------------------------------------


@dataclass
class Belief:
    """One confidence-scored thing the agent believes about the target."""
    key: str
    value: Any
    confidence: float = 0.5          # 0..1
    source: str = ""
    observed_at: float = 0.0         # wall-clock; excluded from snapshot()

    def to_dict(self) -> dict:
        return {
            "key": self.key, "value": self.value,
            "confidence": round(self.confidence, 3), "source": self.source,
        }


@dataclass
class Observation:
    """A structured result from a tool/worker, fed to ``WorldModel.update``.

    Carry whatever the producer learned; empty fields are ignored. Use
    ``from_finding`` to convert the swarm's flat finding dicts.
    """
    source: str = ""
    kind: str = ""                                   # finding | tech | port | http | recon
    ports: list = field(default_factory=list)        # [int | "80/tcp"]
    services: dict = field(default_factory=dict)     # port -> service str
    technologies: list = field(default_factory=list) # ["nginx", "WordPress 5.8"]
    endpoints: list = field(default_factory=list)    # ["https://t/login", ...]
    parameters: list = field(default_factory=list)   # ["id", "redirect", ...]
    vulnerabilities: list = field(default_factory=list)  # vuln descriptor dicts
    beliefs: list = field(default_factory=list)      # [(key, value, confidence)]
    waf: Optional[bool] = None
    auth_required: Optional[bool] = None
    raw: dict = field(default_factory=dict)

    # ---- conversion from the swarm's finding dicts ----

    @classmethod
    def from_finding(cls, f: dict) -> "Observation":
        """Map a swarm/worker finding dict into an Observation."""
        ftype = str(f.get("type") or "").lower()
        vtype = str(f.get("vuln_type") or "").lower()
        url = f.get("url") or f.get("endpoint") or ""
        conf = _as_float(f.get("confidence"), default=0.6)
        obs = cls(source=str(f.get("technique") or f.get("source") or "worker"),
                  kind="finding", raw=dict(f))

        if url:
            obs.endpoints.append(url)
        if f.get("parameter"):
            obs.parameters.append(str(f["parameter"]))

        # Recon-shaped findings -> structural facts.
        if ftype in ("technology", "tech") and f.get("title"):
            obs.technologies.append(str(f["title"]))
        elif ftype == "open_port" and f.get("port") is not None:
            obs.ports.append(f["port"])
            if f.get("service"):
                obs.services[str(f["port"])] = str(f["service"])
        elif ftype in ("subdomain", "dns_a", "dns_aaaa", "dns_cname") and f.get("asset"):
            obs.endpoints.append(str(f["asset"]))

        if "waf" in ftype or f.get("waf"):
            obs.waf = True

        # Anything that looks like a vulnerability becomes a vuln belief.
        sev = str(f.get("severity") or "").lower()
        is_vuln = bool(vtype) or ftype not in (
            "technology", "tech", "open_port", "subdomain", "dns_a", "dns_aaaa",
            "dns_cname", "finding", "",
        ) or sev in ("low", "medium", "high", "critical")
        if is_vuln and sev not in ("", "info", "informational"):
            klass = vtype or ftype or "finding"
            obs.vulnerabilities.append({
                "class": klass, "url": url, "severity": sev,
                "title": f.get("title"), "confidence": conf,
            })
            # An *_exploited / confirmed finding is a high-confidence belief.
            confirmed = "exploit" in klass or "confirmed" in str(f.get("title", "")).lower()
            obs.beliefs.append((
                f"vuln:{_short_class(klass)}@{_host(url)}",
                {"severity": sev, "url": url, "confirmed": confirmed},
                min(0.99, conf + 0.2) if confirmed else conf,
            ))
        return obs


def _as_float(v: Any, *, default: float) -> float:
    try:
        f = float(v)
        return f if 0.0 <= f <= 1.0 else (f / 100.0 if f <= 100 else default)
    except (TypeError, ValueError):
        return default


def _short_class(klass: str) -> str:
    return klass.split("_exploit")[0].split("_candidate")[0].split(":")[0]


def _host(url: str) -> str:
    if not url:
        return ""
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0].split("?", 1)[0]


# ---------------------------------------------------------------------------
# WorldModel
# ---------------------------------------------------------------------------


class WorldModel:
    """The per-hunt belief state. Wraps TargetInfo; adds confidence beliefs."""

    def __init__(self, target: str = "", *, clock=time.time):
        self.target = target
        self.info = TargetInfo(primary_target=target)
        self.beliefs: dict[str, Belief] = {}
        # Attack-surface facts TargetInfo lacks.
        self.endpoints: set[str] = set()
        self.parameters: set[str] = set()
        self.waf_present: Optional[bool] = None
        self.auth_required: Optional[bool] = None
        self._clock = clock
        self.observation_count = 0

    # ---- the one mutator ----

    def update(self, obs: Observation) -> bool:
        """Fold an observation into the model. Returns True iff anything changed.

        Idempotent: replaying the same observation leaves snapshot() unchanged.
        """
        before = self.snapshot()

        # Structural facts via TargetInfo's deduping merge.
        if obs.ports or obs.technologies or obs.services or obs.vulnerabilities:
            patch = TargetInfo(
                ports=[p for p in obs.ports],
                technologies=[t for t in obs.technologies],
                services=dict(obs.services),
                vulnerabilities=[v for v in obs.vulnerabilities],
            )
            self.info.merge_from(patch)

        for e in obs.endpoints:
            if e:
                self.endpoints.add(e)
        for p in obs.parameters:
            if p:
                self.parameters.add(p)
        if obs.waf is not None:
            self.waf_present = self.waf_present or obs.waf
        if obs.auth_required is not None:
            self.auth_required = self.auth_required or obs.auth_required

        # Auto-derive structural beliefs (so callers don't have to).
        for tech in obs.technologies:
            self._set_belief(f"tech:{str(tech).split()[0].lower()}", tech, 0.8, obs.source)
        for port in obs.ports:
            self._set_belief(f"port:{port}", True, 0.9, obs.source)
        if obs.endpoints:
            self._set_belief("has_endpoints", True, 0.7, obs.source)
        if self.waf_present:
            self._set_belief("waf", True, 0.7, obs.source)

        # Explicit beliefs from the observation.
        for entry in obs.beliefs:
            try:
                key, value, conf = entry
            except (ValueError, TypeError):
                continue
            self._set_belief(key, value, _as_float(conf, default=0.6), obs.source)

        self.observation_count += 1
        return self.snapshot() != before

    def _set_belief(self, key: str, value: Any, confidence: float, source: str) -> None:
        """Monotonic confidence update: never lowers an existing belief."""
        existing = self.beliefs.get(key)
        if existing is None:
            self.beliefs[key] = Belief(key, value, confidence, source, self._clock())
            return
        # Raise confidence only; keep the higher-confidence value/source.
        if confidence > existing.confidence:
            existing.confidence = confidence
            existing.value = value
            existing.source = source
            existing.observed_at = self._clock()

    # ---- queries ----

    def has_belief(self, key: str, *, min_confidence: float = 0.0) -> bool:
        b = self.beliefs.get(key)
        return b is not None and b.confidence >= min_confidence

    def confidence(self, key: str) -> float:
        b = self.beliefs.get(key)
        return b.confidence if b else 0.0

    def confirmed_vulns(self) -> list:
        return [v for v in self.info.vulnerabilities
                if isinstance(v, dict) and v.get("confidence", 0) >= 0.85]

    def attack_surface(self) -> dict:
        return {
            "endpoints": sorted(self.endpoints),
            "parameters": sorted(self.parameters),
            "open_ports": sorted(str(p) for p in self.info.ports),
            "technologies": list(self.info.technologies),
        }

    # ---- serialization ----

    def snapshot(self) -> dict:
        """Deterministic, volatile-field-free view (for idempotency + equality)."""
        return {
            "target": self.target,
            "ports": sorted(str(p) for p in self.info.ports),
            "services": dict(sorted(self.info.services.items())),
            "technologies": sorted(self.info.technologies),
            "endpoints": sorted(self.endpoints),
            "parameters": sorted(self.parameters),
            "vulnerabilities": sorted(
                (str(v.get("class")) + "@" + str(v.get("url")))
                if isinstance(v, dict) else str(v)
                for v in self.info.vulnerabilities
            ),
            "waf": self.waf_present,
            "auth_required": self.auth_required,
            "beliefs": {k: self.beliefs[k].to_dict() for k in sorted(self.beliefs)},
        }

    def to_dict(self) -> dict:
        d = self.snapshot()
        d["observation_count"] = self.observation_count
        return d

    def to_prompt_section(self) -> str:
        """Structured, confidence-annotated belief view for the planner/LLM."""
        lines = [f"## Target beliefs: {self.target or '(unknown)'}"]
        surf = self.attack_surface()
        if surf["open_ports"]:
            lines.append(f"- Open ports: {', '.join(surf['open_ports'])}")
        if surf["technologies"]:
            lines.append(f"- Technologies: {', '.join(map(str, surf['technologies']))}")
        if surf["endpoints"]:
            shown = surf["endpoints"][:12]
            more = "" if len(surf["endpoints"]) <= 12 else f" (+{len(surf['endpoints'])-12} more)"
            lines.append(f"- Endpoints ({len(surf['endpoints'])}): {', '.join(shown)}{more}")
        if surf["parameters"]:
            lines.append(f"- Parameters: {', '.join(surf['parameters'][:20])}")
        if self.waf_present:
            lines.append("- WAF: present (favor evasion / low-and-slow)")
        cv = self.confirmed_vulns()
        if cv:
            lines.append(f"- CONFIRMED vulns: " + ", ".join(
                f"{v.get('class')}@{_host(v.get('url',''))}" for v in cv))
        # Top suspected beliefs by confidence.
        ranked = sorted(self.beliefs.values(), key=lambda b: -b.confidence)
        vuln_beliefs = [b for b in ranked if b.key.startswith("vuln:")][:8]
        if vuln_beliefs:
            lines.append("- Suspected (by confidence): " + ", ".join(
                f"{b.key.split(':',1)[1]} ({b.confidence:.0%})" for b in vuln_beliefs))
        if len(lines) == 1:
            lines.append("- (no observations yet)")
        return "\n".join(lines)

    # ---- convenience ----

    def observe_finding(self, finding: dict) -> bool:
        """Update from a swarm finding dict in one call."""
        return self.update(Observation.from_finding(finding))
