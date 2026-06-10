"""Tests for core.world_model — the per-hunt belief state (PLAN.md Section 7.2)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.world_model import Belief, Observation, WorldModel  # noqa: E402


# A monotonic fake clock so observed_at is deterministic across runs.
class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 1.0
        return self.t


class TestIdempotency:
    def test_replaying_same_observation_is_idempotent(self):
        wm = WorldModel("example.com", clock=_Clock())
        obs = Observation(
            source="nuclei", technologies=["nginx"], ports=[443],
            endpoints=["https://example.com/login"],
            beliefs=[("vuln:sqli@example.com", {"url": "https://example.com/x"}, 0.7)],
        )
        assert wm.update(obs) is True          # first time changes the model
        snap = wm.snapshot()
        assert wm.update(obs) is False         # replay changes nothing
        assert wm.snapshot() == snap           # the §7.2 invariant

    def test_monotonic_confidence_never_lowers(self):
        wm = WorldModel("t", clock=_Clock())
        wm.update(Observation(beliefs=[("vuln:xss@t", "v", 0.9)]))
        wm.update(Observation(beliefs=[("vuln:xss@t", "v", 0.3)]))  # lower
        assert wm.confidence("vuln:xss@t") == 0.9

    def test_higher_confidence_raises(self):
        wm = WorldModel("t", clock=_Clock())
        wm.update(Observation(beliefs=[("vuln:xss@t", "v", 0.4)]))
        changed = wm.update(Observation(beliefs=[("vuln:xss@t", "v", 0.95)]))
        assert changed is True
        assert wm.confidence("vuln:xss@t") == 0.95


class TestFromFinding:
    def test_tech_finding_becomes_technology(self):
        wm = WorldModel("t", clock=_Clock())
        wm.observe_finding({"type": "technology", "title": "WordPress 5.8",
                            "url": "https://t/"})
        assert "WordPress 5.8" in wm.info.technologies
        assert wm.has_belief("tech:wordpress")

    def test_open_port_finding(self):
        wm = WorldModel("t", clock=_Clock())
        wm.observe_finding({"type": "open_port", "port": 8080, "service": "http-alt",
                            "asset": "t"})
        assert 8080 in wm.info.ports
        assert wm.info.services["8080"] == "http-alt"
        assert wm.has_belief("port:8080")

    def test_exploited_finding_is_high_confidence_confirmed_belief(self):
        wm = WorldModel("t", clock=_Clock())
        wm.observe_finding({
            "type": "sqli_exploited", "vuln_type": "sqli_exploited",
            "severity": "critical", "url": "https://t/item?id=1",
            "title": "SQL injection confirmed", "confidence": 0.8,
        })
        # confirmed → confidence boosted above the raw 0.8
        key = "vuln:sqli@t"
        assert wm.has_belief(key)
        b = wm.beliefs[key]
        assert b.value.get("confirmed") is True
        assert b.confidence > 0.8

    def test_info_severity_is_not_a_vuln(self):
        wm = WorldModel("t", clock=_Clock())
        wm.observe_finding({"type": "header", "severity": "info", "url": "https://t/"})
        assert wm.info.vulnerabilities == []
        assert not any(k.startswith("vuln:") for k in wm.beliefs)


class TestViews:
    def test_attack_surface_and_prompt_section(self):
        wm = WorldModel("example.com", clock=_Clock())
        wm.update(Observation(technologies=["nginx"], ports=[80],
                              endpoints=["https://example.com/a"],
                              parameters=["id"], waf=True))
        surf = wm.attack_surface()
        assert "80" in surf["open_ports"]
        assert "nginx" in surf["technologies"]
        section = wm.to_prompt_section()
        assert "example.com" in section
        assert "WAF" in section
        assert "nginx" in section

    def test_empty_model_prompt_section(self):
        wm = WorldModel("t", clock=_Clock())
        assert "no observations yet" in wm.to_prompt_section()

    def test_to_dict_roundtrip_keys(self):
        wm = WorldModel("t", clock=_Clock())
        wm.update(Observation(ports=[22]))
        d = wm.to_dict()
        assert d["observation_count"] == 1
        assert "22" in d["ports"]
