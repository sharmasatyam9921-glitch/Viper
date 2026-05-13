"""Lateral Movement Agent — autonomous post-foothold campaign driver.

Once a foothold is established (low-priv shell on a Linux/Windows box),
this agent drives the rest of an internal pentest:

    foothold -> enumerate -> privesc -> AD enum -> kerberoast/asreproast
             -> credential dump -> lateral hop -> repeat on new host

The state machine has two operating modes:

  * **deterministic** — pure-heuristic transitions (no LLM). Used for
    testing, demos, and risk-averse engagements where the operator wants
    to predict every step.
  * **llm** — calls the configured model_router at each decision point
    with a structured prompt (the `LATERAL_AGENT_PROMPT` below) and lets
    the model pick the next step. Used when the campaign hits novel
    territory the heuristic can't handle.

All destructive steps (privesc execution, secretsdump, psexec, etc.)
flow through PostExploitAgent's existing approval_gate.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("viper.lateral")


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class LateralState(str, Enum):
    INIT = "INIT"
    ENUMERATE_HOST = "ENUMERATE_HOST"
    ANALYZE_PRIVESC = "ANALYZE_PRIVESC"
    EXECUTE_PRIVESC = "EXECUTE_PRIVESC"
    DETECT_AD = "DETECT_AD"
    AD_ENUM = "AD_ENUM"
    PRE_AUTH_ATTACKS = "PRE_AUTH_ATTACKS"  # ASREPRoast
    AUTH_ATTACKS = "AUTH_ATTACKS"           # Kerberoast, BloodHound
    CRED_DUMP = "CRED_DUMP"                 # secretsdump
    LATERAL_HOP = "LATERAL_HOP"             # psexec/wmiexec to next host
    DONE = "DONE"
    HALTED = "HALTED"  # operator pause / approval denied


# ---------------------------------------------------------------------------
# Campaign state
# ---------------------------------------------------------------------------


@dataclass
class FootholdInfo:
    target: str            # IP / hostname
    os: str = "linux"       # "linux" | "windows"
    user: str = ""           # current user on target
    is_root: bool = False
    domain: Optional[str] = None
    domain_sid: Optional[str] = None
    dc_ip: Optional[str] = None


@dataclass
class CredentialBundle:
    """Stuff we've gathered along the way."""
    user: str
    domain: Optional[str] = None
    password: Optional[str] = None
    nthash: Optional[str] = None
    aes256_key: Optional[str] = None
    source: str = ""  # "kerberoast" / "secretsdump" / "config_file" / etc.


@dataclass
class CampaignStep:
    """One executed action — kept for the post-mortem report."""
    state: LateralState
    action: str
    args: dict = field(default_factory=dict)
    result_summary: str = ""
    succeeded: bool = False
    timestamp: float = 0.0


@dataclass
class LateralCampaign:
    """The running state of a lateral movement campaign."""
    foothold: FootholdInfo
    state: LateralState = LateralState.INIT
    history: list[CampaignStep] = field(default_factory=list)
    creds: list[CredentialBundle] = field(default_factory=list)
    owned_hosts: set[str] = field(default_factory=set)
    discovered_hosts: set[str] = field(default_factory=set)
    asrep_hashes: list[str] = field(default_factory=list)
    tgs_hashes: list[str] = field(default_factory=list)
    bloodhound_dump_dir: Optional[str] = None
    halt_reason: Optional[str] = None
    max_steps: int = 50

    def add_step(self, step: CampaignStep) -> None:
        self.history.append(step)

    @property
    def step_count(self) -> int:
        return len(self.history)

    @property
    def summary(self) -> dict:
        return {
            "foothold": self.foothold.target,
            "current_state": self.state.value,
            "steps_executed": self.step_count,
            "owned_hosts": sorted(self.owned_hosts),
            "discovered_hosts": sorted(self.discovered_hosts),
            "credentials_gathered": [
                {"user": c.user, "domain": c.domain, "source": c.source,
                 "has_password": bool(c.password), "has_nthash": bool(c.nthash)}
                for c in self.creds
            ],
            "asrep_hash_count": len(self.asrep_hashes),
            "tgs_hash_count": len(self.tgs_hashes),
            "bloodhound_dump": self.bloodhound_dump_dir,
            "halt_reason": self.halt_reason,
        }


# ---------------------------------------------------------------------------
# LLM prompt (used in llm mode)
# ---------------------------------------------------------------------------


LATERAL_AGENT_PROMPT = """\
You are driving an internal-pentest lateral movement campaign. Given the
campaign state JSON below, return ONLY valid JSON:

{
  "next_state": "<one of: ENUMERATE_HOST | ANALYZE_PRIVESC | EXECUTE_PRIVESC | DETECT_AD | AD_ENUM | PRE_AUTH_ATTACKS | AUTH_ATTACKS | CRED_DUMP | LATERAL_HOP | DONE | HALTED>",
  "reason": "<one short sentence>",
  "args": {<key/value args for the next action>}
}

Decision principles:
  - Get root/SYSTEM on current host before chasing AD attacks.
  - Pre-auth attacks (ASREPRoast) before authenticated attacks (Kerberoast).
  - Never run secretsdump on a DC unless we already have admin equivalent.
  - Stop at the first compromise of Domain Admin — DONE.
  - HALT if no progress for 2 consecutive steps.

Current campaign state:
{state_json}
"""


# ---------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------


class LateralAgent:
    """Autonomous lateral-movement orchestrator built on top of PostExploitAgent.

    The agent doesn't reimplement any tool — it composes existing
    PostExploitAgent methods using a state machine and a pluggable
    decision policy (deterministic | llm).
    """

    def __init__(
        self,
        post_exploit_agent,
        *,
        mode: str = "deterministic",
        model_router=None,
        approval_required: bool = True,
    ) -> None:
        if mode not in ("deterministic", "llm"):
            raise ValueError(f"unknown mode: {mode!r}")
        if mode == "llm" and model_router is None:
            raise ValueError("mode='llm' requires model_router")
        self.pe = post_exploit_agent
        self.mode = mode
        self.model_router = model_router
        self.approval_required = approval_required

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    async def run(
        self, foothold: FootholdInfo, *, max_steps: Optional[int] = None,
    ) -> LateralCampaign:
        """Run the campaign to completion (or halt). Returns final state.

        max_steps: override the default cap (50) — useful for tests or
        constrained engagements.
        """
        campaign = LateralCampaign(foothold=foothold)
        if max_steps is not None:
            campaign.max_steps = max_steps

        while campaign.step_count < campaign.max_steps:
            if campaign.state in (LateralState.DONE, LateralState.HALTED):
                break

            decision = await self._decide(campaign)
            campaign.state = LateralState(decision["next_state"])
            if campaign.state in (LateralState.DONE, LateralState.HALTED):
                campaign.halt_reason = decision.get("reason")
                break

            step = await self._execute(campaign, decision)
            campaign.add_step(step)

            if not step.succeeded and self._consecutive_failures(campaign) >= 2:
                campaign.state = LateralState.HALTED
                campaign.halt_reason = "two consecutive failed steps — operator review"
                break

        return campaign

    # ------------------------------------------------------------------
    # Decision policy
    # ------------------------------------------------------------------

    async def _decide(self, campaign: LateralCampaign) -> dict:
        if self.mode == "deterministic":
            return self._heuristic_decide(campaign)
        return await self._llm_decide(campaign)

    def _heuristic_decide(self, campaign: LateralCampaign) -> dict:
        """Pure rules engine — no LLM call. Predictable, testable."""
        f = campaign.foothold

        # Priority 1: gather host enumeration if we haven't yet
        if not self._already_done(campaign, LateralState.ENUMERATE_HOST):
            return {
                "next_state": LateralState.ENUMERATE_HOST.value,
                "reason": "First step: enumerate the foothold host",
                "args": {},
            }

        # Priority 2: try local privesc if not root yet
        if not f.is_root:
            if not self._already_done(campaign, LateralState.ANALYZE_PRIVESC):
                return {
                    "next_state": LateralState.ANALYZE_PRIVESC.value,
                    "reason": "Not root yet — analyze enumeration output for privesc paths",
                    "args": {},
                }
            if not self._already_done(campaign, LateralState.EXECUTE_PRIVESC):
                return {
                    "next_state": LateralState.EXECUTE_PRIVESC.value,
                    "reason": "Privesc paths analyzed — execute the highest-confidence one",
                    "args": {},
                }
            # Tried privesc, still not root → can still pursue AD if creds
            # available, else stop
            if not campaign.creds:
                return {
                    "next_state": LateralState.HALTED.value,
                    "reason": "Privesc failed and no AD creds — operator review",
                }

        # Priority 3: detect AD if we haven't yet
        if not self._already_done(campaign, LateralState.DETECT_AD):
            return {
                "next_state": LateralState.DETECT_AD.value,
                "reason": "Check if target is part of an AD domain",
                "args": {},
            }

        # If no domain detected → DONE (no AD = single-host engagement)
        if not f.domain:
            return {
                "next_state": LateralState.DONE.value,
                "reason": "No AD domain detected — single-host engagement complete",
            }

        # Priority 4: AD enumeration
        if not self._already_done(campaign, LateralState.AD_ENUM):
            return {
                "next_state": LateralState.AD_ENUM.value,
                "reason": "AD domain detected — enumerate users + shares",
                "args": {},
            }

        # Priority 5: pre-auth attacks (no creds needed)
        if not self._already_done(campaign, LateralState.PRE_AUTH_ATTACKS):
            return {
                "next_state": LateralState.PRE_AUTH_ATTACKS.value,
                "reason": "Try ASREPRoast on enumerated users",
                "args": {},
            }

        # Priority 6: authenticated AD attacks (need creds)
        if campaign.creds and not self._already_done(campaign, LateralState.AUTH_ATTACKS):
            return {
                "next_state": LateralState.AUTH_ATTACKS.value,
                "reason": "Have credentials — Kerberoast + BloodHound",
                "args": {},
            }

        # Priority 7: cred dump if we have creds + likely target a DC
        if (campaign.creds and f.dc_ip
                and not self._already_done(campaign, LateralState.CRED_DUMP)):
            return {
                "next_state": LateralState.CRED_DUMP.value,
                "reason": "Have AD creds — attempt secretsdump (approval-gated)",
                "args": {"target": f.dc_ip},
            }

        # Priority 8: lateral hop if we have creds + new hosts to try
        new_hosts = campaign.discovered_hosts - campaign.owned_hosts
        if campaign.creds and new_hosts and not self._already_done(
                campaign, LateralState.LATERAL_HOP):
            return {
                "next_state": LateralState.LATERAL_HOP.value,
                "reason": f"Have creds + {len(new_hosts)} unowned hosts — try lateral hop",
                "args": {"target": next(iter(new_hosts))},
            }

        # Nothing more to try
        return {
            "next_state": LateralState.DONE.value,
            "reason": "No more deterministic moves — campaign complete",
        }

    async def _llm_decide(self, campaign: LateralCampaign) -> dict:
        """Ask the configured model_router for the next step."""
        import json
        prompt = LATERAL_AGENT_PROMPT.format(
            state_json=json.dumps(campaign.summary, indent=2),
        )
        try:
            response = await self.model_router.complete(prompt)
        except Exception as e:
            logger.error("LLM call failed: %r — falling back to heuristic", e)
            return self._heuristic_decide(campaign)

        # Strip ```json fences if present
        text = response.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            decision = json.loads(text)
            assert "next_state" in decision
            return decision
        except (json.JSONDecodeError, AssertionError) as e:
            logger.error("LLM returned malformed decision: %r — using heuristic", e)
            return self._heuristic_decide(campaign)

    # ------------------------------------------------------------------
    # Step execution — dispatches to PostExploitAgent
    # ------------------------------------------------------------------

    async def _execute(self, campaign: LateralCampaign, decision: dict) -> CampaignStep:
        """Dispatch to the right PostExploitAgent method based on state."""
        import time

        state = LateralState(decision["next_state"])
        args = decision.get("args", {})
        step = CampaignStep(
            state=state, action=decision.get("reason", ""),
            args=args, timestamp=time.time(),
        )

        try:
            if state == LateralState.ENUMERATE_HOST:
                step.result_summary, step.succeeded = await self._run_host_enum(campaign)
            elif state == LateralState.ANALYZE_PRIVESC:
                step.result_summary, step.succeeded = self._run_privesc_analysis(campaign)
            elif state == LateralState.EXECUTE_PRIVESC:
                step.result_summary, step.succeeded = await self._run_privesc_execute(campaign)
            elif state == LateralState.DETECT_AD:
                step.result_summary, step.succeeded = await self._run_ad_detection(campaign)
            elif state == LateralState.AD_ENUM:
                step.result_summary, step.succeeded = await self._run_ad_enum(campaign)
            elif state == LateralState.PRE_AUTH_ATTACKS:
                step.result_summary, step.succeeded = await self._run_pre_auth(campaign)
            elif state == LateralState.AUTH_ATTACKS:
                step.result_summary, step.succeeded = await self._run_auth_attacks(campaign)
            elif state == LateralState.CRED_DUMP:
                step.result_summary, step.succeeded = await self._run_cred_dump(
                    campaign, target=args.get("target", campaign.foothold.dc_ip))
            elif state == LateralState.LATERAL_HOP:
                step.result_summary, step.succeeded = await self._run_lateral_hop(
                    campaign, target=args.get("target"))
        except Exception as e:
            logger.exception("step %s raised: %r", state, e)
            step.result_summary = f"exception: {e!r}"
            step.succeeded = False

        return step

    # ------------------------------------------------------------------
    # State handlers
    # ------------------------------------------------------------------

    async def _run_host_enum(self, c: LateralCampaign) -> tuple[str, bool]:
        # NOTE: real deployment path goes through SSH/PSRemoting; for the
        # heuristic skeleton we simply mark this slot as done. Real callers
        # supply already-collected output via campaign.history (operator
        # paste workflow) or via PostExploitAgent.run_linpeas_via_ssh.
        return ("Host enumeration slot marked — call PostExploitAgent.run_linpeas_via_ssh "
                "or paste output and call analyze_*_foothold yourself", True)

    def _run_privesc_analysis(self, c: LateralCampaign) -> tuple[str, bool]:
        """Look at the most recent enum result attached to history and run
        the right analyzer. For the deterministic skeleton, we just check
        whether there are pre-pasted results in the foothold metadata."""
        # Operator can stash collected output on the campaign by extending
        # FootholdInfo with optional fields. Skeleton path:
        return ("Privesc analysis slot — invoke pe.analyze_linux_foothold / "
                "analyze_windows_foothold with collected enum output", True)

    async def _run_privesc_execute(self, c: LateralCampaign) -> tuple[str, bool]:
        # Privesc execution is engagement-specific (drop a binary, run a
        # one-liner). The heuristic just marks the slot.
        return ("Privesc execution slot — operator runs the chosen one-liner", True)

    async def _run_ad_detection(self, c: LateralCampaign) -> tuple[str, bool]:
        """Use ad_enum.probe_smb to check if the foothold target is a DC."""
        from pentest.ad_enum import probe_open_ports, probe_smb
        ports = await probe_open_ports(c.foothold.target)
        c.discovered_hosts.add(c.foothold.target)
        if 88 in ports:
            smb = await probe_smb(c.foothold.target)
            if smb.get("domain"):
                c.foothold.domain = smb["domain"]
                c.foothold.dc_ip = c.foothold.target  # likely a DC
                return (f"Domain detected: {smb['domain']}", True)
        return ("No AD detected (port 88 closed or no domain in SMB info)", True)

    async def _run_ad_enum(self, c: LateralCampaign) -> tuple[str, bool]:
        if not c.foothold.dc_ip:
            return ("No DC IP set — skip AD enum", False)
        result = await self.pe.enumerate_ad(c.foothold.dc_ip)
        for u in result.get("users", []):
            c.discovered_hosts.add(u)  # user enumeration goes here too for tracking
        # Promote attack paths into log
        return (f"AD enum complete: {len(result.get('users', []))} users, "
                f"attack_paths={result.get('attack_paths', [])}", True)

    async def _run_pre_auth(self, c: LateralCampaign) -> tuple[str, bool]:
        if not c.foothold.dc_ip or not c.foothold.domain:
            return ("Need dc_ip + domain for ASREPRoast", False)
        # Pull users from history (last AD enum result). For skeleton, use a stub.
        users = [step.result_summary for step in c.history
                 if step.state == LateralState.AD_ENUM]
        result = await self.pe.asreproast(
            c.foothold.dc_ip, c.foothold.domain,
            users[:50] if users else [],  # cap
        )
        hashes = result.get("parsed", {}).get("hashes", [])
        c.asrep_hashes.extend(hashes)
        return (f"ASREPRoast: {len(hashes)} hash(es) captured", bool(hashes))

    async def _run_auth_attacks(self, c: LateralCampaign) -> tuple[str, bool]:
        if not c.creds:
            return ("Need at least one credential for authenticated attacks", False)
        cred = c.creds[0]
        result = await self.pe.kerberoast(
            c.foothold.dc_ip or c.foothold.target,
            cred.domain or c.foothold.domain or "",
            cred.user, cred.password or "",
        )
        hashes = result.get("parsed", {}).get("hashes", [])
        c.tgs_hashes.extend(hashes)
        return (f"Kerberoast: {len(hashes)} TGS hash(es) captured", bool(hashes))

    async def _run_cred_dump(self, c: LateralCampaign, target: Optional[str]) -> tuple[str, bool]:
        if not target:
            return ("No target supplied for cred dump", False)
        if not c.creds:
            return ("No creds for secretsdump", False)
        cred = c.creds[0]
        result = await self.pe.secretsdump(
            target, cred.user, cred.password or "",
            nthash=cred.nthash or "",
        )
        if result.get("dry_run"):
            return ("secretsdump dry-run (approval not granted)", False)
        return (f"secretsdump returncode={result.get('returncode')}, "
                f"ok={result.get('ok')}", bool(result.get("ok")))

    async def _run_lateral_hop(self, c: LateralCampaign, target: Optional[str]) -> tuple[str, bool]:
        if not target:
            return ("No target for lateral hop", False)
        if not c.creds:
            return ("No creds for lateral hop", False)
        cred = c.creds[0]
        result = await self.pe.psexec(
            target, cred.user, cred.password or "",
            nthash=cred.nthash or "",
            command="whoami",
        )
        if result.get("dry_run"):
            return ("psexec dry-run (approval not granted)", False)
        if result.get("ok"):
            c.owned_hosts.add(target)
            return (f"Lateral hop SUCCESS to {target}", True)
        return (f"Lateral hop to {target} failed", False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _already_done(self, c: LateralCampaign, state: LateralState) -> bool:
        return any(s.state == state for s in c.history)

    def _consecutive_failures(self, c: LateralCampaign) -> int:
        n = 0
        for s in reversed(c.history):
            if s.succeeded:
                break
            n += 1
        return n
