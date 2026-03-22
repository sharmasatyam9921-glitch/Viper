#!/usr/bin/env python3
"""
VIPER 4.0 Attack Chain Graph Writer.

Background thread writer for persisting attack chains to the knowledge graph.
Fire-and-forget pattern: callers don't wait for graph writes.

Inspired by open-source pentesting frameworks.
"""

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("viper.chain_writer")


class ChainWriter:
    """
    Writes attack chain data to the GraphEngine in a background thread.

    Usage:
        writer = ChainWriter(graph_engine)
        chain_id = writer.start_chain(target="example.com")
        step_id = writer.add_step(chain_id, tool="nuclei", input="...", output="...", phase="scan")
        writer.add_finding(chain_id, step_id, finding_type="sqli", severity="high", ...)
        writer.add_decision(chain_id, decision="escalate to exploitation", reasoning="...")
        writer.end_chain(chain_id, status="completed")
    """

    def __init__(self, graph_engine, max_workers: int = 1):
        self._graph = graph_engine
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="chain_writer")
        self._active_chains: Dict[str, Dict] = {}

    def start_chain(self, target: str, session_id: str = None, attack_type: str = "unclassified") -> str:
        """Start a new attack chain. Returns chain_id."""
        chain_id = session_id or f"chain-{uuid.uuid4().hex[:12]}"
        chain_data = {
            "chain_id": chain_id,
            "target": target,
            "attack_type": attack_type,
            "status": "active",
            "started_at": datetime.now().isoformat(),
            "steps": [],
            "findings": [],
            "decisions": [],
            "failures": [],
        }
        self._active_chains[chain_id] = chain_data

        # Write to graph in background
        self._executor.submit(
            self._graph.add_attack_chain,
            chain_id,
            target=target,
            attack_type=attack_type,
            status="active",
            started_at=chain_data["started_at"],
        )

        logger.debug(f"Started chain {chain_id} for {target}")
        return chain_id

    def add_step(
        self,
        chain_id: str,
        tool: str,
        input_data: str = "",
        output_data: str = "",
        phase: str = "informational",
        thought: str = "",
        success: bool = False,
        duration_ms: float = 0,
    ) -> str:
        """Add an execution step to the chain. Returns step_id."""
        step_id = f"step-{uuid.uuid4().hex[:8]}"
        step_data = {
            "step_id": step_id,
            "chain_id": chain_id,
            "tool": tool,
            "input": input_data[:5000],  # Truncate large inputs
            "output": output_data[:5000],  # Truncate large outputs
            "phase": phase,
            "thought": thought[:2000],
            "success": success,
            "duration_ms": duration_ms,
            "timestamp": datetime.now().isoformat(),
        }

        if chain_id in self._active_chains:
            self._active_chains[chain_id]["steps"].append(step_data)

        # Write to graph in background
        self._executor.submit(self._write_step, step_data)

        return step_id

    def add_finding(
        self,
        chain_id: str,
        step_id: str = None,
        finding_type: str = "unknown",
        severity: str = "info",
        title: str = "",
        url: str = "",
        evidence: str = "",
        confidence: float = 0.0,
    ) -> str:
        """Record a finding discovered during the chain. Returns finding_id."""
        finding_id = f"cfind-{uuid.uuid4().hex[:8]}"
        finding_data = {
            "finding_id": finding_id,
            "chain_id": chain_id,
            "step_id": step_id,
            "finding_type": finding_type,
            "severity": severity,
            "title": title,
            "url": url,
            "evidence": evidence[:5000],
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
        }

        if chain_id in self._active_chains:
            self._active_chains[chain_id]["findings"].append(finding_data)

        self._executor.submit(self._write_finding, finding_data)

        return finding_id

    def add_decision(
        self,
        chain_id: str,
        decision: str,
        reasoning: str = "",
        alternatives: List[str] = None,
    ) -> str:
        """Record a strategic decision in the chain. Returns decision_id."""
        decision_id = f"dec-{uuid.uuid4().hex[:8]}"
        decision_data = {
            "decision_id": decision_id,
            "chain_id": chain_id,
            "decision": decision,
            "reasoning": reasoning,
            "alternatives": alternatives or [],
            "timestamp": datetime.now().isoformat(),
        }

        if chain_id in self._active_chains:
            self._active_chains[chain_id]["decisions"].append(decision_data)

        self._executor.submit(self._write_decision, decision_data)

        return decision_id

    def add_failure(
        self,
        chain_id: str,
        step_id: str = None,
        failure_type: str = "error",
        message: str = "",
        tool: str = "",
    ) -> str:
        """Record a failure in the chain. Returns failure_id."""
        failure_id = f"fail-{uuid.uuid4().hex[:8]}"
        failure_data = {
            "failure_id": failure_id,
            "chain_id": chain_id,
            "step_id": step_id,
            "failure_type": failure_type,
            "message": message[:2000],
            "tool": tool,
            "timestamp": datetime.now().isoformat(),
        }

        if chain_id in self._active_chains:
            self._active_chains[chain_id]["failures"].append(failure_data)

        self._executor.submit(self._write_failure, failure_data)

        return failure_id

    def end_chain(self, chain_id: str, status: str = "completed", summary: str = "") -> Dict:
        """End an active chain. Returns chain summary."""
        chain = self._active_chains.pop(chain_id, None)
        if not chain:
            return {"chain_id": chain_id, "status": "not_found"}

        chain["status"] = status
        chain["ended_at"] = datetime.now().isoformat()
        chain["summary"] = summary

        # Update graph
        self._executor.submit(
            self._graph.add_attack_chain,
            chain_id,
            status=status,
            ended_at=chain["ended_at"],
            steps_count=len(chain["steps"]),
            findings_count=len(chain["findings"]),
            failures_count=len(chain["failures"]),
        )

        logger.debug(
            f"Ended chain {chain_id}: {len(chain['steps'])} steps, "
            f"{len(chain['findings'])} findings, {len(chain['failures'])} failures"
        )

        return {
            "chain_id": chain_id,
            "status": status,
            "steps": len(chain["steps"]),
            "findings": len(chain["findings"]),
            "decisions": len(chain["decisions"]),
            "failures": len(chain["failures"]),
        }

    def get_active_chains(self) -> List[Dict]:
        """Get summary of all active chains."""
        return [
            {
                "chain_id": c["chain_id"],
                "target": c["target"],
                "status": c["status"],
                "steps": len(c["steps"]),
                "findings": len(c["findings"]),
                "started_at": c["started_at"],
            }
            for c in self._active_chains.values()
        ]

    def get_chain_trace(self, chain_id: str) -> Optional[Dict]:
        """Get full trace of a chain (active or from graph)."""
        if chain_id in self._active_chains:
            return self._active_chains[chain_id]

        # Try loading from graph
        chains = self._graph.find("AttackChain", chain_id=chain_id)
        if not chains:
            return None

        chain_node = chains[0]
        steps = self._graph.neighbors(chain_node["id"], rel_type="HAS_STEP")
        findings = self._graph.neighbors(chain_node["id"], rel_type="HAS_FINDING")

        return {
            "chain_id": chain_id,
            "status": chain_node.get("status", "unknown"),
            "target": chain_node.get("target", ""),
            "steps": steps,
            "findings": findings,
        }

    # ── Internal write methods ──

    def _write_step(self, step_data: Dict):
        try:
            self._graph.add_chain_step(
                step_data["step_id"],
                step_data["chain_id"],
                **{k: v for k, v in step_data.items() if k not in ("step_id", "chain_id")},
            )
        except Exception as e:
            logger.error(f"Failed to write step {step_data.get('step_id')}: {e}")

    def _write_finding(self, finding_data: Dict):
        try:
            self._graph.add_chain_finding(
                finding_data["finding_id"],
                finding_data["chain_id"],
                **{k: v for k, v in finding_data.items() if k not in ("finding_id", "chain_id")},
            )
        except Exception as e:
            logger.error(f"Failed to write finding {finding_data.get('finding_id')}: {e}")

    def _write_decision(self, decision_data: Dict):
        try:
            from core.graph_engine import CHAIN_DECISION, CHAIN_HAS_DECISION
            self._graph.backend.add_node(
                CHAIN_DECISION,
                decision_data["decision_id"],
                decision_data,
            )
            # Link to chain
            chains = self._graph.find("AttackChain", chain_id=decision_data["chain_id"])
            if chains:
                self._graph.link(chains[0]["id"], decision_data["decision_id"], CHAIN_HAS_DECISION)
        except Exception as e:
            logger.error(f"Failed to write decision: {e}")

    def _write_failure(self, failure_data: Dict):
        try:
            from core.graph_engine import CHAIN_FAILURE, CHAIN_HAS_FAILURE
            self._graph.backend.add_node(
                CHAIN_FAILURE,
                failure_data["failure_id"],
                failure_data,
            )
            chains = self._graph.find("AttackChain", chain_id=failure_data["chain_id"])
            if chains:
                self._graph.link(chains[0]["id"], failure_data["failure_id"], CHAIN_HAS_FAILURE)
        except Exception as e:
            logger.error(f"Failed to write failure: {e}")

    def shutdown(self):
        """Gracefully shutdown the writer."""
        self._executor.shutdown(wait=True)

    def __del__(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

    # ── Consumer-facing aliases ──

    def record_attack(self, target, attack_type, success=False, details=None):
        chain_id = self.start_chain(target=target, attack_type=attack_type)
        d = details or {}
        return self.add_step(
            chain_id, tool=attack_type, thought=f"Attack {attack_type}",
            success=success,
            input_data=d.get('payload', ''),
            output_data=d.get('output', ''),
        )

    def record_finding(self, target, finding):
        # Find or create a chain for this target
        active = [c for c in self._active_chains.values() if c["target"] == target]
        chain_id = active[0]["chain_id"] if active else self.start_chain(target=target)
        # Map consumer keys to add_finding params
        return self.add_finding(
            chain_id,
            finding_type=finding.get('type', finding.get('finding_type', 'unknown')),
            severity=finding.get('severity', 'info'),
            title=finding.get('title', finding.get('type', '')),
            url=finding.get('url', ''),
            evidence=finding.get('evidence', ''),
            confidence=finding.get('confidence', 0.0),
        )

    def get_attack_chains(self, target):
        chains = self._graph.find("AttackChain", target=target)
        return chains if chains else []
