"""Cloud Agent — Docker-based distributed scanning.

Deploys VIPER scanner instances in Docker containers for parallel scanning.
Falls back gracefully when Docker is unavailable.
"""

import asyncio
import json
import logging
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("viper.cloud_agent")

PROJECT_ROOT = Path(__file__).parent.parent
DOCKER_IMAGE = "viper-scanner:latest"


@dataclass
class ScanInstance:
    """Metadata for a running scanner container."""
    instance_id: str
    container_id: str
    target: str
    status: str = "running"  # running, completed, failed, stopped
    started_at: str = ""
    findings_dir: str = ""


class CloudAgent:
    """Manages Docker-based VIPER scanner instances for distributed scanning.

    Usage:
        agent = CloudAgent()
        if agent.is_available():
            result = await agent.deploy("https://target.com")
            findings = await agent.collect_results(result["instance_id"])
            await agent.teardown(result["instance_id"])
    """

    def __init__(self, image: str = DOCKER_IMAGE, work_dir: Optional[Path] = None):
        self._image = image
        self._work_dir = work_dir or PROJECT_ROOT / "state" / "cloud_instances"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._instances: Dict[str, ScanInstance] = {}
        self._docker_path = shutil.which("docker")

    def is_available(self) -> bool:
        """Check if Docker is installed and accessible."""
        return self._docker_path is not None

    @property
    def status(self) -> str:
        if not self._docker_path:
            return "docker_not_found"
        return "ready" if not self._instances else "active"

    @property
    def instances(self) -> List[Dict]:
        return [
            {
                "instance_id": inst.instance_id,
                "target": inst.target,
                "status": inst.status,
                "started_at": inst.started_at,
            }
            for inst in self._instances.values()
        ]

    async def deploy(self, target: str, config: Optional[dict] = None) -> dict:
        """Deploy a Docker-based scanner instance.

        Args:
            target: Target URL to scan.
            config: Optional scan configuration (stealth_level, max_minutes, etc.)

        Returns:
            Dict with instance_id, status, and container_id.
        """
        if not self._docker_path:
            return {
                "status": "error",
                "message": "Docker not found. Install Docker to use distributed scanning.",
            }

        config = config or {}
        instance_id = f"viper-{uuid.uuid4().hex[:8]}"
        findings_dir = self._work_dir / instance_id / "findings"
        reports_dir = self._work_dir / instance_id / "reports"
        findings_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Build docker run command
        cmd = [
            self._docker_path, "run", "-d",
            "--name", instance_id,
            "--network", config.get("network", "host"),
            # Volume mounts for output collection
            "-v", f"{findings_dir}:/app/findings",
            "-v", f"{reports_dir}:/app/reports",
            # Resource limits
            "--memory", config.get("memory", "2g"),
            "--cpus", str(config.get("cpus", "1.0")),
            # Environment
            "-e", f"VIPER_TARGET={target}",
            "-e", f"VIPER_STEALTH={config.get('stealth_level', 1)}",
            "-e", f"VIPER_MAX_MINUTES={config.get('max_minutes', 30)}",
        ]

        # Forward API keys from host environment
        import os
        for env_key in ["ANTHROPIC_API_KEY", "SHODAN_API_KEY", "NUCLEI_API_KEY"]:
            val = os.environ.get(env_key)
            if val:
                cmd.extend(["-e", f"{env_key}={val}"])

        cmd.extend([self._image, "python", "viper.py", target, "--full", "--json"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode != 0:
                error_msg = stderr.decode().strip() if stderr else "Unknown error"
                logger.error("Docker deploy failed: %s", error_msg)
                return {
                    "status": "error",
                    "message": f"Container failed to start: {error_msg}",
                }

            container_id = stdout.decode().strip()[:12]
            instance = ScanInstance(
                instance_id=instance_id,
                container_id=container_id,
                target=target,
                status="running",
                started_at=datetime.now().isoformat(),
                findings_dir=str(findings_dir),
            )
            self._instances[instance_id] = instance

            logger.info("Deployed scanner %s for %s (container=%s)", instance_id, target, container_id)
            return {
                "status": "deployed",
                "instance_id": instance_id,
                "container_id": container_id,
                "target": target,
            }

        except asyncio.TimeoutError:
            logger.error("Docker deploy timed out for %s", target)
            return {"status": "error", "message": "Container launch timed out"}
        except FileNotFoundError:
            logger.error("Docker binary not found at %s", self._docker_path)
            return {"status": "error", "message": "Docker binary not found"}
        except OSError as e:
            logger.error("Docker deploy OS error: %s", e)
            return {"status": "error", "message": str(e)}

    async def collect_results(self, instance_id: str) -> dict:
        """Collect scan results from a scanner instance.

        Reads JSON findings from the instance's mounted findings directory.
        """
        instance = self._instances.get(instance_id)
        if not instance:
            return {"status": "error", "message": f"Unknown instance: {instance_id}", "findings": []}

        findings_dir = Path(instance.findings_dir)
        findings = []

        # Check container status
        try:
            proc = await asyncio.create_subprocess_exec(
                self._docker_path, "inspect", "-f", "{{.State.Status}}", instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            container_status = stdout.decode().strip()

            if container_status == "exited":
                instance.status = "completed"
            elif container_status == "running":
                instance.status = "running"
            else:
                instance.status = container_status

        except (OSError, asyncio.TimeoutError) as e:
            logger.warning("Could not check container status: %s", e)

        # Collect findings from JSON files
        if findings_dir.exists():
            for f in findings_dir.glob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        findings.extend(data)
                    elif isinstance(data, dict):
                        findings.append(data)
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning("Failed to read findings file %s: %s", f, e)

        return {
            "status": instance.status,
            "instance_id": instance_id,
            "target": instance.target,
            "findings": findings,
            "findings_count": len(findings),
        }

    async def teardown(self, instance_id: str) -> bool:
        """Stop and remove a scanner container.

        Returns True if successfully cleaned up.
        """
        instance = self._instances.get(instance_id)
        if not instance:
            logger.warning("Teardown requested for unknown instance: %s", instance_id)
            return False

        try:
            # Stop container
            proc = await asyncio.create_subprocess_exec(
                self._docker_path, "stop", "-t", "10", instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=20)

            # Remove container
            proc = await asyncio.create_subprocess_exec(
                self._docker_path, "rm", "-f", instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)

            instance.status = "stopped"
            logger.info("Torn down instance %s", instance_id)
            return True

        except (OSError, asyncio.TimeoutError) as e:
            logger.error("Teardown failed for %s: %s", instance_id, e)
            return False

    async def teardown_all(self) -> int:
        """Tear down all running instances. Returns count of successfully cleaned up."""
        count = 0
        for instance_id in list(self._instances.keys()):
            if await self.teardown(instance_id):
                count += 1
        return count

    async def get_logs(self, instance_id: str, tail: int = 100) -> str:
        """Get container logs for debugging."""
        instance = self._instances.get(instance_id)
        if not instance:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                self._docker_path, "logs", "--tail", str(tail), instance.container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            return (stdout or b"").decode() + (stderr or b"").decode()
        except (OSError, asyncio.TimeoutError) as e:
            logger.warning("Failed to get logs for %s: %s", instance_id, e)
            return ""
