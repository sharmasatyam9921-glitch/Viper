"""Cloud Agent — remote scanning via cloud instances.

Stub implementation. Full version will support:
- Docker-based remote VIPER instances
- AWS/GCP/Azure runner provisioning
- Distributed scan coordination
"""


class CloudAgent:
    """Manages remote VIPER instances for distributed scanning."""

    def __init__(self):
        self.available = False
        self.status = "not_configured"
        self.instances = []

    def is_available(self) -> bool:
        return self.available

    async def deploy(self, target: str, config: dict = None) -> dict:
        """Deploy a remote scanner instance."""
        return {
            "status": "not_implemented",
            "message": "Cloud agent not yet implemented. Use local scanning.",
        }

    async def collect_results(self, instance_id: str) -> dict:
        """Collect scan results from a remote instance."""
        return {"status": "not_implemented", "findings": []}

    async def teardown(self, instance_id: str) -> bool:
        """Tear down a remote scanner instance."""
        return False
