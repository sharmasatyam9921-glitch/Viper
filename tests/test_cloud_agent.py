"""Tests for CloudAgent — Docker-based distributed scanning."""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from pathlib import Path
from core.cloud_agent import CloudAgent


@pytest.fixture
def agent(tmp_path):
    return CloudAgent(work_dir=tmp_path / "cloud")


class TestAvailability:
    def test_available_when_docker_found(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")
            assert agent.is_available() is True

    def test_unavailable_when_no_docker(self, tmp_path):
        with patch("shutil.which", return_value=None):
            agent = CloudAgent(work_dir=tmp_path / "cloud")
            assert agent.is_available() is False

    def test_status_docker_not_found(self, tmp_path):
        with patch("shutil.which", return_value=None):
            agent = CloudAgent(work_dir=tmp_path / "cloud")
            assert agent.status == "docker_not_found"

    def test_status_ready(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")
            assert agent.status == "ready"

    def test_instances_initially_empty(self, agent):
        assert agent.instances == []


class TestDeploy:
    async def test_deploy_no_docker(self, tmp_path):
        with patch("shutil.which", return_value=None):
            agent = CloudAgent(work_dir=tmp_path / "cloud")
            result = await agent.deploy("http://test.com")
            assert result["status"] == "error"
            assert "Docker not found" in result["message"]

    async def test_deploy_success(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")

            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"abc123def456\n", b""))

            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await agent.deploy("http://test.com")
                assert result["status"] == "deployed"
                assert "instance_id" in result
                assert result["target"] == "http://test.com"
                assert len(agent.instances) == 1

    async def test_deploy_failure(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")

            mock_proc = AsyncMock()
            mock_proc.returncode = 1
            mock_proc.communicate = AsyncMock(return_value=(b"", b"image not found"))

            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await agent.deploy("http://test.com")
                assert result["status"] == "error"


class TestCollectResults:
    async def test_collect_unknown_instance(self, agent):
        result = await agent.collect_results("nonexistent")
        assert result["status"] == "error"
        assert result["findings"] == []

    async def test_collect_with_findings(self, tmp_path):
        import json
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")

            # Simulate a deployed instance
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"container123\n", b""))

            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                result = await agent.deploy("http://test.com")
                instance_id = result["instance_id"]

            # Write fake findings
            findings_dir = tmp_path / "cloud" / instance_id / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            (findings_dir / "scan_results.json").write_text(
                json.dumps([{"type": "xss", "severity": "high"}])
            )

            # Mock docker inspect for status check
            mock_inspect = AsyncMock()
            mock_inspect.returncode = 0
            mock_inspect.communicate = AsyncMock(return_value=(b"exited\n", b""))

            with patch("asyncio.create_subprocess_exec", return_value=mock_inspect):
                results = await agent.collect_results(instance_id)
                assert results["findings_count"] == 1
                assert results["findings"][0]["type"] == "xss"


class TestTeardown:
    async def test_teardown_unknown_instance(self, agent):
        result = await agent.teardown("nonexistent")
        assert result is False

    async def test_teardown_success(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            agent = CloudAgent(work_dir=tmp_path / "cloud")

            # Deploy first
            mock_deploy = AsyncMock()
            mock_deploy.returncode = 0
            mock_deploy.communicate = AsyncMock(return_value=(b"container123\n", b""))

            with patch("asyncio.create_subprocess_exec", return_value=mock_deploy):
                result = await agent.deploy("http://test.com")
                instance_id = result["instance_id"]

            # Teardown
            mock_teardown = AsyncMock()
            mock_teardown.returncode = 0
            mock_teardown.communicate = AsyncMock(return_value=(b"", b""))

            with patch("asyncio.create_subprocess_exec", return_value=mock_teardown):
                success = await agent.teardown(instance_id)
                assert success is True
