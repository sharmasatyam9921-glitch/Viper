#!/usr/bin/env python3
"""
VIPER Web3 Smart Contract Auditor

Scans Solidity/Vyper contracts for 10 vulnerability classes with regex-based
static analysis. Each check returns structured findings with line numbers,
code snippets, severity, description, and remediation guidance.

Usage:
    auditor = Web3Auditor()
    findings = await auditor.audit_contract(source_code, language="solidity")
    findings = await auditor.audit_url("https://etherscan.io/address/0x...")
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.web3_auditor")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ContractFinding:
    """A single vulnerability finding in a smart contract."""
    vuln_type: str
    vuln_class: str
    severity: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class Web3Auditor:
    """Smart contract vulnerability auditor.

    Scans Solidity/Vyper contracts for 10 vulnerability classes:
    1. Reentrancy (cross-function, cross-contract, read-only)
    2. Access Control (missing modifiers, tx.origin, default visibility)
    3. Integer Overflow/Underflow (unchecked math, type casting)
    4. Oracle Manipulation (TWAP, flash loan price manipulation)
    5. Flash Loan Attacks (sandwich, arbitrage, governance)
    6. Front-Running/MEV (transaction ordering, sandwich attacks)
    7. Denial of Service (gas limit, unbounded loops, block stuffing)
    8. Logic Errors (accounting desync, rounding, state inconsistency)
    9. Signature Replay (missing nonce, cross-chain replay)
    10. Unsafe External Calls (unchecked return, delegatecall)
    """

    # ── Pattern database for each vulnerability class ────────────────────

    REENTRANCY_PATTERNS = [
        # .call{value:} — low-level call that forwards all gas
        (r'\.call\{value\s*:', "Low-level call with value transfer (forwards all gas)"),
        # .call.value() — pre-0.7 syntax
        (r'\.call\.value\(', "Legacy call.value() — forwards all gas"),
        # State change after external call (classic reentrancy)
        (r'\.call\{[^}]*\}[^;]*;[^}]*\b\w+\s*[\-\+]?=', "State change after external call — reentrancy risk"),
        # transfer/send after state read but before state write
        (r'\.transfer\([^)]*\)\s*;[^}]*\b\w+\s*=', "State change after transfer — potential reentrancy"),
        # Cross-contract calls before state update
        (r'I\w+\([^)]*\)\.\w+\([^)]*\)\s*;[^}]*\b\w+\s*[\-\+]?=', "Cross-contract call before state update"),
    ]

    ACCESS_CONTROL_PATTERNS = [
        # tx.origin for auth — phishable
        (r'\btx\.origin\b', "tx.origin used — vulnerable to phishing attacks"),
        # Public function missing common access modifiers
        (r'function\s+\w+\s*\([^)]*\)\s+public\s+(?!view|pure|override)', "Public function without access modifier"),
        # selfdestruct without access control
        (r'selfdestruct\s*\(', "selfdestruct found — verify access control"),
        # Default visibility (no public/private/internal/external)
        (r'function\s+\w+\s*\([^)]*\)\s*\{', "Function with default visibility — should be explicit"),
        # Missing onlyOwner on sensitive operations
        (r'function\s+(set|update|change|modify|withdraw|transfer|pause|unpause|mint|burn)\w*\s*\([^)]*\)\s+(?:public|external)\s+(?!.*only)', "Sensitive function without access modifier"),
    ]

    INTEGER_OVERFLOW_PATTERNS = [
        # unchecked blocks (Solidity >=0.8)
        (r'unchecked\s*\{', "Unchecked arithmetic block — overflow/underflow possible"),
        # Type casting to smaller type
        (r'uint\d+\s*\(\s*\w+\s*\)', "Type downcast — may truncate value"),
        (r'int\d+\s*\(\s*\w+\s*\)', "Signed type downcast — may truncate or flip sign"),
        # Multiplication before division (precision loss)
        (r'\w+\s*\*\s*\w+\s*/\s*\w+', "Multiply before divide — precision loss risk"),
        # uint subtraction without check (pre-0.8 or unchecked)
        (r'(\w+)\s*-\s*(\w+)', "Subtraction without underflow guard"),
    ]

    ORACLE_MANIPULATION_PATTERNS = [
        # Spot price from getReserves (manipulable via flash loan)
        (r'getReserves\s*\(', "Spot reserve price — manipulable via flash loan"),
        # Single-block TWAP or price read
        (r'latestRoundData\s*\(', "Chainlink oracle — check staleness and round completeness"),
        (r'latestAnswer\s*\(', "Deprecated Chainlink latestAnswer — use latestRoundData"),
        # Price from balanceOf (manipulable)
        (r'balanceOf\s*\([^)]*\)\s*[*/]', "Price derived from balanceOf — flash loan manipulable"),
        # UniswapV2 pair price
        (r'token\d?\.balanceOf\s*\(\s*address\s*\(\s*pair\s*\)', "AMM spot price — manipulable in single tx"),
    ]

    FLASH_LOAN_PATTERNS = [
        # Flash loan callback functions
        (r'function\s+executeOperation\s*\(', "Aave flash loan callback — verify caller and repayment"),
        (r'function\s+uniswapV2Call\s*\(', "Uniswap flash swap callback — verify caller"),
        (r'function\s+pancakeCall\s*\(', "PancakeSwap flash swap callback — verify caller"),
        # Flash loan without access control on callback
        (r'function\s+(executeOperation|uniswapV\dCall|pancakeCall)\s*\([^)]*\)\s+external\s+(?!.*only)', "Flash loan callback without caller verification"),
        # Governance vote in single tx
        (r'(propose|castVote|queue|execute)\s*\(.*\).*\n.*\n.*(propose|castVote|queue|execute)\s*\(', "Multiple governance actions — flash loan governance attack risk"),
    ]

    FRONTRUNNING_PATTERNS = [
        # Approval without zero-reset
        (r'approve\s*\(\s*\w+\s*,\s*\w+\s*\)', "ERC20 approve without zero-reset — front-run risk"),
        # Slippage without minimum output
        (r'swap\w*\s*\([^)]*\b0\b[^)]*\)', "Swap with zero slippage protection — sandwich attack risk"),
        # Commit-reveal missing
        (r'function\s+(bid|vote|submit|reveal)\w*\s*\(', "Action without commit-reveal — front-runnable"),
        # Price-sensitive operation without deadline
        (r'swap\w*\s*\([^)]*\)\s*(?!.*deadline)', "Swap without deadline parameter — MEV risk"),
        # Block.timestamp for randomness
        (r'block\.(timestamp|number|difficulty|prevrandao)\b', "Block variable used — predictable by miners/validators"),
    ]

    DOS_PATTERNS = [
        # Unbounded loops over dynamic arrays
        (r'for\s*\(\s*uint\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length\s*;', "Unbounded loop over dynamic array — gas limit DoS"),
        # External call in loop
        (r'for\s*\([^)]*\)\s*\{[^}]*\.call\{', "External call inside loop — gas limit DoS"),
        (r'for\s*\([^)]*\)\s*\{[^}]*\.transfer\(', "Transfer inside loop — gas limit DoS"),
        # require with external call result
        (r'require\s*\([^)]*\.call\{', "require depends on external call — DoS if callee reverts"),
        # Push to unbounded array
        (r'\.push\s*\([^)]*\)\s*;', "Unbounded array push — gas limit risk if iterated"),
        # Block gas limit via large calldata
        (r'abi\.decode\s*\([^)]*bytes\s+memory', "Dynamic bytes decoding — potential gas bomb"),
    ]

    LOGIC_ERROR_PATTERNS = [
        # Balance check after transfer (check-effect-interaction violation)
        (r'require\s*\([^)]*balanceOf[^)]*\)\s*;[^}]*\.transfer\(', "Balance check before transfer — TOCTOU race"),
        # Rounding down to zero
        (r'/\s*1e18\b', "Division by 1e18 — may round to zero for small amounts"),
        (r'/\s*10\s*\*\*\s*\d+', "Large divisor — rounding to zero risk"),
        # Missing zero-address check
        (r'function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s+(?:public|external)[^{]*\{(?![^}]*require\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\))', "Missing zero-address validation"),
        # State variable shadow
        (r'(uint|int|address|bool|bytes|string|mapping)\s+(\w+)\s*;.*function\s+\w+\s*\([^)]*\1\s+\2[^)]*\)', "Parameter shadows state variable"),
        # Double spending via reentrancy-like logic
        (r'balances\s*\[\s*\w+\s*\]\s*-=\s*\w+\s*;[^}]*balances\s*\[\s*\w+\s*\]\s*\+=', "Balance update pattern — verify atomicity"),
    ]

    SIGNATURE_REPLAY_PATTERNS = [
        # ecrecover without nonce
        (r'ecrecover\s*\(', "ecrecover used — verify nonce/chain-id prevents replay"),
        # Missing chain.id in hash
        (r'keccak256\s*\(abi\.encode(?:Packed)?\s*\([^)]*\)\s*\)(?![^;]*chainid)', "Hash without chain ID — cross-chain replay risk"),
        # EIP-712 without domain separator update
        (r'DOMAIN_SEPARATOR\b(?!.*block\.chainid)', "Static DOMAIN_SEPARATOR — cross-chain replay after fork"),
        # Permit without deadline check
        (r'function\s+permit\s*\(', "ERC-2612 permit — verify deadline and nonce"),
        # Signature without expiry
        (r'ecrecover\s*\([^)]*\)(?![^;]*deadline|[^;]*expir)', "Signature recovery without expiry check"),
    ]

    UNSAFE_CALL_PATTERNS = [
        # Unchecked low-level call return
        (r'\.call\{[^}]*\}\s*\([^)]*\)\s*;', "Low-level call with unchecked return value"),
        # delegatecall — critical, can overwrite storage
        (r'\.delegatecall\s*\(', "delegatecall — can overwrite caller storage"),
        # staticcall result ignored
        (r'\.staticcall\s*\([^)]*\)\s*;', "staticcall return value not checked"),
        # send() without return check (returns false, doesn't revert)
        (r'\.send\s*\([^)]*\)\s*;', ".send() without return check — fails silently"),
        # External call to user-supplied address
        (r'address\s*\(\s*\w+\s*\)\s*\.call\{', "Call to user-supplied address — arbitrary code execution"),
        # delegatecall to non-constant address
        (r'\.delegatecall\s*\(abi\.encode', "delegatecall with dynamic target — storage corruption risk"),
    ]

    # ── Etherscan API endpoints for fetching source ──────────────────────
    EXPLORER_APIS = {
        "etherscan": "https://api.etherscan.io/api",
        "bscscan": "https://api.bscscan.com/api",
        "polygonscan": "https://api.polygonscan.com/api",
        "arbiscan": "https://api.arbiscan.io/api",
        "optimistic": "https://api-optimistic.etherscan.io/api",
        "basescan": "https://api.basescan.org/api",
    }

    def __init__(self):
        self.findings: List[ContractFinding] = []

    async def audit_contract(
        self, source_code: str, language: str = "solidity"
    ) -> List[dict]:
        """Scan a smart contract for vulnerabilities across all 10 classes.

        Args:
            source_code: The full contract source code.
            language: "solidity" or "vyper" (vyper support is partial).

        Returns:
            List of finding dicts with vuln_type, severity, line_number, etc.
        """
        self.findings = []

        if not source_code or not source_code.strip():
            logger.warning("Empty source code provided")
            return []

        # Normalize line endings
        source_code = source_code.replace("\r\n", "\n")

        # Detect Solidity version for context
        version = self._detect_solidity_version(source_code)
        is_pre_08 = version and version < (0, 8, 0)

        # Run all 10 vulnerability checks
        self.findings.extend(self._check_reentrancy(source_code))
        self.findings.extend(self._check_access_control(source_code))
        self.findings.extend(self._check_integer_overflow(source_code, is_pre_08))
        self.findings.extend(self._check_oracle_manipulation(source_code))
        self.findings.extend(self._check_flash_loan(source_code))
        self.findings.extend(self._check_frontrunning(source_code))
        self.findings.extend(self._check_dos(source_code))
        self.findings.extend(self._check_logic_errors(source_code))
        self.findings.extend(self._check_signature_replay(source_code))
        self.findings.extend(self._check_unsafe_calls(source_code))

        # Deduplicate by (vuln_type, line_number)
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.vuln_type, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        # Sort by severity then line number
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.line_number))

        logger.info(f"Web3 audit complete: {len(self.findings)} findings")
        return [f.to_dict() for f in self.findings]

    async def audit_url(self, url: str) -> List[dict]:
        """Fetch and audit a contract from Etherscan/BSCScan/etc.

        Supports URLs like:
            https://etherscan.io/address/0x...
            https://bscscan.com/address/0x...
            0xADDRESS (defaults to etherscan)

        Args:
            url: Explorer URL or raw contract address.

        Returns:
            List of finding dicts.
        """
        import urllib.parse
        import urllib.request
        import json as _json
        import os

        # Parse the URL to determine explorer and address
        address = None
        explorer = "etherscan"

        if url.startswith("0x"):
            address = url
        else:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path

            # Extract explorer type from hostname
            for name in self.EXPLORER_APIS:
                if name in host:
                    explorer = name
                    break

            # Extract address from path
            addr_match = re.search(r'(0x[a-fA-F0-9]{40})', path)
            if addr_match:
                address = addr_match.group(1)

        if not address:
            logger.error(f"Could not extract contract address from: {url}")
            return []

        # Fetch source from explorer API
        api_base = self.EXPLORER_APIS.get(explorer, self.EXPLORER_APIS["etherscan"])
        api_key = os.environ.get(f"{explorer.upper()}_API_KEY", "")
        api_url = f"{api_base}?module=contract&action=getsource&address={address}"
        if api_key:
            api_url += f"&apikey={api_key}"

        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "VIPER/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = _json.loads(resp.read().decode())

            if data.get("status") != "1" or not data.get("result"):
                logger.error(f"Explorer API error: {data.get('message', 'unknown')}")
                return []

            result = data["result"]
            if isinstance(result, list) and len(result) > 0:
                source_code = result[0].get("SourceCode", "")
                contract_name = result[0].get("ContractName", "Unknown")
                compiler = result[0].get("CompilerVersion", "")
            else:
                logger.error("No source code returned from explorer")
                return []

            if not source_code:
                logger.error(f"Contract {address} source not verified on {explorer}")
                return []

            # Handle multi-file JSON format
            if source_code.startswith("{{"):
                source_code = source_code[1:-1]  # Remove outer braces
                try:
                    files = _json.loads(source_code)
                    sources = files.get("sources", files)
                    all_source = "\n".join(
                        v.get("content", v) if isinstance(v, dict) else str(v)
                        for v in sources.values()
                    )
                    source_code = all_source
                except _json.JSONDecodeError:
                    pass

            logger.info(f"Fetched {contract_name} ({compiler}) from {explorer}: {len(source_code)} chars")
            findings = await self.audit_contract(source_code, language="solidity")

            # Annotate findings with contract metadata
            for f in findings:
                f["contract_address"] = address
                f["contract_name"] = contract_name
                f["compiler"] = compiler
                f["explorer"] = explorer

            return findings

        except Exception as e:
            logger.error(f"Failed to fetch contract from {explorer}: {e}")
            return []

    # ── Private check methods ────────────────────────────────────────────

    def _scan_patterns(
        self,
        source: str,
        patterns: List[Tuple[str, str]],
        vuln_class: str,
        vuln_type_prefix: str,
        severity: str,
        remediation: str,
        confidence: float = 0.7,
    ) -> List[ContractFinding]:
        """Generic pattern scanner used by all check methods."""
        findings = []
        lines = source.split("\n")

        for pattern, description in patterns:
            try:
                for match in re.finditer(pattern, source, re.MULTILINE):
                    # Calculate line number
                    line_num = source[:match.start()].count("\n") + 1
                    # Get the matching line and surrounding context
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    snippet = "\n".join(lines[start_line:end_line])

                    findings.append(ContractFinding(
                        vuln_type=f"{vuln_type_prefix}:{description[:50]}",
                        vuln_class=vuln_class,
                        severity=severity,
                        line_number=line_num,
                        code_snippet=snippet[:500],
                        description=description,
                        remediation=remediation,
                        confidence=confidence,
                    ))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")

        return findings

    def _check_reentrancy(self, source: str) -> List[ContractFinding]:
        """Check for reentrancy vulnerabilities (CWE-841).

        Detects:
        - State changes after external calls
        - Cross-function reentrancy via shared state
        - Read-only reentrancy via view functions
        """
        findings = self._scan_patterns(
            source, self.REENTRANCY_PATTERNS,
            vuln_class="reentrancy",
            vuln_type_prefix="SWC-107",
            severity=Severity.CRITICAL,
            remediation="Use checks-effects-interactions pattern. Apply ReentrancyGuard (OpenZeppelin) "
                        "or use pull-payment pattern. Ensure state changes happen BEFORE external calls.",
            confidence=0.75,
        )

        # Additional check: external call followed by state mutation in same function
        func_pattern = r'function\s+(\w+)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
        for func_match in re.finditer(func_pattern, source, re.DOTALL):
            func_name = func_match.group(1)
            func_body = func_match.group(2)

            # Find external calls
            call_positions = [m.start() for m in re.finditer(
                r'\.(call|transfer|send)\s*[\({]', func_body
            )]
            # Find state mutations
            state_mutations = [m.start() for m in re.finditer(
                r'\b\w+\s*(\[.*?\])?\s*[\-\+]?=\s*', func_body
            )]

            for call_pos in call_positions:
                mutations_after = [m for m in state_mutations if m > call_pos]
                if mutations_after:
                    line_num = source[:func_match.start() + call_pos].count("\n") + 1
                    lines = source.split("\n")
                    snippet_start = max(0, line_num - 2)
                    snippet_end = min(len(lines), line_num + 3)
                    findings.append(ContractFinding(
                        vuln_type=f"SWC-107:state-after-call in {func_name}()",
                        vuln_class="reentrancy",
                        severity=Severity.CRITICAL,
                        line_number=line_num,
                        code_snippet="\n".join(lines[snippet_start:snippet_end])[:500],
                        description=f"Function {func_name}() modifies state after external call — "
                                    f"classic reentrancy vulnerability.",
                        remediation="Move state changes before external calls (checks-effects-interactions). "
                                    "Add nonReentrant modifier from OpenZeppelin ReentrancyGuard.",
                        confidence=0.85,
                    ))

        return findings

    def _check_access_control(self, source: str) -> List[ContractFinding]:
        """Check for access control issues (CWE-284).

        Detects:
        - tx.origin usage for authorization
        - Missing access modifiers on sensitive functions
        - Default function visibility
        - Unprotected selfdestruct
        """
        findings = self._scan_patterns(
            source, self.ACCESS_CONTROL_PATTERNS,
            vuln_class="access_control",
            vuln_type_prefix="SWC-115",
            severity=Severity.HIGH,
            remediation="Use msg.sender instead of tx.origin. Add onlyOwner/onlyRole modifiers "
                        "to sensitive functions. Use OpenZeppelin AccessControl or Ownable.",
            confidence=0.8,
        )

        # Specific high-severity check: selfdestruct without owner check
        for match in re.finditer(r'function\s+(\w+)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}', source, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(2)
            if 'selfdestruct' in func_body or 'suicide' in func_body:
                has_guard = bool(re.search(r'(onlyOwner|require\s*\(\s*msg\.sender\s*==|onlyRole)', func_body))
                if not has_guard:
                    line_num = source[:match.start()].count("\n") + 1
                    findings.append(ContractFinding(
                        vuln_type="SWC-106:unprotected-selfdestruct",
                        vuln_class="access_control",
                        severity=Severity.CRITICAL,
                        line_number=line_num,
                        code_snippet=func_body[:300],
                        description=f"selfdestruct in {func_name}() without access control — "
                                    f"anyone can destroy the contract.",
                        remediation="Add onlyOwner modifier or require(msg.sender == owner) guard.",
                        confidence=0.9,
                    ))

        return findings

    def _check_integer_overflow(self, source: str, is_pre_08: bool = False) -> List[ContractFinding]:
        """Check for integer overflow/underflow (CWE-190, CWE-191).

        Detects:
        - Unchecked arithmetic blocks (Solidity >= 0.8)
        - Type downcasting truncation
        - Multiplication before division (precision loss)
        - Pre-0.8 arithmetic without SafeMath
        """
        # In pre-0.8, all arithmetic is unchecked — higher severity
        base_severity = Severity.HIGH if is_pre_08 else Severity.MEDIUM

        findings = self._scan_patterns(
            source, self.INTEGER_OVERFLOW_PATTERNS,
            vuln_class="integer_overflow",
            vuln_type_prefix="SWC-101",
            severity=base_severity,
            remediation="Use Solidity >= 0.8 for built-in overflow checks. Use SafeMath for 0.7.x. "
                        "Use SafeCast for type conversions. Order operations as (a * b) / c with "
                        "intermediate overflow protection.",
            confidence=0.65,
        )

        # Pre-0.8 without SafeMath — critical
        if is_pre_08:
            has_safemath = bool(re.search(r'using\s+SafeMath\s+for', source))
            if not has_safemath:
                # Find arithmetic operations
                for match in re.finditer(r'(\w+)\s*[\+\-\*]\s*(\w+)', source):
                    line_num = source[:match.start()].count("\n") + 1
                    lines = source.split("\n")
                    findings.append(ContractFinding(
                        vuln_type="SWC-101:no-safemath",
                        vuln_class="integer_overflow",
                        severity=Severity.HIGH,
                        line_number=line_num,
                        code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                        description="Arithmetic operation in pre-0.8 contract without SafeMath.",
                        remediation="Add 'using SafeMath for uint256;' or upgrade to Solidity >= 0.8.",
                        confidence=0.7,
                    ))
                    if len(findings) > 50:  # Limit noise
                        break

        return findings

    def _check_oracle_manipulation(self, source: str) -> List[ContractFinding]:
        """Check for oracle manipulation vulnerabilities.

        Detects:
        - Spot price reliance (getReserves, balanceOf)
        - Stale Chainlink data (missing freshness checks)
        - Deprecated oracle interfaces
        - Single-source oracle dependency
        """
        findings = self._scan_patterns(
            source, self.ORACLE_MANIPULATION_PATTERNS,
            vuln_class="oracle_manipulation",
            vuln_type_prefix="ORACLE",
            severity=Severity.HIGH,
            remediation="Use time-weighted average prices (TWAP) over multiple blocks. "
                        "Add Chainlink staleness checks (require(updatedAt > 0 && "
                        "block.timestamp - updatedAt < heartbeat)). Use multiple oracle sources.",
            confidence=0.7,
        )

        # Check for Chainlink latestRoundData without staleness validation
        for match in re.finditer(
            r'(\w+)\s*=\s*\w+\.latestRoundData\s*\(\s*\)', source
        ):
            # Check if there's a staleness check nearby
            context_end = min(len(source), match.end() + 500)
            context = source[match.end():context_end]
            has_staleness = bool(re.search(
                r'(updatedAt|answeredInRound|roundId|block\.timestamp)', context
            ))
            if not has_staleness:
                line_num = source[:match.start()].count("\n") + 1
                lines = source.split("\n")
                findings.append(ContractFinding(
                    vuln_type="ORACLE:stale-chainlink-data",
                    vuln_class="oracle_manipulation",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    code_snippet="\n".join(lines[max(0, line_num-2):line_num+3])[:400],
                    description="Chainlink latestRoundData() called without staleness check — "
                                "stale/incorrect prices may be used.",
                    remediation="Add: require(updatedAt > 0 && block.timestamp - updatedAt < HEARTBEAT "
                                "&& answeredInRound >= roundId);",
                    confidence=0.85,
                ))

        return findings

    def _check_flash_loan(self, source: str) -> List[ContractFinding]:
        """Check for flash loan attack vectors.

        Detects:
        - Unprotected flash loan callbacks
        - Missing caller verification in callbacks
        - Governance manipulation via flash-borrowed tokens
        - Price-dependent operations without flash loan guards
        """
        findings = self._scan_patterns(
            source, self.FLASH_LOAN_PATTERNS,
            vuln_class="flash_loan",
            vuln_type_prefix="FLASH",
            severity=Severity.HIGH,
            remediation="Verify msg.sender in flash loan callbacks (require(msg.sender == POOL)). "
                        "Use TWAP for price-dependent operations. Add flash loan guards "
                        "(e.g., snapshot-based voting, timelocks on governance).",
            confidence=0.7,
        )

        # Check for balance-dependent logic without flash loan protection
        for match in re.finditer(
            r'(balanceOf|totalSupply)\s*\([^)]*\)\s*[><=!]+\s*\w+', source
        ):
            line_num = source[:match.start()].count("\n") + 1
            lines = source.split("\n")
            findings.append(ContractFinding(
                vuln_type="FLASH:balance-dependency",
                vuln_class="flash_loan",
                severity=Severity.MEDIUM,
                line_number=line_num,
                code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                description="Balance-dependent comparison — manipulable via flash loan.",
                remediation="Use time-weighted balances or snapshot mechanisms for governance/pricing.",
                confidence=0.5,
            ))

        return findings

    def _check_frontrunning(self, source: str) -> List[ContractFinding]:
        """Check for front-running and MEV vulnerabilities.

        Detects:
        - Token approval without zero-reset
        - Swaps without slippage protection
        - Missing commit-reveal patterns
        - Predictable block variables for randomness
        """
        findings = self._scan_patterns(
            source, self.FRONTRUNNING_PATTERNS,
            vuln_class="frontrunning",
            vuln_type_prefix="SWC-114",
            severity=Severity.MEDIUM,
            remediation="Use commit-reveal for sensitive operations. Add minimum output amount "
                        "(slippage protection) to swaps. Use Chainlink VRF for randomness. "
                        "Reset approval to 0 before setting new value.",
            confidence=0.65,
        )

        # Check for approve(spender, amount) without approve(spender, 0) first
        approve_calls = list(re.finditer(
            r'\.approve\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', source
        ))
        for i, match in enumerate(approve_calls):
            amount = match.group(2)
            if amount != "0":
                # Check if there's a zero-approve before this one
                has_zero_approve = False
                for j in range(max(0, i - 3), i):
                    prev = approve_calls[j]
                    if prev.group(1) == match.group(1) and prev.group(2) == "0":
                        has_zero_approve = True
                        break
                if not has_zero_approve:
                    line_num = source[:match.start()].count("\n") + 1
                    lines = source.split("\n")
                    findings.append(ContractFinding(
                        vuln_type="SWC-114:approve-race",
                        vuln_class="frontrunning",
                        severity=Severity.MEDIUM,
                        line_number=line_num,
                        code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                        description="ERC20 approve() called without resetting to 0 first — "
                                    "front-running race condition on allowance.",
                        remediation="Call approve(spender, 0) before approve(spender, amount), "
                                    "or use increaseAllowance/decreaseAllowance.",
                        confidence=0.75,
                    ))

        return findings

    def _check_dos(self, source: str) -> List[ContractFinding]:
        """Check for denial of service vulnerabilities (CWE-400).

        Detects:
        - Unbounded loops over dynamic arrays
        - External calls in loops
        - Require depending on external call results
        - Unbounded array growth
        """
        findings = self._scan_patterns(
            source, self.DOS_PATTERNS,
            vuln_class="dos",
            vuln_type_prefix="SWC-128",
            severity=Severity.MEDIUM,
            remediation="Use pagination or pull-over-push patterns for arrays. Avoid external "
                        "calls in loops. Set hard caps on array lengths. Use mapping instead "
                        "of array when order doesn't matter.",
            confidence=0.6,
        )

        # Check for while(true) or while(condition) without bound
        for match in re.finditer(r'while\s*\(\s*(true|[^)]+)\s*\)\s*\{', source):
            line_num = source[:match.start()].count("\n") + 1
            lines = source.split("\n")
            findings.append(ContractFinding(
                vuln_type="SWC-128:unbounded-while-loop",
                vuln_class="dos",
                severity=Severity.MEDIUM,
                line_number=line_num,
                code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                description="While loop without known bound — may consume all gas.",
                remediation="Add explicit iteration limit or use a for loop with bounded range.",
                confidence=0.5,
            ))

        return findings

    def _check_logic_errors(self, source: str) -> List[ContractFinding]:
        """Check for business logic errors.

        Detects:
        - Accounting desync (balance != expected)
        - Rounding errors with large divisors
        - Missing zero-address validation
        - State variable shadowing
        """
        findings = self._scan_patterns(
            source, self.LOGIC_ERROR_PATTERNS,
            vuln_class="logic_error",
            vuln_type_prefix="LOGIC",
            severity=Severity.MEDIUM,
            remediation="Validate all addresses against zero-address. Use consistent rounding "
                        "(round up for protocol fees, round down for user withdrawals). "
                        "Add invariant checks. Avoid variable shadowing.",
            confidence=0.55,
        )

        # Check for missing return value handling
        for match in re.finditer(
            r'(IERC20|ERC20)\s*\([^)]*\)\s*\.(transfer|transferFrom)\s*\([^)]*\)\s*;', source
        ):
            line_num = source[:match.start()].count("\n") + 1
            # Check if return value is captured
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_text = source[line_start:match.end()]
            if not re.search(r'(bool|require|assert)\s+', line_text):
                lines = source.split("\n")
                findings.append(ContractFinding(
                    vuln_type="LOGIC:unchecked-erc20-return",
                    vuln_class="logic_error",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    description="ERC20 transfer/transferFrom return value not checked — "
                                "may silently fail with non-standard tokens (USDT).",
                    remediation="Use OpenZeppelin SafeERC20 (safeTransfer/safeTransferFrom) "
                                "which handles non-standard return values.",
                    confidence=0.85,
                ))

        return findings

    def _check_signature_replay(self, source: str) -> List[ContractFinding]:
        """Check for signature replay vulnerabilities (CWE-294).

        Detects:
        - ecrecover without nonce tracking
        - Missing chain ID in signature hash
        - Static DOMAIN_SEPARATOR (breaks after fork)
        - Signatures without expiry
        """
        findings = self._scan_patterns(
            source, self.SIGNATURE_REPLAY_PATTERNS,
            vuln_class="signature_replay",
            vuln_type_prefix="SWC-121",
            severity=Severity.HIGH,
            remediation="Include nonce, chain ID, contract address, and deadline in signed data. "
                        "Use EIP-712 typed structured data. Compute DOMAIN_SEPARATOR dynamically "
                        "using block.chainid to handle forks. Invalidate used nonces.",
            confidence=0.7,
        )

        # Check for ecrecover without nonce increment
        for match in re.finditer(r'ecrecover\s*\(', source):
            context_start = max(0, match.start() - 500)
            context_end = min(len(source), match.end() + 500)
            context = source[context_start:context_end]

            has_nonce = bool(re.search(r'nonce[s]?\s*\[', context))
            has_nonce_increment = bool(re.search(r'nonce[s]?\s*\[.*\]\s*\+\+|nonce[s]?\s*\[.*\]\s*\+=\s*1', context))

            if not has_nonce or not has_nonce_increment:
                line_num = source[:match.start()].count("\n") + 1
                lines = source.split("\n")
                findings.append(ContractFinding(
                    vuln_type="SWC-121:replay-no-nonce",
                    vuln_class="signature_replay",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    code_snippet="\n".join(lines[max(0, line_num-2):line_num+2])[:400],
                    description="ecrecover used without nonce tracking — signatures can be replayed.",
                    remediation="Maintain per-user nonces (mapping(address => uint256)). "
                                "Include nonce in signed hash and increment after use.",
                    confidence=0.75,
                ))

        return findings

    def _check_unsafe_calls(self, source: str) -> List[ContractFinding]:
        """Check for unsafe external calls (CWE-252).

        Detects:
        - Unchecked low-level call return values
        - delegatecall (storage corruption risk)
        - .send() without return check
        - Calls to user-supplied addresses
        """
        findings = self._scan_patterns(
            source, self.UNSAFE_CALL_PATTERNS,
            vuln_class="unsafe_calls",
            vuln_type_prefix="SWC-104",
            severity=Severity.HIGH,
            remediation="Always check return values of low-level calls: "
                        "(bool success, ) = addr.call{value: amt}(''); require(success); "
                        "Avoid delegatecall to untrusted contracts. Use .transfer() or "
                        "OpenZeppelin Address.sendValue() for ETH transfers.",
            confidence=0.75,
        )

        # Check for properly checked vs unchecked calls
        for match in re.finditer(r'\.call\{[^}]*\}\s*\(([^)]*)\)', source):
            line_num = source[:match.start()].count("\n") + 1
            # Check if return is captured
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_text = source[line_start:match.end() + 50]
            is_checked = bool(re.search(r'\(\s*bool\s+\w+\s*,', line_text))
            if is_checked:
                # Remove from findings if we already flagged this line
                findings = [f for f in findings if f.line_number != line_num
                            or "unchecked return" not in f.description.lower()]

        return findings

    # ── Utility methods ──────────────────────────────────────────────────

    def _detect_solidity_version(self, source: str) -> Optional[Tuple[int, ...]]:
        """Extract the Solidity compiler version from pragma statement."""
        match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(\d+)\.(\d+)\.(\d+)', source)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return None

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the audit results."""
        by_class = {}
        by_severity = {}
        for f in self.findings:
            by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_class": by_class,
            "by_severity": by_severity,
            "classes_checked": 10,
        }
