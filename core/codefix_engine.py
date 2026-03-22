#!/usr/bin/env python3
"""
VIPER 4.0 Phase 5 — CodeFix Engine.

Given a vulnerability finding and a repository path, uses LLM to analyze code
and generate fixes. Can optionally create GitHub PRs.

Inspired by open-source pentesting frameworks.
"""

import difflib
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import codefix_tools as tools

logger = logging.getLogger("viper.codefix_engine")

# System prompt for the CodeFix LLM
CODEFIX_SYSTEM_PROMPT = """You are a security engineer fixing vulnerabilities in source code.

Given a vulnerability finding and code context, generate a minimal, correct fix.

Rules:
1. Fix ONLY the vulnerability — do not refactor unrelated code
2. Preserve existing code style and patterns
3. Add comments explaining the security fix (one line, concise)
4. If the fix requires importing new modules, include those imports
5. For injection vulns (SQLi, XSS, command injection): use parameterized queries, output encoding, or input validation
6. For secrets: replace hardcoded values with environment variables or config references
7. For dependencies: specify the exact patched version
8. For misconfigurations: set the correct secure value
9. Output ONLY the fixed code — no explanation needed

If you cannot determine the fix, output a JSON object: {"status": "needs_review", "reason": "..."} """

# Max iterations for the ReAct fix loop
MAX_FIX_ITERATIONS = 10


class CodeFixEngine:
    """
    Vulnerability code fix engine.

    Takes a finding (from TriageEngine) and a repository path, then:
    1. Locates the vulnerable code
    2. Generates a fix using LLM
    3. Writes the patch
    4. Optionally creates a GitHub PR
    """

    def __init__(self, model_router=None):
        """
        Args:
            model_router: Optional ModelRouter for LLM-powered fix generation.
                          If None, only manual fix suggestions are produced.
        """
        self._model_router = model_router

    async def fix_finding(self, finding: Dict, repo_path: str) -> Dict:
        """
        Fix a single vulnerability finding.

        Args:
            finding: Dict with keys: id, title, finding_type, affected_assets,
                     cve_ids, cwe_ids, description, recommendation, evidence, category
            repo_path: Absolute path to the repository root.

        Returns:
            Dict with keys: finding_id, status, patch_file, pr_url, files_changed, error
        """
        finding_id = finding.get("id", "unknown")
        logger.info(f"Fixing finding: {finding.get('title', finding_id)}")

        result = {
            "finding_id": finding_id,
            "status": "pending",
            "patch_file": None,
            "pr_url": None,
            "files_changed": [],
            "error": None,
        }

        try:
            # Step 1: Locate vulnerable code
            logger.info(f"Step 1: Locating vulnerable code in {repo_path}")
            locations = self._locate_vulnerable_code(finding, repo_path)
            if not locations:
                result["status"] = "not_found"
                result["error"] = "Could not locate vulnerable code in repository"
                logger.warning(f"No code locations found for {finding_id}")
                return result

            logger.info(f"Found {len(locations)} potential locations")

            # Step 2: Read code context
            code_contexts = []
            for loc in locations[:5]:  # Max 5 files
                content = tools.read_tool(loc["file"], offset=max(0, loc.get("line", 1) - 20), limit=60)
                code_contexts.append({
                    "file": loc["file"],
                    "line": loc.get("line", 0),
                    "match": loc.get("match", ""),
                    "content": content,
                })

            # Step 3: Generate fix
            if self._model_router:
                logger.info("Step 3: Generating LLM-powered fix")
                fixes = await self._generate_fixes_llm(finding, code_contexts, repo_path)
            else:
                logger.info("Step 3: Generating rule-based fix suggestion")
                fixes = self._generate_fixes_rules(finding, code_contexts)

            if not fixes:
                result["status"] = "no_fix"
                result["error"] = "Could not generate a fix"
                return result

            # Step 4: Apply fixes and create patches
            patches = []
            files_changed = []
            for fix in fixes:
                file_path = fix.get("file")
                old_text = fix.get("old_text", "")
                new_text = fix.get("new_text", "")

                if not file_path or not old_text or not new_text:
                    continue

                # Read original
                original = Path(file_path).read_text(encoding='utf-8', errors='replace')

                # Apply fix
                success = tools.edit_tool(file_path, old_text, new_text)
                if success:
                    fixed = Path(file_path).read_text(encoding='utf-8', errors='replace')
                    patch = self._create_patch(file_path, original, fixed)
                    patches.append(patch)
                    files_changed.append(str(Path(file_path).relative_to(repo_path)))
                    logger.info(f"Applied fix to {file_path}")
                else:
                    logger.warning(f"Failed to apply fix to {file_path}")

            if not patches:
                result["status"] = "fix_failed"
                result["error"] = "Fixes generated but could not be applied"
                return result

            # Step 5: Write combined patch file
            patch_dir = Path(repo_path) / ".viper_patches"
            patch_dir.mkdir(exist_ok=True)
            patch_file = patch_dir / f"{finding_id}.patch"
            patch_content = "\n\n".join(patches)
            tools.write_tool(str(patch_file), patch_content)

            result["status"] = "fixed"
            result["patch_file"] = str(patch_file)
            result["files_changed"] = files_changed
            logger.info(f"Fix complete: {len(files_changed)} files changed, patch at {patch_file}")

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error fixing {finding_id}: {e}")

        return result

    async def fix_findings(self, findings: List[Dict], repo_path: str) -> List[Dict]:
        """
        Fix multiple findings sequentially.

        Args:
            findings: List of finding dicts.
            repo_path: Repository root path.

        Returns:
            List of result dicts (one per finding).
        """
        results = []
        for i, finding in enumerate(findings):
            logger.info(f"Processing finding {i+1}/{len(findings)}: {finding.get('title', 'N/A')}")
            result = await self.fix_finding(finding, repo_path)
            results.append(result)
        return results

    def _locate_vulnerable_code(self, finding: Dict, repo_path: str) -> List[Dict]:
        """
        Find files containing the vulnerable pattern.

        Uses multiple strategies:
        1. Search by affected assets (URLs, file paths)
        2. Search by vulnerability keywords
        3. Search by CWE/CVE-specific patterns
        """
        results = []

        # Strategy 1: Search affected assets for file-like paths
        assets = finding.get("affected_assets", [])
        for asset in assets:
            # If asset looks like a file path
            if "/" in asset and not asset.startswith("http"):
                matches = tools.glob_tool(f"**/*{Path(asset).name}", repo_path)
                for m in matches:
                    full = str(Path(repo_path) / m)
                    results.append({"file": full, "line": 0, "match": f"asset match: {asset}"})

            # If asset looks like a URL path
            if asset.startswith("/") or "/api/" in asset:
                path_part = asset.split("?")[0].rstrip("/").split("/")[-1]
                if path_part:
                    hits = tools.grep_tool(re.escape(path_part), repo_path, max_results=10)
                    for h in hits:
                        full = str(Path(repo_path) / h["file"])
                        results.append({"file": full, "line": h["line"], "match": h["text"]})

        # Strategy 2: Search by vulnerability category/type
        category = (finding.get("category") or finding.get("finding_type") or "").lower()
        patterns = self._get_vuln_patterns(category)
        for pattern in patterns:
            hits = tools.grep_tool(pattern, repo_path, max_results=10)
            for h in hits:
                full = str(Path(repo_path) / h["file"])
                results.append({"file": full, "line": h["line"], "match": h["text"]})

        # Strategy 3: Search evidence text
        evidence = finding.get("evidence", "")
        if evidence:
            # Extract file paths or URLs from evidence
            path_matches = re.findall(r'[\w/.-]+\.\w{1,5}', evidence)
            for pm in path_matches[:3]:
                name = Path(pm).name
                matches = tools.glob_tool(f"**/{name}", repo_path)
                for m in matches:
                    full = str(Path(repo_path) / m)
                    results.append({"file": full, "line": 0, "match": f"evidence: {pm}"})

        # Deduplicate by file
        seen = set()
        unique = []
        for r in results:
            key = f"{r['file']}:{r['line']}"
            if key not in seen:
                seen.add(key)
                unique.append(r)

        return unique

    def _get_vuln_patterns(self, category: str) -> List[str]:
        """Get regex patterns to search for based on vulnerability category."""
        patterns_map = {
            "sqli": [
                r'execute\s*\(.*["\'].*%s',
                r'f".*SELECT.*{',
                r'query\s*\+\s*',
                r'cursor\.execute\s*\(\s*["\'].*\+',
                r'\.raw\s*\(',
            ],
            "xss": [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'v-html\s*=',
                r'dangerouslySetInnerHTML',
                r'\|\s*safe\b',
                r'render_template_string',
            ],
            "rce": [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(.*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\(',
                r'child_process\.exec\s*\(',
            ],
            "secret": [
                r'(?i)(password|secret|token|api_key|apikey)\s*=\s*["\'][^"\']{8,}',
                r'(?i)hardcoded.*(?:password|key|secret)',
            ],
            "misconfiguration": [
                r'(?i)cors.*origin.*\*',
                r'(?i)debug\s*=\s*True',
                r'(?i)verify\s*=\s*False',
                r'(?i)secure\s*=\s*False',
            ],
            "dependency": [],  # Dependencies are in package files, not code patterns
            "certificate": [],
            "exposure": [
                r'\.env\b',
                r'(?i)sensitive.*expose',
            ],
        }
        return patterns_map.get(category, [])

    async def _generate_fixes_llm(self, finding: Dict, code_contexts: List[Dict], repo_path: str) -> List[Dict]:
        """
        Use LLM to generate fixes for each affected file.

        Returns list of {file, old_text, new_text} dicts.
        """
        fixes = []

        for ctx in code_contexts:
            prompt = f"""## Vulnerability
Title: {finding.get('title', 'N/A')}
Type: {finding.get('finding_type', finding.get('category', 'N/A'))}
Severity: {finding.get('severity', 'N/A')}
Description: {finding.get('description', 'N/A')}
CVEs: {', '.join(finding.get('cve_ids', []))}
CWEs: {', '.join(finding.get('cwe_ids', []))}
Recommendation: {finding.get('recommendation', finding.get('solution', 'N/A'))}

## Affected Code
File: {ctx['file']}
Line: {ctx.get('line', 'unknown')}
Match: {ctx.get('match', 'N/A')}

```
{ctx['content']}
```

## Instructions
1. Identify the vulnerable code in the snippet above
2. Output a JSON object with:
   - "old_text": The exact vulnerable code to replace (copy exactly from the snippet, including whitespace)
   - "new_text": The fixed code
   - "explanation": One-line explanation of the fix

Output ONLY the JSON object, no markdown fences."""

            try:
                response = await self._model_router.query(prompt, system=CODEFIX_SYSTEM_PROMPT)
                fix = self._parse_fix_response(response, ctx["file"])
                if fix:
                    fixes.append(fix)
            except Exception as e:
                logger.error(f"LLM fix generation failed for {ctx['file']}: {e}")

        return fixes

    def _generate_fixes_rules(self, finding: Dict, code_contexts: List[Dict]) -> List[Dict]:
        """
        Generate rule-based fix suggestions (no LLM needed).
        Returns {file, old_text, new_text} or empty list if no rule applies.
        """
        fixes = []
        category = (finding.get("category") or finding.get("finding_type") or "").lower()

        for ctx in code_contexts:
            content = ctx.get("content", "")
            file_path = ctx["file"]

            # Extract the line numbers from read_tool output
            lines = content.split("\n")

            if category == "misconfiguration":
                # Fix DEBUG=True
                for line in lines:
                    stripped = line.lstrip()
                    # Remove line number prefix
                    parts = stripped.split("\t", 1)
                    code = parts[1] if len(parts) > 1 else parts[0]

                    if re.match(r'\s*DEBUG\s*=\s*True', code):
                        fixes.append({
                            "file": file_path,
                            "old_text": code.rstrip(),
                            "new_text": code.rstrip().replace("True", "os.environ.get('DEBUG', 'False') == 'True'"),
                            "explanation": "Read DEBUG from environment variable instead of hardcoding",
                        })
                        break

            elif category == "secret":
                for line in lines:
                    parts = line.lstrip().split("\t", 1)
                    code = parts[1] if len(parts) > 1 else parts[0]
                    m = re.match(r'(\s*\w+\s*=\s*)["\']([^"\']{8,})["\']', code)
                    if m:
                        var_part = m.group(1)
                        fixes.append({
                            "file": file_path,
                            "old_text": code.rstrip(),
                            "new_text": f'{var_part}os.environ.get("{var_part.strip().rstrip("=").strip()}", "")',
                            "explanation": "Replace hardcoded secret with environment variable",
                        })
                        break

        return fixes

    def _parse_fix_response(self, response: str, file_path: str) -> Optional[Dict]:
        """Parse LLM fix response into {file, old_text, new_text}."""
        # Try JSON parse
        try:
            # Strip markdown fences if present
            cleaned = re.sub(r'^```\w*\n?', '', response.strip(), flags=re.MULTILINE)
            cleaned = re.sub(r'\n?```$', '', cleaned.strip())
            data = json.loads(cleaned)

            if data.get("status") == "needs_review":
                logger.info(f"Fix needs review: {data.get('reason', 'N/A')}")
                return None

            old_text = data.get("old_text", "")
            new_text = data.get("new_text", "")
            if old_text and new_text and old_text != new_text:
                return {
                    "file": file_path,
                    "old_text": old_text,
                    "new_text": new_text,
                    "explanation": data.get("explanation", ""),
                }
        except (json.JSONDecodeError, AttributeError):
            pass

        # Try extracting old/new from structured text
        old_match = re.search(r'"old_text"\s*:\s*"(.*?)"', response, re.DOTALL)
        new_match = re.search(r'"new_text"\s*:\s*"(.*?)"', response, re.DOTALL)
        if old_match and new_match:
            old_text = old_match.group(1).replace("\\n", "\n").replace('\\"', '"')
            new_text = new_match.group(1).replace("\\n", "\n").replace('\\"', '"')
            if old_text and new_text and old_text != new_text:
                return {"file": file_path, "old_text": old_text, "new_text": new_text}

        logger.warning(f"Could not parse fix response for {file_path}")
        return None

    def _create_patch(self, file_path: str, original: str, fixed: str) -> str:
        """Create a unified diff patch."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{Path(file_path).name}",
            tofile=f"b/{Path(file_path).name}",
            lineterm="",
        )
        return "".join(diff)

    def _create_github_pr(self, repo_path: str, branch_name: str, title: str, body: str) -> str:
        """
        Create a GitHub PR using gh CLI.

        Args:
            repo_path: Path to the git repository.
            branch_name: Branch name for the PR.
            title: PR title.
            body: PR body/description.

        Returns:
            PR URL if successful, empty string otherwise.
        """
        # Stage and commit
        commit_msg = f"fix: {title}\n\nAutomated security fix by VIPER CodeFix Engine."
        stage_result = tools.bash_tool("git add -A", cwd=repo_path)
        if "Error" in stage_result:
            logger.error(f"git add failed: {stage_result}")
            return ""

        commit_result = tools.bash_tool(
            f'git commit -m "{commit_msg}"',
            cwd=repo_path,
        )
        if "Error" in commit_result and "nothing to commit" not in commit_result:
            logger.error(f"git commit failed: {commit_result}")
            return ""

        # Push branch
        push_result = tools.bash_tool(
            f"git push -u origin {branch_name}",
            cwd=repo_path,
            timeout=60,
        )
        if "Error" in push_result and "Everything up-to-date" not in push_result:
            logger.error(f"git push failed: {push_result}")
            return ""

        # Create PR
        # Escape body for shell
        safe_body = body.replace('"', '\\"').replace('`', '\\`')
        pr_result = tools.bash_tool(
            f'gh pr create --title "{title}" --body "{safe_body}" --head {branch_name}',
            cwd=repo_path,
            timeout=30,
        )

        # Extract PR URL from output
        url_match = re.search(r'https://github\.com/\S+/pull/\d+', pr_result)
        if url_match:
            pr_url = url_match.group(0)
            logger.info(f"PR created: {pr_url}")
            return pr_url

        logger.warning(f"PR creation output: {pr_result}")
        return ""

    async def fix_and_pr(self, finding: Dict, repo_path: str,
                         branch_prefix: str = "viper-fix/") -> Dict:
        """
        Fix a finding AND create a GitHub PR.

        Convenience method that:
        1. Creates a fix branch
        2. Applies the fix
        3. Commits and pushes
        4. Creates a PR

        Args:
            finding: Finding dict.
            repo_path: Repository root path.
            branch_prefix: Branch name prefix.

        Returns:
            Result dict with pr_url field populated.
        """
        finding_id = finding.get("id", "unknown")
        branch_name = f"{branch_prefix}{finding_id}"

        # Create branch
        tools.bash_tool(f"git checkout -b {branch_name}", cwd=repo_path)

        # Fix
        result = await self.fix_finding(finding, repo_path)

        if result["status"] == "fixed" and result["files_changed"]:
            # Create PR
            title = f"Security fix: {finding.get('title', finding_id)}"
            body = (
                f"## Vulnerability\n"
                f"**{finding.get('title', 'N/A')}**\n\n"
                f"- Severity: {finding.get('severity', 'N/A')}\n"
                f"- Type: {finding.get('finding_type', 'N/A')}\n"
                f"- CVEs: {', '.join(finding.get('cve_ids', []))}\n"
                f"- CWEs: {', '.join(finding.get('cwe_ids', []))}\n\n"
                f"## Changes\n"
                f"Files modified: {', '.join(result['files_changed'])}\n\n"
                f"## Description\n"
                f"{finding.get('description', 'N/A')}\n\n"
                f"---\n"
                f"Automated fix by VIPER 4.0 CodeFix Engine"
            )
            pr_url = self._create_github_pr(repo_path, branch_name, title, body)
            result["pr_url"] = pr_url

        # Return to original branch
        tools.bash_tool("git checkout -", cwd=repo_path)

        return result


# Compatibility alias (lowercase 'f')
CodefixEngine = CodeFixEngine
