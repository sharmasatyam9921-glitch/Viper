#!/usr/bin/env python3
"""
VIPER 4.0 Phase D — CodeFix Engine (Tree-Sitter ReACT).

Given a vulnerability finding and a repository path, uses an LLM-driven ReACT
loop with tree-sitter-powered tools to analyze code and generate precise fixes.
Can create GitHub PRs.
"""

import difflib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import codefix_tools as tools
from .codefix_tools import CODEFIX_TOOL_DEFS

logger = logging.getLogger("viper.codefix_engine")

# ── System prompt for the CodeFix ReACT loop ─────────────────────────────

CODEFIX_SYSTEM_PROMPT = """You are a security engineer fixing vulnerabilities in source code.

You have access to the following tools:
{tool_descriptions}

## Workflow
1. Start with `repo_map` to understand the codebase structure
2. Use `symbols` to find relevant functions/classes in key files
3. Use `find_definition` to locate the vulnerable code
4. Use `read` to examine the vulnerable code in detail
5. Use `find_references` to understand how the vulnerable code is used
6. Use `edit` to apply the minimal fix
7. Use `bash` to run tests/linters to verify the fix

## Rules
1. Fix ONLY the vulnerability — do not refactor unrelated code
2. Preserve existing code style and patterns
3. Add a concise comment explaining the security fix
4. If the fix requires importing new modules, include those imports
5. For injection vulns (SQLi, XSS, command injection): use parameterized queries, output encoding, or input validation
6. For secrets: replace hardcoded values with environment variables or config references
7. For dependencies: specify the exact patched version
8. For misconfigurations: set the correct secure value
9. ALWAYS read a file before editing it
10. ALWAYS use `symbols` before reading a large file to find the right section

## Output Format
After fixing, output a JSON summary:
{{"status": "fixed", "files_changed": [...], "explanation": "..."}}

If you cannot fix it:
{{"status": "needs_review", "reason": "..."}}
"""

# Max iterations for the ReACT fix loop
MAX_FIX_ITERATIONS = 15


class CodeFixEngine:
    """
    Vulnerability code fix engine with ReACT loop.

    Takes a finding and a repository path, then:
    1. Uses repo_map/symbols/find_definition to locate vulnerable code
    2. Reads and analyzes the code context
    3. Generates and applies a fix using edit_tool
    4. Optionally creates a GitHub PR
    """

    def __init__(self, model_router=None):
        """
        Args:
            model_router: ModelRouter for LLM-powered fix generation.
                          If None, falls back to rule-based fixes.
        """
        self._model_router = model_router
        self._files_read: set = set()
        self._files_modified: set = set()

    async def fix_finding(self, finding: Dict, repo_path: str) -> Dict:
        """
        Fix a single vulnerability finding using ReACT loop.

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
            if self._model_router:
                # Full ReACT loop with LLM
                react_result = await self._react_fix_loop(finding, repo_path)
                result.update(react_result)
            else:
                # Fallback: locate + rule-based fix
                result = await self._fallback_fix(finding, repo_path, result)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error fixing {finding_id}: {e}")

        return result

    # ── ReACT Loop ────────────────────────────────────────────────────────

    async def _react_fix_loop(self, finding: Dict, repo_path: str) -> Dict:
        """
        Full ReACT loop: LLM calls tools iteratively until fix is applied.
        """
        self._files_read = set()
        self._files_modified = set()

        # Build tool descriptions for the system prompt
        tool_desc_lines = []
        for td in CODEFIX_TOOL_DEFS:
            params = td["input_schema"].get("properties", {})
            param_str = ", ".join(
                f"{k}: {v.get('type', 'any')}" for k, v in params.items()
            )
            tool_desc_lines.append(f"- **{td['name']}**({param_str}): {td['description']}")
        tool_descriptions = "\n".join(tool_desc_lines)

        system_prompt = CODEFIX_SYSTEM_PROMPT.format(
            tool_descriptions=tool_descriptions
        )

        # Build initial user message with finding details
        user_msg = self._build_finding_prompt(finding, repo_path)

        messages = [{"role": "user", "content": user_msg}]

        files_changed = []
        last_status = "pending"
        last_error = None

        for iteration in range(MAX_FIX_ITERATIONS):
            logger.info(f"ReACT iteration {iteration + 1}/{MAX_FIX_ITERATIONS}")

            try:
                response = await self._model_router.query(
                    messages=messages,
                    system=system_prompt,
                    tools=CODEFIX_TOOL_DEFS,
                    max_tokens=4096,
                )
            except Exception as e:
                logger.error(f"LLM call failed at iteration {iteration + 1}: {e}")
                last_error = str(e)
                break

            # Parse LLM response
            if isinstance(response, str):
                # Plain text response — check if it contains a final JSON summary
                messages.append({"role": "assistant", "content": response})
                final = self._parse_final_summary(response)
                if final:
                    last_status = final.get("status", "fixed")
                    files_changed = final.get("files_changed", list(self._files_modified))
                    break
                continue

            if isinstance(response, dict):
                # Structured response with tool_calls
                assistant_content = response.get("content", "")
                tool_calls = response.get("tool_calls", [])

                if not tool_calls:
                    # No tool calls — treat as final answer
                    messages.append({"role": "assistant", "content": assistant_content})
                    final = self._parse_final_summary(assistant_content)
                    if final:
                        last_status = final.get("status", "fixed")
                        files_changed = final.get("files_changed", list(self._files_modified))
                    elif self._files_modified:
                        last_status = "fixed"
                        files_changed = list(self._files_modified)
                    break

                # Execute tool calls
                messages.append({"role": "assistant", "content": assistant_content,
                                 "tool_calls": tool_calls})

                tool_results = []
                for tc in tool_calls:
                    tool_name = tc.get("name", tc.get("function", {}).get("name", ""))
                    tool_args = tc.get("arguments", tc.get("function", {}).get("arguments", {}))
                    if isinstance(tool_args, str):
                        try:
                            tool_args = json.loads(tool_args)
                        except json.JSONDecodeError:
                            tool_args = {}

                    tool_result = self._execute_tool(tool_name, tool_args, repo_path)
                    tool_results.append({
                        "tool_call_id": tc.get("id", ""),
                        "role": "tool",
                        "name": tool_name,
                        "content": str(tool_result),
                    })

                messages.extend(tool_results)

        # Build patches if files were modified
        patch_file = None
        if self._files_modified:
            files_changed = list(self._files_modified)
            last_status = "fixed"
            patch_dir = Path(repo_path) / ".viper_patches"
            patch_dir.mkdir(exist_ok=True)
            finding_id = finding.get("id", "unknown")
            patch_file = str(patch_dir / f"{finding_id}.patch")
            # Generate unified diff for all modified files
            # (originals are lost after edit, so we generate a summary)
            with open(patch_file, 'w') as f:
                f.write(f"# VIPER CodeFix patch for {finding_id}\n")
                f.write(f"# Files modified: {', '.join(files_changed)}\n")
                f.write(f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        return {
            "finding_id": finding.get("id", "unknown"),
            "status": last_status,
            "patch_file": patch_file,
            "pr_url": None,
            "files_changed": files_changed,
            "error": last_error,
        }

    def _execute_tool(self, name: str, args: Dict, repo_path: str) -> str:
        """Execute a codefix tool and return its result as a string."""
        logger.debug(f"Tool call: {name}({args})")

        try:
            if name == "symbols":
                fp = self._resolve_path(args.get("file_path", ""), repo_path)
                result = tools.symbols_tool(fp)
                if isinstance(result, list):
                    if result and "error" in result[0]:
                        return result[0]["error"]
                    lines = [f"Symbols in {args.get('file_path', '')} ({len(result)} found):"]
                    for s in result:
                        depth_indent = "  " * s.get("depth", 0)
                        end = f"-{s['end_line']}" if s.get('end_line', 0) != s.get('start_line', 0) else ""
                        lines.append(
                            f"  {depth_indent}{s.get('kind', '?')} {s.get('name', '?')}  "
                            f"[{s.get('start_line', s.get('line', '?'))}{end}]"
                        )
                    return "\n".join(lines)
                return str(result)

            elif name == "find_definition":
                symbol = args.get("symbol", "")
                path = self._resolve_path(args.get("path", ""), repo_path)
                result = tools.find_definition_tool(symbol, path)
                if not result:
                    return f"No definition found for '{symbol}'. Try grep instead."
                lines = [f"Definitions of '{symbol}' ({len(result)} found):"]
                for r in result:
                    lines.append(f"  {r['file']}:{r['line']}  ({r['kind']})")
                    if r.get("signature"):
                        lines.append(f"    {r['signature']}")
                return "\n".join(lines)

            elif name == "find_references":
                symbol = args.get("symbol", "")
                path = self._resolve_path(args.get("path", ""), repo_path)
                fp = args.get("file_path")
                result = tools.find_references_tool(symbol, path, file_path=fp)
                if not result:
                    return f"No references found for '{symbol}'."
                lines = [f"References to '{symbol}' ({len(result)} found):"]
                for r in result:
                    lines.append(f"  {r['file']}:{r['line']}  {r.get('text', '')}")
                return "\n".join(lines)

            elif name == "repo_map":
                path = self._resolve_path(args.get("path", ""), repo_path)
                return tools.repo_map_tool(
                    path,
                    max_files=args.get("max_files", 100),
                    max_tokens=args.get("max_tokens", 2000),
                    focus_paths=args.get("focus_paths"),
                )

            elif name == "edit":
                fp = self._resolve_path(args.get("file_path", ""), repo_path)
                if fp not in self._files_read:
                    return f"Error: You must read {args.get('file_path', '')} before editing. Use read first."
                result = tools.edit_tool(
                    fp, args.get("old_text", ""), args.get("new_text", ""),
                    replace_all=args.get("replace_all", False),
                )
                if result.startswith("OK"):
                    rel = str(Path(fp).relative_to(repo_path)) if repo_path else fp
                    self._files_modified.add(rel)
                return result

            elif name == "read":
                fp = self._resolve_path(args.get("file_path", ""), repo_path)
                self._files_read.add(fp)
                return tools.read_tool(
                    fp,
                    offset=args.get("offset", 0),
                    limit=args.get("limit", 2000),
                )

            elif name == "grep":
                path = self._resolve_path(args.get("path", ""), repo_path)
                result = tools.grep_tool(
                    args.get("pattern", ""),
                    path,
                    max_results=args.get("max_results", 50),
                    case_insensitive=args.get("case_insensitive", False),
                    context=args.get("context", 0),
                )
                if not result:
                    return "No matches found."
                lines = [f"Found {len(result)} matches:"]
                for r in result:
                    lines.append(f"  {r['file']}:{r['line']}  {r.get('text', '')}")
                return "\n".join(lines)

            elif name == "glob":
                path = self._resolve_path(args.get("path", ""), repo_path)
                result = tools.glob_tool(args.get("pattern", ""), path)
                if not result:
                    return "No files matched."
                return "\n".join(result)

            elif name == "list_dir":
                path = self._resolve_path(args.get("path", ""), repo_path)
                return tools.list_dir_tool(path, max_depth=args.get("max_depth", 2))

            elif name == "bash":
                cwd = args.get("cwd", repo_path)
                return tools.bash_tool(
                    args.get("command", ""),
                    cwd=cwd,
                    timeout=args.get("timeout", 30),
                )

            else:
                return f"Error: Unknown tool '{name}'. Available: {', '.join(tools.CODEFIX_TOOLS.keys())}"

        except Exception as e:
            return f"Error executing {name}: {type(e).__name__}: {e}"

    def _resolve_path(self, path: str, repo_path: str) -> str:
        """Resolve a relative path against repo_path."""
        if not path:
            return repo_path
        p = Path(path)
        if p.is_absolute():
            return str(p)
        return str(Path(repo_path) / path)

    def _build_finding_prompt(self, finding: Dict, repo_path: str) -> str:
        """Build the initial user prompt describing the vulnerability."""
        return f"""Fix the following vulnerability in the repository at {repo_path}:

## Vulnerability
- **Title:** {finding.get('title', 'N/A')}
- **Type:** {finding.get('finding_type', finding.get('category', 'N/A'))}
- **Severity:** {finding.get('severity', 'N/A')}
- **CVEs:** {', '.join(finding.get('cve_ids', [])) or 'N/A'}
- **CWEs:** {', '.join(finding.get('cwe_ids', [])) or 'N/A'}
- **Description:** {finding.get('description', 'N/A')}
- **Recommendation:** {finding.get('recommendation', finding.get('solution', 'N/A'))}

## Affected Assets
{chr(10).join('- ' + a for a in finding.get('affected_assets', [])) or 'N/A'}

## Evidence
{finding.get('evidence', 'N/A')}

Start by using `repo_map` to understand the codebase, then locate and fix the vulnerability."""

    def _parse_final_summary(self, text: str) -> Optional[Dict]:
        """Try to parse a final JSON summary from LLM text."""
        # Look for JSON blocks
        json_patterns = [
            r'```json\s*\n(.*?)\n\s*```',
            r'```\s*\n(.*?)\n\s*```',
            r'(\{[^{}]*"status"[^{}]*\})',
        ]
        for pat in json_patterns:
            m = re.search(pat, text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                    if "status" in data:
                        return data
                except (json.JSONDecodeError, IndexError):
                    continue
        return None

    # ── Fallback (no LLM) ────────────────────────────────────────────────

    async def _fallback_fix(self, finding: Dict, repo_path: str,
                            result: Dict) -> Dict:
        """Locate vulnerable code and apply rule-based fixes (no LLM needed)."""
        finding_id = finding.get("id", "unknown")

        # Step 1: Locate vulnerable code
        logger.info(f"Step 1: Locating vulnerable code in {repo_path}")
        locations = self._locate_vulnerable_code(finding, repo_path)
        if not locations:
            result["status"] = "not_found"
            result["error"] = "Could not locate vulnerable code in repository"
            return result

        logger.info(f"Found {len(locations)} potential locations")

        # Step 2: Read code context
        code_contexts = []
        for loc in locations[:5]:
            content = tools.read_tool(
                loc["file"], offset=max(0, loc.get("line", 1) - 20), limit=60
            )
            code_contexts.append({
                "file": loc["file"],
                "line": loc.get("line", 0),
                "match": loc.get("match", ""),
                "content": content,
            })

        # Step 3: Generate rule-based fix
        logger.info("Step 3: Generating rule-based fix suggestion")
        fixes = self._generate_fixes_rules(finding, code_contexts)

        if not fixes:
            result["status"] = "no_fix"
            result["error"] = "Could not generate a fix"
            return result

        # Step 4: Apply fixes
        patches = []
        files_changed = []
        for fix in fixes:
            file_path = fix.get("file")
            old_text = fix.get("old_text", "")
            new_text = fix.get("new_text", "")

            if not file_path or not old_text or not new_text:
                continue

            original = Path(file_path).read_text(encoding='utf-8', errors='replace')
            edit_result = tools.edit_tool(file_path, old_text, new_text)
            if edit_result.startswith("OK"):
                fixed = Path(file_path).read_text(encoding='utf-8', errors='replace')
                patch = self._create_patch(file_path, original, fixed)
                patches.append(patch)
                files_changed.append(str(Path(file_path).relative_to(repo_path)))
                logger.info(f"Applied fix to {file_path}")

        if not patches:
            result["status"] = "fix_failed"
            result["error"] = "Fixes generated but could not be applied"
            return result

        # Step 5: Write patch file
        patch_dir = Path(repo_path) / ".viper_patches"
        patch_dir.mkdir(exist_ok=True)
        patch_file = patch_dir / f"{finding_id}.patch"
        patch_content = "\n\n".join(patches)
        tools.write_tool(str(patch_file), patch_content)

        result["status"] = "fixed"
        result["patch_file"] = str(patch_file)
        result["files_changed"] = files_changed
        return result

    # ── Code location strategies ──────────────────────────────────────────

    def _locate_vulnerable_code(self, finding: Dict, repo_path: str) -> List[Dict]:
        """
        Find files containing the vulnerable pattern using multiple strategies:
        1. Search by affected assets (URLs, file paths)
        2. Search by vulnerability keywords
        3. Search by CWE/CVE-specific patterns
        4. Use find_definition for function/class names from evidence
        """
        results = []

        # Strategy 1: Affected assets
        assets = finding.get("affected_assets", [])
        for asset in assets:
            if "/" in asset and not asset.startswith("http"):
                matches = tools.glob_tool(f"**/*{Path(asset).name}", repo_path)
                for m in matches:
                    full = str(Path(repo_path) / m)
                    results.append({"file": full, "line": 0, "match": f"asset: {asset}"})

            if asset.startswith("/") or "/api/" in asset:
                path_part = asset.split("?")[0].rstrip("/").split("/")[-1]
                if path_part:
                    hits = tools.grep_tool(re.escape(path_part), repo_path, max_results=10)
                    for h in hits:
                        full = str(Path(repo_path) / h["file"])
                        results.append({"file": full, "line": h["line"], "text": h["text"]})

        # Strategy 2: Vulnerability category patterns
        category = (finding.get("category") or finding.get("finding_type") or "").lower()
        patterns = self._get_vuln_patterns(category)
        for pattern in patterns:
            hits = tools.grep_tool(pattern, repo_path, max_results=10)
            for h in hits:
                full = str(Path(repo_path) / h["file"])
                results.append({"file": full, "line": h["line"], "text": h["text"]})

        # Strategy 3: Evidence text — extract file paths and function names
        evidence = finding.get("evidence", "")
        if evidence:
            path_matches = re.findall(r'[\w/.-]+\.\w{1,5}', evidence)
            for pm in path_matches[:3]:
                name = Path(pm).name
                matches = tools.glob_tool(f"**/{name}", repo_path)
                for m in matches:
                    full = str(Path(repo_path) / m)
                    results.append({"file": full, "line": 0, "match": f"evidence: {pm}"})

            # Try find_definition for function names in evidence
            func_matches = re.findall(r'\b([a-z_][a-z0-9_]{2,})\b', evidence, re.I)
            for func_name in func_matches[:5]:
                defs = tools.find_definition_tool(func_name, repo_path)
                for d in defs[:3]:
                    full = str(Path(repo_path) / d["file"])
                    results.append({
                        "file": full, "line": d["line"],
                        "match": f"definition: {d['signature']}"
                    })

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            key = f"{r['file']}:{r.get('line', 0)}"
            if key not in seen:
                seen.add(key)
                unique.append(r)

        return unique

    def _get_vuln_patterns(self, category: str) -> List[str]:
        """Get regex patterns based on vulnerability category."""
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
            "cmdi": [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(.*shell\s*=\s*True',
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
            "lfi": [
                r'open\s*\(\s*.*\+',
                r'file_get_contents\s*\(',
                r'include\s*\(',
                r'require\s*\(',
            ],
            "ssrf": [
                r'requests\.get\s*\(\s*[^"\']*\+',
                r'urllib\.request\.urlopen\s*\(',
                r'fetch\s*\(\s*[^"\']*\+',
            ],
            "ssti": [
                r'render_template_string\s*\(',
                r'Template\s*\(\s*[^"\']*\+',
                r'Jinja2\s*\(',
            ],
        }
        return patterns_map.get(category, [])

    def _generate_fixes_rules(self, finding: Dict,
                              code_contexts: List[Dict]) -> List[Dict]:
        """Generate rule-based fix suggestions (no LLM needed)."""
        fixes = []
        category = (finding.get("category") or finding.get("finding_type") or "").lower()

        for ctx in code_contexts:
            content = ctx.get("content", "")
            file_path = ctx["file"]
            lines = content.split("\n")

            if category == "misconfiguration":
                for line in lines:
                    parts = line.lstrip().split("\t", 1)
                    code = parts[1] if len(parts) > 1 else parts[0]
                    if re.match(r'\s*DEBUG\s*=\s*True', code):
                        fixes.append({
                            "file": file_path,
                            "old_text": code.rstrip(),
                            "new_text": code.rstrip().replace(
                                "True",
                                "os.environ.get('DEBUG', 'False') == 'True'"
                            ),
                            "explanation": "Read DEBUG from environment variable",
                        })
                        break

            elif category == "secret":
                for line in lines:
                    parts = line.lstrip().split("\t", 1)
                    code = parts[1] if len(parts) > 1 else parts[0]
                    m = re.match(r'(\s*\w+\s*=\s*)["\']([^"\']{8,})["\']', code)
                    if m:
                        var_part = m.group(1)
                        var_name = var_part.strip().rstrip("=").strip()
                        fixes.append({
                            "file": file_path,
                            "old_text": code.rstrip(),
                            "new_text": f'{var_part}os.environ.get("{var_name}", "")',
                            "explanation": "Replace hardcoded secret with env var",
                        })
                        break

        return fixes

    # ── Patch / PR helpers ────────────────────────────────────────────────

    def _create_patch(self, file_path: str, original: str, fixed: str) -> str:
        """Create a unified diff patch."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        diff = difflib.unified_diff(
            original_lines, fixed_lines,
            fromfile=f"a/{Path(file_path).name}",
            tofile=f"b/{Path(file_path).name}",
            lineterm="",
        )
        return "".join(diff)

    def _create_github_pr(self, repo_path: str, branch_name: str,
                          title: str, body: str) -> str:
        """Create a GitHub PR using gh CLI."""
        commit_msg = f"fix: {title}\n\nAutomated security fix by VIPER CodeFix Engine."
        stage_result = tools.bash_tool("git add -A", cwd=repo_path)
        if "Error" in stage_result:
            logger.error(f"git add failed: {stage_result}")
            return ""

        commit_result = tools.bash_tool(
            f'git commit -m "{commit_msg}"', cwd=repo_path
        )
        if "Error" in commit_result and "nothing to commit" not in commit_result:
            logger.error(f"git commit failed: {commit_result}")
            return ""

        push_result = tools.bash_tool(
            f"git push -u origin {branch_name}", cwd=repo_path, timeout=60
        )
        if "Error" in push_result and "Everything up-to-date" not in push_result:
            logger.error(f"git push failed: {push_result}")
            return ""

        safe_body = body.replace('"', '\\"').replace('`', '\\`')
        pr_result = tools.bash_tool(
            f'gh pr create --title "{title}" --body "{safe_body}" --head {branch_name}',
            cwd=repo_path, timeout=30,
        )

        url_match = re.search(r'https://github\.com/\S+/pull/\d+', pr_result)
        if url_match:
            pr_url = url_match.group(0)
            logger.info(f"PR created: {pr_url}")
            return pr_url

        logger.warning(f"PR creation output: {pr_result}")
        return ""

    async def fix_findings(self, findings: List[Dict],
                           repo_path: str) -> List[Dict]:
        """Fix multiple findings sequentially."""
        results = []
        for i, finding in enumerate(findings):
            logger.info(f"Processing finding {i+1}/{len(findings)}: {finding.get('title', 'N/A')}")
            result = await self.fix_finding(finding, repo_path)
            results.append(result)
        return results

    async def fix_and_pr(self, finding: Dict, repo_path: str,
                         branch_prefix: str = "viper-fix/") -> Dict:
        """
        Fix a finding AND create a GitHub PR.

        1. Creates a fix branch
        2. Applies the fix (ReACT loop or rules)
        3. Commits, pushes, creates PR
        """
        finding_id = finding.get("id", "unknown")
        branch_name = f"{branch_prefix}{finding_id}"

        tools.bash_tool(f"git checkout -b {branch_name}", cwd=repo_path)

        result = await self.fix_finding(finding, repo_path)

        if result["status"] == "fixed" and result["files_changed"]:
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
                f"Automated fix by VIPER 4.0 CodeFix Engine (Phase D — Tree-Sitter)"
            )
            pr_url = self._create_github_pr(repo_path, branch_name, title, body)
            result["pr_url"] = pr_url

        tools.bash_tool("git checkout -", cwd=repo_path)

        return result


# Compatibility alias
CodefixEngine = CodeFixEngine
