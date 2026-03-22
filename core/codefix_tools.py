#!/usr/bin/env python3
"""
VIPER 4.0 Phase 5 — CodeFix Tools.

11 standalone code manipulation tools for the CodeFix engine.
All tools work on local filesystem — no tree-sitter dependency (regex-based symbol finding).

Inspired by open-source pentesting frameworks.
"""

import fnmatch
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("viper.codefix_tools")

# Safety constants
MAX_OUTPUT_CHARS = 50000
MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_RESULTS = 200

BLOCKED_COMMANDS = [
    r'rm\s+(-rf?\s+)?/',
    r'mkfs\.',
    r'dd\s+if=',
    r'>\s*/dev/',
    r':(){ :|:& };:',
    r'curl\s+.*\|\s*sh',
    r'wget\s+.*\|\s*sh',
]

SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '__pycache__', '.tox', 'venv', '.venv',
    'dist', 'build', '.next', '.cache', 'coverage', '.mypy_cache', '.pytest_cache',
    'egg-info',
}

# Language detection from extension
EXT_TO_LANG = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.jsx': 'javascript', '.java': 'java', '.go': 'go', '.rs': 'rust',
    '.rb': 'ruby', '.php': 'php', '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp',
    '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
    '.html': 'html', '.css': 'css', '.yml': 'yaml', '.yaml': 'yaml',
    '.json': 'json', '.xml': 'xml', '.sh': 'shell', '.bash': 'shell',
}

# Regex patterns for definition finding (no tree-sitter needed)
DEFINITION_PATTERNS = {
    'python': [
        (r'^\s*(async\s+)?def\s+(\w+)', 'function'),
        (r'^\s*class\s+(\w+)', 'class'),
    ],
    'javascript': [
        (r'^\s*(export\s+)?(async\s+)?function\s+(\w+)', 'function'),
        (r'^\s*(export\s+)?class\s+(\w+)', 'class'),
        (r'^\s*(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(', 'function'),
        (r'^\s*(const|let|var)\s+(\w+)\s*=', 'variable'),
    ],
    'typescript': [
        (r'^\s*(export\s+)?(async\s+)?function\s+(\w+)', 'function'),
        (r'^\s*(export\s+)?class\s+(\w+)', 'class'),
        (r'^\s*(export\s+)?interface\s+(\w+)', 'interface'),
        (r'^\s*(export\s+)?type\s+(\w+)', 'type'),
        (r'^\s*(export\s+)?(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(', 'function'),
        (r'^\s*(export\s+)?(const|let|var)\s+(\w+)\s*[:=]', 'variable'),
    ],
    'java': [
        (r'^\s*(public|private|protected)?\s*(static\s+)?\w+\s+(\w+)\s*\(', 'method'),
        (r'^\s*(public|private|protected)?\s*(abstract\s+)?class\s+(\w+)', 'class'),
        (r'^\s*(public\s+)?interface\s+(\w+)', 'interface'),
    ],
    'go': [
        (r'^\s*func\s+(\w+)', 'function'),
        (r'^\s*func\s+\(\w+\s+\*?\w+\)\s+(\w+)', 'method'),
        (r'^\s*type\s+(\w+)\s+struct', 'struct'),
        (r'^\s*type\s+(\w+)\s+interface', 'interface'),
    ],
    'rust': [
        (r'^\s*(pub\s+)?fn\s+(\w+)', 'function'),
        (r'^\s*(pub\s+)?struct\s+(\w+)', 'struct'),
        (r'^\s*(pub\s+)?enum\s+(\w+)', 'enum'),
        (r'^\s*(pub\s+)?trait\s+(\w+)', 'trait'),
        (r'^\s*impl\s+(\w+)', 'impl'),
    ],
    'ruby': [
        (r'^\s*def\s+(\w+)', 'method'),
        (r'^\s*class\s+(\w+)', 'class'),
        (r'^\s*module\s+(\w+)', 'module'),
    ],
    'php': [
        (r'^\s*(public|private|protected)?\s*(static\s+)?function\s+(\w+)', 'function'),
        (r'^\s*class\s+(\w+)', 'class'),
    ],
    'c': [
        (r'^\w[\w\s\*]+\s+(\w+)\s*\(', 'function'),
        (r'^\s*typedef\s+struct\s+(\w+)', 'struct'),
    ],
    'cpp': [
        (r'^\w[\w\s\*:]+\s+(\w+)\s*\(', 'function'),
        (r'^\s*class\s+(\w+)', 'class'),
        (r'^\s*struct\s+(\w+)', 'struct'),
    ],
    'csharp': [
        (r'^\s*(public|private|protected|internal)\s+.*\s+(\w+)\s*\(', 'method'),
        (r'^\s*(public|private|protected|internal)?\s*class\s+(\w+)', 'class'),
        (r'^\s*(public\s+)?interface\s+(\w+)', 'interface'),
    ],
}


def _validate_path(file_path: str, base_path: str = None) -> Path:
    """Validate and resolve a file path. Prevents path traversal."""
    p = Path(file_path).resolve()
    if base_path:
        base = Path(base_path).resolve()
        if not str(p).startswith(str(base)):
            raise ValueError(f"Path traversal blocked: {file_path} escapes {base_path}")
    return p


def _truncate(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Truncate text to max chars."""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n\n[Output truncated at {max_chars} chars]"
    return text


def _should_skip(path: Path) -> bool:
    """Check if path should be skipped (hidden dirs, node_modules, etc.)."""
    return any(part in SKIP_DIRS for part in path.parts)


# ── Tool 1: bash_tool ──────────────────────────────────────────────────────

def bash_tool(command: str, cwd: str = None, timeout: int = 30) -> str:
    """
    Execute a shell command safely.

    Args:
        command: Shell command to execute.
        cwd: Working directory (defaults to current dir).
        timeout: Timeout in seconds (max 120).

    Returns:
        Command output (stdout + stderr).
    """
    timeout = min(timeout, 120)

    for pattern in BLOCKED_COMMANDS:
        if re.search(pattern, command):
            return f"Error: Command blocked for safety: {command}"

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        output = result.stdout
        if result.stderr:
            output += f"\n{result.stderr}"
        if result.returncode != 0:
            output += f"\n[Exit code: {result.returncode}]"
        return _truncate(output)
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


# ── Tool 2: read_tool ──────────────────────────────────────────────────────

def read_tool(file_path: str, offset: int = 0, limit: int = 2000) -> str:
    """
    Read a file's contents with optional line offset and limit.

    Args:
        file_path: Absolute or relative path to file.
        offset: Start reading from this line (0-based).
        limit: Max number of lines to read.

    Returns:
        File contents with line numbers.
    """
    try:
        p = Path(file_path).resolve()
        if not p.exists():
            return f"Error: File not found: {file_path}"
        if not p.is_file():
            return f"Error: Not a file: {file_path}"
        if p.stat().st_size > MAX_FILE_SIZE:
            return f"Error: File too large ({p.stat().st_size} bytes, max {MAX_FILE_SIZE})"

        with open(p, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        selected = lines[offset:offset + limit]
        numbered = []
        for i, line in enumerate(selected, start=offset + 1):
            numbered.append(f"{i:>6}\t{line.rstrip()}")

        result = "\n".join(numbered)
        if offset + limit < len(lines):
            result += f"\n\n[Showing lines {offset+1}-{offset+len(selected)} of {len(lines)}]"
        return _truncate(result)
    except Exception as e:
        return f"Error reading {file_path}: {e}"


# ── Tool 3: write_tool ─────────────────────────────────────────────────────

def write_tool(file_path: str, content: str) -> None:
    """
    Write content to a file. Creates parent directories if needed.

    Args:
        file_path: Path to write to.
        content: File content.
    """
    try:
        p = Path(file_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Wrote {len(content)} chars to {p}")
    except Exception as e:
        raise RuntimeError(f"Error writing {file_path}: {e}")


# ── Tool 4: edit_tool ──────────────────────────────────────────────────────

def edit_tool(file_path: str, old_text: str, new_text: str) -> bool:
    """
    Replace text in a file. Exact string match required.

    Args:
        file_path: Path to the file.
        old_text: Text to find (must be unique in file).
        new_text: Replacement text.

    Returns:
        True if replacement was made, False otherwise.
    """
    try:
        p = Path(file_path).resolve()
        if not p.exists():
            logger.error(f"File not found: {file_path}")
            return False

        content = p.read_text(encoding='utf-8', errors='replace')
        count = content.count(old_text)

        if count == 0:
            logger.error(f"Text not found in {file_path}")
            return False
        if count > 1:
            logger.warning(f"Text found {count} times in {file_path} — replacing first occurrence")

        new_content = content.replace(old_text, new_text, 1)
        p.write_text(new_content, encoding='utf-8')
        logger.info(f"Edited {file_path}: replaced {len(old_text)} chars with {len(new_text)} chars")
        return True
    except Exception as e:
        logger.error(f"Error editing {file_path}: {e}")
        return False


# ── Tool 5: grep_tool ──────────────────────────────────────────────────────

def grep_tool(pattern: str, path: str, max_results: int = 50,
              case_insensitive: bool = False, context: int = 0) -> List[dict]:
    """
    Search for pattern in files. Uses ripgrep if available, falls back to Python regex.

    Args:
        pattern: Regex pattern to search for.
        path: Directory or file to search in.
        max_results: Maximum number of matches to return.
        case_insensitive: Case-insensitive search.
        context: Lines of context around each match.

    Returns:
        List of {file, line, text} dicts.
    """
    results = []

    # Try ripgrep first
    try:
        cmd = ["rg", pattern, "-n", "--max-count", str(max_results)]
        if case_insensitive:
            cmd.append("-i")
        if context > 0:
            cmd.extend(["-C", str(context)])
        cmd.append(str(path))

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode <= 1:  # 0 = found, 1 = not found
            base = str(Path(path).resolve())
            for line in proc.stdout.strip().split('\n'):
                if not line:
                    continue
                # Parse rg output: file:line:text
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    fpath = parts[0].replace(base + os.sep, '').replace(base + '/', '')
                    results.append({"file": fpath, "line": int(parts[1]) if parts[1].isdigit() else 0, "text": parts[2]})
                if len(results) >= max_results:
                    break
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # ripgrep not available, fall through to Python

    # Python fallback
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        compiled = re.compile(pattern, flags)
    except re.error as e:
        return [{"file": "", "line": 0, "text": f"Invalid regex: {e}"}]

    base = Path(path).resolve()
    files = [base] if base.is_file() else sorted(base.rglob("*"))

    for fp in files:
        if not fp.is_file() or _should_skip(fp) or fp.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            lines = fp.read_text(encoding='utf-8', errors='replace').splitlines()
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    rel = str(fp.relative_to(base)) if base.is_dir() else fp.name
                    results.append({"file": rel, "line": i, "text": line.rstrip()[:500]})
                    if len(results) >= max_results:
                        return results
        except Exception:
            continue

    return results


# ── Tool 6: glob_tool ──────────────────────────────────────────────────────

def glob_tool(pattern: str, path: str) -> List[str]:
    """
    Find files matching a glob pattern.

    Args:
        pattern: Glob pattern (e.g., "**/*.py", "src/**/*.ts").
        path: Base directory to search from.

    Returns:
        List of relative file paths.
    """
    base = Path(path).resolve()
    if not base.exists():
        return [f"Error: Path not found: {path}"]

    results = []
    for fp in sorted(base.glob(pattern)):
        if _should_skip(fp):
            continue
        try:
            results.append(str(fp.relative_to(base)))
        except ValueError:
            results.append(str(fp))
        if len(results) >= MAX_RESULTS:
            break

    return results


# ── Tool 7: list_dir_tool ──────────────────────────────────────────────────

def list_dir_tool(path: str, max_depth: int = 2) -> str:
    """
    List directory contents as a tree.

    Args:
        path: Directory path.
        max_depth: Maximum recursion depth.

    Returns:
        Tree-formatted directory listing.
    """
    base = Path(path).resolve()
    if not base.exists():
        return f"Error: Directory not found: {path}"
    if not base.is_dir():
        return f"Error: Not a directory: {path}"

    lines = [str(base.name) + "/"]
    _build_tree(base, lines, prefix="", depth=0, max_depth=max_depth)
    return "\n".join(lines[:500])


def _build_tree(directory: Path, lines: list, prefix: str, depth: int, max_depth: int):
    """Recursively build directory tree."""
    if depth >= max_depth:
        return

    try:
        entries = sorted(directory.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
    except PermissionError:
        return

    # Filter out skip dirs
    entries = [e for e in entries if e.name not in SKIP_DIRS and not e.name.startswith('.')]

    for i, entry in enumerate(entries):
        is_last = (i == len(entries) - 1)
        connector = "--- " if is_last else "|-- "
        if entry.is_dir():
            lines.append(f"{prefix}{connector}{entry.name}/")
            extension = "    " if is_last else "|   "
            _build_tree(entry, lines, prefix + extension, depth + 1, max_depth)
        else:
            size = entry.stat().st_size
            size_str = f" ({_human_size(size)})" if size > 1024 else ""
            lines.append(f"{prefix}{connector}{entry.name}{size_str}")


def _human_size(size: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}TB"


# ── Tool 8: find_definition_tool ────────────────────────────────────────────

def find_definition_tool(symbol: str, path: str) -> List[dict]:
    """
    Find symbol definitions (class, def, function, const, var, let) using regex.

    Args:
        symbol: Symbol name to search for.
        path: Directory to search in.

    Returns:
        List of {file, line, kind, signature} dicts.
    """
    base = Path(path).resolve()
    results = []

    for fp in base.rglob("*"):
        if not fp.is_file() or _should_skip(fp):
            continue
        ext = fp.suffix
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            continue
        patterns = DEFINITION_PATTERNS.get(lang, [])
        if not patterns:
            continue

        try:
            lines = fp.read_text(encoding='utf-8', errors='replace').splitlines()
            for i, line in enumerate(lines, 1):
                for pat, kind in patterns:
                    m = re.match(pat, line)
                    if m:
                        # Extract the symbol name from the last captured group
                        groups = [g for g in m.groups() if g and g.strip() not in
                                  ('export', 'async', 'public', 'private', 'protected',
                                   'static', 'abstract', 'const', 'let', 'var', 'pub', 'internal')]
                        name = groups[-1] if groups else ""
                        if name == symbol:
                            rel = str(fp.relative_to(base))
                            results.append({
                                "file": rel,
                                "line": i,
                                "kind": kind,
                                "signature": line.strip()[:200],
                            })
                if len(results) >= 50:
                    break
        except Exception:
            continue
        if len(results) >= 50:
            break

    return results


# ── Tool 9: find_references_tool ────────────────────────────────────────────

def find_references_tool(symbol: str, path: str) -> List[dict]:
    """
    Find all references to a symbol across the codebase.

    Args:
        symbol: Symbol name to search for.
        path: Directory to search in.

    Returns:
        List of {file, line, text} dicts.
    """
    # Use grep_tool with word-boundary pattern
    pattern = rf'\b{re.escape(symbol)}\b'
    return grep_tool(pattern, path, max_results=100)


# ── Tool 10: symbols_tool ──────────────────────────────────────────────────

def symbols_tool(file_path: str) -> List[dict]:
    """
    List all symbols (functions, classes, variables) in a file using regex.

    Args:
        file_path: Path to the source file.

    Returns:
        List of {name, kind, line, signature} dicts.
    """
    p = Path(file_path).resolve()
    if not p.exists():
        return [{"error": f"File not found: {file_path}"}]

    ext = p.suffix
    lang = EXT_TO_LANG.get(ext)
    if not lang:
        return [{"error": f"Unsupported file type: {ext}"}]

    patterns = DEFINITION_PATTERNS.get(lang, [])
    if not patterns:
        return [{"error": f"No definition patterns for {lang}"}]

    results = []
    try:
        lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        for i, line in enumerate(lines, 1):
            for pat, kind in patterns:
                m = re.match(pat, line)
                if m:
                    groups = [g for g in m.groups() if g and g.strip() not in
                              ('export', 'async', 'public', 'private', 'protected',
                               'static', 'abstract', 'const', 'let', 'var', 'pub', 'internal')]
                    name = groups[-1] if groups else "unknown"
                    results.append({
                        "name": name,
                        "kind": kind,
                        "line": i,
                        "signature": line.strip()[:200],
                    })
                    break  # Only first matching pattern per line
    except Exception as e:
        return [{"error": f"Error parsing {file_path}: {e}"}]

    return results


# ── Tool 11: repo_map_tool ─────────────────────────────────────────────────

def repo_map_tool(path: str, max_files: int = 100) -> str:
    """
    Generate a structural map of the repository showing files and their symbols.

    Args:
        path: Repository root path.
        max_files: Max number of source files to index.

    Returns:
        Formatted repo map string.
    """
    base = Path(path).resolve()
    if not base.exists():
        return f"Error: Path not found: {path}"

    # Collect source files
    source_files = []
    for fp in sorted(base.rglob("*")):
        if not fp.is_file() or _should_skip(fp):
            continue
        if fp.suffix not in EXT_TO_LANG:
            continue
        if fp.stat().st_size > MAX_FILE_SIZE:
            continue
        source_files.append(fp)
        if len(source_files) >= max_files:
            break

    if not source_files:
        return "No source files found."

    # Count symbol references for ranking
    all_symbols = {}  # {name: [(file, kind, line)]}
    for fp in source_files:
        syms = symbols_tool(str(fp))
        for s in syms:
            if "error" in s:
                continue
            name = s.get("name", "")
            if name and len(name) > 2:  # Skip very short names
                if name not in all_symbols:
                    all_symbols[name] = []
                rel = str(fp.relative_to(base))
                all_symbols[name].append((rel, s["kind"], s["line"]))

    # Count references per file
    file_scores = {}
    ref_counts = {}
    for name, defs in all_symbols.items():
        # Quick count: how many files reference this symbol
        count = 0
        for fp in source_files:
            try:
                text = fp.read_text(encoding='utf-8', errors='replace')
                count += text.count(name)
            except Exception:
                pass
        ref_counts[name] = count
        for file_rel, _, _ in defs:
            file_scores[file_rel] = file_scores.get(file_rel, 0) + count

    # Build output ranked by importance
    ranked_files = sorted(file_scores.keys(), key=lambda f: file_scores[f], reverse=True)

    lines = ["Repository Map (ranked by importance):", ""]
    chars = 50
    budget = 8000  # ~2000 tokens

    for rel in ranked_files:
        file_line = f"{rel}:"
        defs = []
        for name, locs in all_symbols.items():
            for loc_file, kind, line_num in locs:
                if loc_file == rel:
                    defs.append(f"  {kind} {name}  [line {line_num}]")

        section = file_line + "\n" + "\n".join(defs) + "\n"
        if chars + len(section) > budget:
            lines.append(f"\n[Map truncated — {len(ranked_files)} files total]")
            break
        lines.append(section)
        chars += len(section)

    return "\n".join(lines)


# ── Tool registry (for programmatic access) ────────────────────────────────

CODEFIX_TOOLS = {
    "bash": bash_tool,
    "read": read_tool,
    "write": write_tool,
    "edit": edit_tool,
    "grep": grep_tool,
    "glob": glob_tool,
    "list_dir": list_dir_tool,
    "find_definition": find_definition_tool,
    "find_references": find_references_tool,
    "symbols": symbols_tool,
    "repo_map": repo_map_tool,
}


class CodefixTools:
    """Compatibility wrapper for programmatic access to codefix tools."""

    def __init__(self):
        self.tools = CODEFIX_TOOLS

    def get_tool(self, name):
        return self.tools.get(name)

    def list_tools(self):
        return list(self.tools.keys())
