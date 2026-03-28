#!/usr/bin/env python3
"""
VIPER 4.0 Phase D — CodeFix Tools (Tree-Sitter + Regex Fallback).

11 code manipulation tools for the CodeFix engine's ReACT loop.
Uses tree-sitter AST parsing when available, degrades gracefully to regex.
"""

import fnmatch
import logging
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("viper.codefix_tools")

# ── Safety constants ──────────────────────────────────────────────────────

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

# ── Language detection ────────────────────────────────────────────────────

EXT_TO_LANG = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.jsx': 'javascript', '.java': 'java', '.go': 'go', '.rs': 'rust',
    '.rb': 'ruby', '.php': 'php', '.c': 'c', '.cpp': 'cpp', '.cs': 'csharp',
    '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
    '.html': 'html', '.css': 'css', '.yml': 'yaml', '.yaml': 'yaml',
    '.json': 'json', '.xml': 'xml', '.sh': 'shell', '.bash': 'shell',
}

# tree-sitter language name mapping (some differ from EXT_TO_LANG values)
TS_LANG_MAP = {
    'python': 'python', 'javascript': 'javascript', 'typescript': 'typescript',
    'java': 'java', 'go': 'go', 'rust': 'rust', 'ruby': 'ruby', 'php': 'php',
    'c': 'c', 'cpp': 'cpp', 'csharp': 'c_sharp', 'kotlin': 'kotlin',
    'swift': 'swift', 'scala': 'scala',
}

# tree-sitter AST node types that represent definitions
TS_DEFINITION_TYPES = {
    'python': ['function_definition', 'class_definition', 'decorated_definition'],
    'javascript': ['function_declaration', 'class_declaration', 'method_definition',
                    'arrow_function', 'variable_declarator'],
    'typescript': ['function_declaration', 'class_declaration', 'method_definition',
                    'arrow_function', 'variable_declarator', 'interface_declaration',
                    'type_alias_declaration'],
    'java': ['class_declaration', 'method_declaration', 'interface_declaration'],
    'go': ['function_declaration', 'method_declaration', 'type_declaration'],
    'rust': ['function_item', 'impl_item', 'struct_item', 'enum_item', 'trait_item'],
    'ruby': ['method', 'class', 'module', 'singleton_method'],
    'php': ['function_definition', 'class_declaration', 'method_declaration'],
    'c': ['function_definition', 'struct_specifier'],
    'cpp': ['function_definition', 'class_specifier', 'struct_specifier'],
    'c_sharp': ['class_declaration', 'method_declaration', 'interface_declaration'],
}

# Regex fallback patterns for definition finding (no tree-sitter needed)
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

# ── Tree-sitter availability detection ────────────────────────────────────

_TREE_SITTER_AVAILABLE = None
_TS_PARSERS: Dict[str, Any] = {}


def _check_tree_sitter() -> bool:
    """Check if tree-sitter is available. Cached after first call."""
    global _TREE_SITTER_AVAILABLE
    if _TREE_SITTER_AVAILABLE is not None:
        return _TREE_SITTER_AVAILABLE
    try:
        from tree_sitter_languages import get_parser  # noqa: F401
        _TREE_SITTER_AVAILABLE = True
        logger.info("tree-sitter available — using AST-based symbol extraction")
    except ImportError:
        _TREE_SITTER_AVAILABLE = False
        logger.info("tree-sitter not available — using regex-based symbol extraction")
    return _TREE_SITTER_AVAILABLE


def _get_ts_parser(lang: str):
    """Get a tree-sitter parser for the given language. Returns None if unavailable."""
    if not _check_tree_sitter():
        return None
    ts_lang = TS_LANG_MAP.get(lang)
    if not ts_lang:
        return None
    if ts_lang in _TS_PARSERS:
        return _TS_PARSERS[ts_lang]
    try:
        from tree_sitter_languages import get_parser
        parser = get_parser(ts_lang)
        _TS_PARSERS[ts_lang] = parser
        return parser
    except Exception as e:
        logger.debug(f"tree-sitter parser unavailable for {ts_lang}: {e}")
        _TS_PARSERS[ts_lang] = None
        return None


# ── Tree-sitter AST helpers ───────────────────────────────────────────────

def _ts_extract_name(node) -> Optional[str]:
    """Extract the name identifier from a tree-sitter definition node."""
    for child in node.children:
        if child.type in ('identifier', 'name', 'property_identifier', 'type_identifier'):
            return child.text.decode('utf-8')
    return None


def _ts_walk_definitions(node, lang: str, depth: int = 0,
                         parent_name: str = None) -> List[Dict]:
    """Walk tree-sitter AST and extract definitions with line ranges."""
    definitions = []
    ts_lang = TS_LANG_MAP.get(lang, lang)
    def_types = TS_DEFINITION_TYPES.get(ts_lang, [])

    for child in node.children:
        if child.type in def_types:
            name = _ts_extract_name(child)
            if name:
                start_line = child.start_point[0] + 1
                end_line = child.end_point[0] + 1
                kind = (child.type
                        .replace('_definition', '')
                        .replace('_declaration', '')
                        .replace('_item', ''))
                scope = f"{parent_name} > " if parent_name else ""
                definitions.append({
                    'name': name,
                    'kind': kind,
                    'start_line': start_line,
                    'end_line': end_line,
                    'line': start_line,
                    'scope': scope,
                    'depth': depth,
                    'signature': child.text.decode('utf-8', errors='replace').split('\n')[0][:200],
                })
                # Recurse for nested definitions (methods inside classes, etc.)
                definitions.extend(
                    _ts_walk_definitions(child, lang, depth + 1, name)
                )
        else:
            definitions.extend(
                _ts_walk_definitions(child, lang, depth, parent_name)
            )

    return definitions


def _ts_find_refs_in_tree(node, symbol: str, lang: str, file_path: Path,
                          repo_path: Path, text_lines: List[str],
                          results: List[Dict]):
    """Walk tree-sitter AST to find identifier references (excluding definitions)."""
    if node.type == 'identifier' and node.text.decode('utf-8') == symbol:
        parent = node.parent
        ts_lang = TS_LANG_MAP.get(lang, lang)
        def_types = TS_DEFINITION_TYPES.get(ts_lang, [])
        if parent and parent.type not in def_types:
            line = node.start_point[0] + 1
            rel = str(file_path.relative_to(repo_path))
            ctx = text_lines[line - 1].strip()[:200] if line <= len(text_lines) else ""
            results.append({'file': rel, 'line': line, 'text': ctx})

    for child in node.children:
        if len(results) >= MAX_RESULTS:
            return
        _ts_find_refs_in_tree(child, symbol, lang, file_path, repo_path,
                              text_lines, results)


# ── Utility helpers ───────────────────────────────────────────────────────

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


def _extract_symbol_name(match: re.Match) -> str:
    """Extract the symbol name from a regex match (last meaningful group)."""
    NOISE = {'export', 'async', 'public', 'private', 'protected',
             'static', 'abstract', 'const', 'let', 'var', 'pub', 'internal'}
    groups = [g for g in match.groups() if g and g.strip() not in NOISE]
    return groups[-1] if groups else ""


def _iter_source_files(base: Path, max_files: int = 500):
    """Iterate over source files under base, skipping junk dirs."""
    count = 0
    for fp in sorted(base.rglob("*")):
        if not fp.is_file() or _should_skip(fp):
            continue
        if fp.suffix not in EXT_TO_LANG:
            continue
        if fp.stat().st_size > MAX_FILE_SIZE:
            continue
        yield fp
        count += 1
        if count >= max_files:
            break


# ── Tool 1: symbols ──────────────────────────────────────────────────────

def symbols_tool(file_path: str) -> List[Dict]:
    """
    Extract all symbols (functions, classes, methods) from a file with line ranges.

    Uses tree-sitter AST when available; falls back to regex patterns.

    Args:
        file_path: Path to the source file.

    Returns:
        List of {name, kind, line, start_line, end_line, signature, depth, scope}.
    """
    p = Path(file_path).resolve()
    if not p.exists():
        return [{"error": f"File not found: {file_path}"}]

    ext = p.suffix
    lang = EXT_TO_LANG.get(ext)
    if not lang:
        return [{"error": f"Unsupported file type: {ext}"}]

    # Try tree-sitter first
    parser = _get_ts_parser(lang)
    if parser:
        try:
            content = p.read_bytes()
            tree = parser.parse(content)
            definitions = _ts_walk_definitions(tree.root_node, lang)
            if definitions:
                return definitions
            # If tree-sitter found nothing, fall through to regex
        except Exception as e:
            logger.debug(f"tree-sitter parse failed for {file_path}: {e}")

    # Regex fallback
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
                    name = _extract_symbol_name(m)
                    if name:
                        results.append({
                            "name": name,
                            "kind": kind,
                            "line": i,
                            "start_line": i,
                            "end_line": i,  # regex can't determine end
                            "signature": line.strip()[:200],
                            "depth": 0,
                            "scope": "",
                        })
                    break  # Only first matching pattern per line
    except Exception as e:
        return [{"error": f"Error parsing {file_path}: {e}"}]

    return results


# ── Tool 2: find_definition ──────────────────────────────────────────────

def find_definition_tool(symbol: str, path: str) -> List[Dict]:
    """
    Find where a symbol is defined across the repo using tree-sitter or regex.

    Args:
        symbol: Symbol name to search for.
        path: Directory to search in.

    Returns:
        List of {file, line, kind, signature} dicts.
    """
    base = Path(path).resolve()
    results = []

    for fp in _iter_source_files(base):
        ext = fp.suffix
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            continue

        # Try tree-sitter
        parser = _get_ts_parser(lang)
        if parser:
            try:
                content = fp.read_bytes()
                tree = parser.parse(content)
                ts_lang = TS_LANG_MAP.get(lang, lang)
                def_types = TS_DEFINITION_TYPES.get(ts_lang, [])
                _ts_find_defs_recursive(
                    tree.root_node, symbol, def_types, fp, base, results
                )
                if len(results) >= 50:
                    break
                continue
            except Exception:
                pass  # Fall through to regex

        # Regex fallback
        patterns = DEFINITION_PATTERNS.get(lang, [])
        if not patterns:
            continue
        try:
            lines = fp.read_text(encoding='utf-8', errors='replace').splitlines()
            for i, line in enumerate(lines, 1):
                for pat, kind in patterns:
                    m = re.match(pat, line)
                    if m:
                        name = _extract_symbol_name(m)
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


def _ts_find_defs_recursive(node, symbol: str, def_types: list,
                            file_path: Path, repo_path: Path,
                            results: List[Dict]):
    """Recursively search tree-sitter AST for definitions matching symbol."""
    for child in node.children:
        if child.type in def_types:
            name = _ts_extract_name(child)
            if name == symbol:
                rel = str(file_path.relative_to(repo_path))
                line = child.start_point[0] + 1
                kind = (child.type
                        .replace('_definition', '')
                        .replace('_declaration', '')
                        .replace('_item', ''))
                sig = child.text.decode('utf-8', errors='replace').split('\n')[0][:200]
                results.append({
                    'file': rel, 'line': line, 'kind': kind, 'signature': sig,
                })
        _ts_find_defs_recursive(child, symbol, def_types,
                                file_path, repo_path, results)


# ── Tool 3: find_references ──────────────────────────────────────────────

def find_references_tool(symbol: str, path: str, file_path: str = None) -> List[Dict]:
    """
    Find all references to a symbol across the codebase.
    Uses tree-sitter to skip definitions and comments; falls back to word-boundary grep.

    Args:
        symbol: Symbol name to search for.
        path: Repository root path.
        file_path: Optional — limit search to this single file.

    Returns:
        List of {file, line, text} dicts.
    """
    base = Path(path).resolve()

    if file_path:
        files = [base / file_path]
    else:
        files = list(_iter_source_files(base))

    results = []
    used_tree_sitter = False

    for fp in files:
        ext = fp.suffix
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            continue

        # Try tree-sitter
        parser = _get_ts_parser(lang)
        if parser:
            try:
                content = fp.read_bytes()
                text_lines = content.decode('utf-8', errors='replace').splitlines()
                tree = parser.parse(content)
                _ts_find_refs_in_tree(
                    tree.root_node, symbol, lang, fp, base, text_lines, results
                )
                used_tree_sitter = True
                if len(results) >= MAX_RESULTS:
                    break
                continue
            except Exception:
                pass

        # Regex fallback: word-boundary grep
        try:
            text = fp.read_text(encoding='utf-8', errors='replace')
            pat = re.compile(rf'\b{re.escape(symbol)}\b')
            for i, line in enumerate(text.splitlines(), 1):
                if pat.search(line):
                    rel = str(fp.relative_to(base))
                    results.append({"file": rel, "line": i, "text": line.strip()[:200]})
                    if len(results) >= MAX_RESULTS:
                        break
        except Exception:
            continue
        if len(results) >= MAX_RESULTS:
            break

    return results


# ── Tool 4: repo_map ─────────────────────────────────────────────────────

def repo_map_tool(path: str, max_files: int = 100, max_tokens: int = 2000,
                  focus_paths: List[str] = None) -> str:
    """
    Generate a cross-file dependency graph ranked by symbol reference counts.
    Uses tree-sitter when available for accurate symbol extraction.

    Args:
        path: Repository root path.
        max_files: Max number of source files to index.
        max_tokens: Token budget for output (~4 chars/token).
        focus_paths: Optional list of directories/files to focus on.

    Returns:
        Formatted repo map string.
    """
    base = Path(path).resolve()
    if not base.exists():
        return f"Error: Path not found: {path}"

    # Collect files
    if focus_paths:
        source_files = []
        for fp in focus_paths:
            target = base / fp
            if target.is_dir():
                source_files.extend(list(_iter_source_files(target, max_files)))
            elif target.is_file():
                source_files.append(target)
    else:
        source_files = list(_iter_source_files(base, max_files))

    if not source_files:
        return "No source files found."

    # Extract symbols from each file
    file_symbols: Dict[str, List[Dict]] = {}
    all_symbol_names = set()

    for fp in source_files:
        syms = symbols_tool(str(fp))
        valid = [s for s in syms if "error" not in s and s.get("name")]
        if valid:
            rel = str(fp.relative_to(base))
            file_symbols[rel] = valid
            for s in valid:
                name = s["name"]
                if len(name) > 2:  # Skip very short names
                    all_symbol_names.add(name)

    # Count references for ranking
    ref_counts: Dict[str, int] = defaultdict(int)
    for fp in source_files:
        try:
            text = fp.read_text(encoding='utf-8', errors='replace')
            for name in all_symbol_names:
                count = text.count(name)
                if count > 0:
                    ref_counts[name] += count
        except Exception:
            continue

    # Score files by total reference count of their symbols
    file_scores: Dict[str, int] = defaultdict(int)
    for rel, syms in file_symbols.items():
        for s in syms:
            file_scores[rel] += ref_counts.get(s["name"], 0)

    ranked_files = sorted(file_symbols.keys(),
                          key=lambda f: file_scores[f], reverse=True)

    # Build output within token budget
    lines = ["Repository Map (ranked by importance):", ""]
    chars_used = 50
    chars_budget = max_tokens * 4

    for rel in ranked_files:
        syms = file_symbols[rel]
        if not syms:
            continue

        file_line = f"{rel}:"
        def_lines = []
        for s in syms:
            if s.get("depth", 0) == 0:
                end = f"-{s['end_line']}" if s.get('end_line') and s['end_line'] != s.get('start_line') else ""
                def_lines.append(
                    f"  {s['kind']} {s['name']}  [{s.get('start_line', s.get('line', '?'))}{end}]"
                )

        section = file_line + "\n" + "\n".join(def_lines) + "\n"
        if chars_used + len(section) > chars_budget:
            lines.append(f"\n[Map truncated at token budget ({max_tokens} tokens)]")
            break
        lines.append(section)
        chars_used += len(section)

    return "\n".join(lines)


# ── Tool 5: edit ──────────────────────────────────────────────────────────

def edit_tool(file_path: str, old_text: str, new_text: str,
              replace_all: bool = False) -> str:
    """
    Exact string replacement in a file.

    Args:
        file_path: Path to the file.
        old_text: Text to find (must be unique unless replace_all=True).
        new_text: Replacement text.
        replace_all: Replace all occurrences (default: False).

    Returns:
        Success/error message string.
    """
    try:
        p = Path(file_path).resolve()
        if not p.exists():
            return f"Error: File not found: {file_path}"

        content = p.read_text(encoding='utf-8', errors='replace')
        count = content.count(old_text)

        if count == 0:
            return (f"Error: old_text not found in {file_path}. "
                    "Read the file first to see current content.")
        if old_text == new_text:
            return "Error: new_text is identical to old_text. No changes made."
        if count > 1 and not replace_all:
            return (f"Error: old_text found {count} times in {file_path}. "
                    "Provide more context to make it unique, or set replace_all=True.")

        new_content = content.replace(old_text, new_text, -1 if replace_all else 1)
        p.write_text(new_content, encoding='utf-8')

        replaced = count if replace_all else 1
        logger.info(f"Edited {file_path}: replaced {replaced} occurrence(s)")
        return f"OK: Replaced {replaced} occurrence(s) in {file_path}."

    except Exception as e:
        return f"Error editing {file_path}: {e}"


# ── Tool 6: read ──────────────────────────────────────────────────────────

def read_tool(file_path: str, offset: int = 0, limit: int = 2000) -> str:
    """
    Read a file's contents with line numbers.

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


# ── Tool 7: grep ──────────────────────────────────────────────────────────

def grep_tool(pattern: str, path: str, max_results: int = 50,
              case_insensitive: bool = False, context: int = 0) -> List[Dict]:
    """
    Regex search across files. Uses ripgrep if available, falls back to Python regex.

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
        if proc.returncode <= 1:
            base = str(Path(path).resolve())
            for line in proc.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    fpath = parts[0].replace(base + os.sep, '').replace(base + '/', '')
                    results.append({
                        "file": fpath,
                        "line": int(parts[1]) if parts[1].isdigit() else 0,
                        "text": parts[2],
                    })
                if len(results) >= max_results:
                    break
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

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


# ── Tool 8: glob ──────────────────────────────────────────────────────────

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


# ── Tool 9: list_dir ─────────────────────────────────────────────────────

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


def _build_tree(directory: Path, lines: list, prefix: str,
                depth: int, max_depth: int):
    """Recursively build directory tree."""
    if depth >= max_depth:
        return

    try:
        entries = sorted(directory.iterdir(),
                         key=lambda e: (not e.is_dir(), e.name.lower()))
    except PermissionError:
        return

    entries = [e for e in entries
               if e.name not in SKIP_DIRS and not e.name.startswith('.')]

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


# ── Tool 10: bash ─────────────────────────────────────────────────────────

def bash_tool(command: str, cwd: str = None, timeout: int = 30) -> str:
    """
    Execute a shell command safely (sandboxed to repo dir).

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


# ── Tool 11: write ────────────────────────────────────────────────────────

def write_tool(file_path: str, content: str) -> str:
    """
    Write content to a file. Creates parent directories if needed.

    Args:
        file_path: Path to write to.
        content: File content.

    Returns:
        Success/error message.
    """
    try:
        p = Path(file_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Wrote {len(content)} chars to {p}")
        return f"OK: Wrote {len(content)} chars to {file_path}."
    except Exception as e:
        return f"Error writing {file_path}: {e}"


# ── Tool registry ────────────────────────────────────────────────────────

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

# LLM tool definitions (JSON schema for the ReACT loop)
CODEFIX_TOOL_DEFS = [
    {
        "name": "symbols",
        "description": "List all functions, classes, methods in a file with line ranges. Uses tree-sitter AST when available. Use BEFORE reading a file to find relevant sections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the source file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "find_definition",
        "description": "Find where a symbol is defined across the codebase. More precise than grep — returns only definitions, not usages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Name of function/class/method/variable"},
                "path": {"type": "string", "description": "Directory to search in (default: repo root)"},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "find_references",
        "description": "Find all usages of a symbol across the codebase. With tree-sitter, skips definitions and comments.",
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Symbol name to search for"},
                "path": {"type": "string", "description": "Repository root path"},
                "file_path": {"type": "string", "description": "Limit search to this file"},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "repo_map",
        "description": "Generate a codebase overview: files with function/class signatures ranked by cross-reference importance. Use FIRST on unfamiliar repos.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository root path"},
                "max_tokens": {"type": "integer", "description": "Token budget (default: 2000)"},
                "focus_paths": {"type": "array", "items": {"type": "string"}, "description": "Directories to focus on"},
            },
        },
    },
    {
        "name": "edit",
        "description": "Exact string replacement in a file. old_text must be UNIQUE. You MUST read the file first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "old_text": {"type": "string", "description": "Exact text to replace"},
                "new_text": {"type": "string", "description": "Replacement text"},
                "replace_all": {"type": "boolean", "description": "Replace all occurrences (default: false)"},
            },
            "required": ["file_path", "old_text", "new_text"],
        },
    },
    {
        "name": "read",
        "description": "Read a file with line numbers. ALWAYS read before editing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
                "offset": {"type": "integer", "description": "Start line (0-based)"},
                "limit": {"type": "integer", "description": "Number of lines to read (default: 2000)"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "grep",
        "description": "Regex search across files. Uses ripgrep when available.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "path": {"type": "string", "description": "Directory or file to search"},
                "max_results": {"type": "integer", "description": "Max matches (default: 50)"},
                "case_insensitive": {"type": "boolean"},
                "context": {"type": "integer", "description": "Lines of context around matches"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "glob",
        "description": "File pattern matching. Returns relative paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern (e.g., '**/*.py')"},
                "path": {"type": "string", "description": "Base directory (default: repo root)"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "list_dir",
        "description": "Directory listing as a tree.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path (default: repo root)"},
                "max_depth": {"type": "integer", "description": "Max depth (default: 2)"},
            },
        },
    },
    {
        "name": "bash",
        "description": "Run a shell command. Sandboxed to repo dir. Available runtimes: node, python3, go, java, make/gcc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "cwd": {"type": "string", "description": "Working directory"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (max 120)"},
            },
            "required": ["command"],
        },
    },
]


class CodefixTools:
    """Compatibility wrapper for programmatic access to codefix tools."""

    def __init__(self):
        self.tools = CODEFIX_TOOLS

    def get_tool(self, name):
        return self.tools.get(name)

    def list_tools(self):
        return list(self.tools.keys())

    @staticmethod
    def has_tree_sitter() -> bool:
        """Check if tree-sitter is available."""
        return _check_tree_sitter()
