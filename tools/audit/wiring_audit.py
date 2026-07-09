"""VIPER wiring audit — find orphan modules, broken imports, missing registrations.

Walks every .py file in the repo (skipping archive/, tests/, node_modules/,
.venv, dashboard/webapp/.next/, etc.), then:

  1. AST-parses each file to extract:
       - top-level imports (absolute + relative)
       - top-level function/class definitions
       - register_worker(...) calls and similar registration patterns
       - sys.argv / argparse / __main__ blocks (= CLI entry points)
  2. Builds an import graph (module -> [modules it imports]).
  3. Surfaces problems:
       - **orphan_modules**     — not imported by any other module + no
                                  __main__ block (i.e. dead code)
       - **broken_imports**     — `from X import Y` where X doesn't exist
                                  or Y isn't defined in X
       - **register_dangling**  — calls register_worker("phase","tech",...)
                                  where the parent package's __init__ never
                                  imports this module (so the registration
                                  never fires)
       - **cli_no_main**        — module has argparse but no
                                  `if __name__ == "__main__"` block
       - **missing_init**       — package dir has Python files but no
                                  __init__.py
       - **importable_but_empty** — module imports cleanly but exports
                                    nothing (no public symbols)

Output is JSON to stdout, plus a human summary to stderr.

Run::

    python -m tools.audit.wiring_audit            # full audit
    python -m tools.audit.wiring_audit --quick    # only orphans + broken
    python -m tools.audit.wiring_audit --json out.json
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("viper.wiring_audit")


# ─── Configuration ─────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories whose contents we don't audit (archive, vendored, build, tests).
SKIP_DIRS = {
    "__pycache__", ".git", ".venv", "venv", "node_modules",
    "archive", ".next", "out", "dist", "build", "htmlcov",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "tests",            # tests are allowed to import anything; not audited
    "labs", "juice-shop", "juice-shop-src", "training",
    "data", "logs", "reports", "state", "findings", "memory",
    # Vendored / quarantined source trees — not part of VIPER itself.
    # Any underscore-prefixed dir is treated as scratch/vendored (see
    # iter_python_files), so they need not be listed by name here.
    "programs", "pentest", "scripts",
    # Skill helpers (markdown-driven, not part of the Python graph)
    ".claude", "knowledge", "credentials", "scopes", "wordlists",
}

# Module names that are part of the audit's first-class graph. Everything
# else (stdlib, third-party) we treat as opaque.
VIPER_PACKAGES = {
    "ai", "agents", "core", "dashboard", "recon", "scanners",
    "scope", "tools",
}


# ─── Data model ────────────────────────────────────────────────────────

@dataclasses.dataclass
class ModuleInfo:
    """Per-module audit metadata."""
    dotted: str                       # e.g. "core.ai_hunter.probes"
    path: Path
    imports: list[str] = dataclasses.field(default_factory=list)
    relative_imports: list[str] = dataclasses.field(default_factory=list)
    defined: list[str] = dataclasses.field(default_factory=list)
    registrations: list[dict] = dataclasses.field(default_factory=list)
    has_main_block: bool = False
    has_argparse: bool = False
    parse_error: Optional[str] = None
    public_exports: list[str] = dataclasses.field(default_factory=list)

    def to_summary(self) -> dict:
        return {
            "dotted": self.dotted,
            "imports": self.imports,
            "registrations": self.registrations,
            "has_main": self.has_main_block,
            "has_argparse": self.has_argparse,
            "defined_count": len(self.defined),
            "parse_error": self.parse_error,
        }


@dataclasses.dataclass
class AuditReport:
    """The audit's findings."""
    modules: dict[str, ModuleInfo]
    orphan_modules: list[str]
    broken_imports: list[dict]
    register_dangling: list[dict]
    cli_no_main: list[str]
    missing_init: list[str]
    importable_but_empty: list[str]

    def summary(self) -> dict:
        return {
            "total_modules": len(self.modules),
            "orphans": len(self.orphan_modules),
            "broken_imports": len(self.broken_imports),
            "dangling_registrations": len(self.register_dangling),
            "cli_no_main": len(self.cli_no_main),
            "missing_init": len(self.missing_init),
            "empty_modules": len(self.importable_but_empty),
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "orphan_modules": self.orphan_modules,
            "broken_imports": self.broken_imports,
            "register_dangling": self.register_dangling,
            "cli_no_main": self.cli_no_main,
            "missing_init": self.missing_init,
            "importable_but_empty": self.importable_but_empty,
        }


# ─── AST walker ────────────────────────────────────────────────────────

class _ModuleVisitor(ast.NodeVisitor):
    def __init__(self, dotted: str, is_init: bool = False):
        self.dotted = dotted
        # For __init__.py the __package__ equals self.dotted itself.
        # For regular modules __package__ equals self.dotted's parent.
        self.is_init = is_init
        self.imports: list[str] = []
        self.relative_imports: list[str] = []
        self.defined: list[str] = []
        self.registrations: list[dict] = []
        self.has_main_block = False
        self.has_argparse = False
        self.public_exports: list[str] = []

    # imports
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if node.level > 0:
            # Relative import — resolve against __package__.
            # __init__.py: __package__ == self.dotted, so level=1 stays
            # in the same package (strip level-1 segments).
            # Regular module: __package__ == parent of self.dotted, so
            # level=1 strips just the module name itself.
            strip = node.level if not self.is_init else node.level - 1
            parts = self.dotted.split(".")
            base_parts = parts if strip == 0 else parts[:-strip]
            base = ".".join(base_parts)
            target = f"{base}.{mod}" if mod else base
            self.relative_imports.append(target)
            for alias in node.names:
                if alias.name != "*":
                    self.imports.append(f"{target}.{alias.name}")
                else:
                    self.imports.append(target)
        else:
            for alias in node.names:
                self.imports.append(f"{mod}.{alias.name}" if mod else alias.name)

    # definitions
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.defined.append(node.name)
        self._note_if_public(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node) -> None:
        self.defined.append(node.name)
        self._note_if_public(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.defined.append(node.name)
        self._note_if_public(node.name)
        self.generic_visit(node)

    def _note_if_public(self, name: str) -> None:
        if not name.startswith("_"):
            self.public_exports.append(name)

    # registrations + main + argparse
    def visit_Call(self, node: ast.Call) -> None:
        fn_name = _call_name(node.func)
        if fn_name and fn_name.endswith("register_worker"):
            args = []
            for a in node.args[:3]:
                try:
                    args.append(ast.literal_eval(a))
                except Exception:
                    args.append("<dynamic>")
            self.registrations.append({"call": fn_name, "args": args})

        # ModuleLoader.register("dotted.path", "Symbol", ...) — counts as
        # an import of dotted.path for wiring purposes.
        if fn_name and fn_name.endswith(".register") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                target = first.value
                if "." in target:           # heuristic: skip plain identifiers
                    self.imports.append(target)

        # importlib.import_module("dotted.path") OR __import__("dotted.path")
        # — both count as dynamic imports.
        if fn_name and (fn_name.endswith("import_module")
                        or fn_name == "__import__") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                target = first.value
                if "." in target:
                    self.imports.append(target)
            # f-string-built dynamic imports — heuristic: capture the literal
            # prefix from JoinedStr "core.skill_prompts.{name}" so each
            # registered sibling is treated as imported.
            elif isinstance(first, ast.JoinedStr):
                lit = "".join(
                    v.value for v in first.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
                lit = lit.rstrip(".")
                if "." in lit:
                    # Mark every same-package sibling as imported — the
                    # f-string presumably resolves to one of them.
                    self.imports.append(lit + ".*")

        if fn_name and "argparse" in fn_name.lower() and "argumentparser" in fn_name.lower():
            self.has_argparse = True
        if fn_name == "ArgumentParser":
            self.has_argparse = True
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        # detect `if __name__ == "__main__"` blocks
        if isinstance(node.test, ast.Compare):
            left = node.test.left
            if (isinstance(left, ast.Name) and left.id == "__name__"
                    and any(isinstance(c, ast.Eq) for c in node.test.ops)):
                for cmp in node.test.comparators:
                    val = _const_value(cmp)
                    if val == "__main__":
                        self.has_main_block = True
                        break
        self.generic_visit(node)


def _call_name(node: ast.AST) -> Optional[str]:
    """Resolve dotted name of a Call.func node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _const_value(node: ast.AST):
    if isinstance(node, ast.Constant):
        return node.value
    return None


# ─── File discovery ───────────────────────────────────────────────────

def iter_python_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        # Any underscore-prefixed directory is scratch/vendored — skip it.
        if any(part.startswith("_") and part != "__init__.py" for part in p.parts[:-1]):
            continue
        # also skip top-level tests/
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        if rel.parts and rel.parts[0] in SKIP_DIRS:
            continue
        yield p


def dotted_for_path(repo_root: Path, path: Path) -> str:
    rel = path.relative_to(repo_root)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


# ─── Analysis ─────────────────────────────────────────────────────────

def analyse_module(path: Path, dotted: str) -> ModuleInfo:
    info = ModuleInfo(dotted=dotted, path=path)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        info.parse_error = f"SyntaxError: {exc}"
        return info
    except Exception as exc:  # noqa: BLE001
        info.parse_error = repr(exc)
        return info
    v = _ModuleVisitor(dotted, is_init=(path.name == "__init__.py"))
    v.visit(tree)
    info.imports = sorted(set(v.imports))
    info.relative_imports = sorted(set(v.relative_imports))
    info.defined = v.defined
    info.registrations = v.registrations
    info.has_main_block = v.has_main_block
    info.has_argparse = v.has_argparse
    info.public_exports = v.public_exports
    return info


def build_report(modules: dict[str, ModuleInfo]) -> AuditReport:
    # Expand "pkg.*" wildcards (from f-string-built dynamic imports) into
    # every sibling under that package — be permissive about reachability.
    for mod in modules.values():
        expanded = list(mod.imports)
        for imp in list(mod.imports):
            if imp.endswith(".*"):
                pkg = imp[:-2]
                for other in modules:
                    if other.startswith(pkg + "."):
                        expanded.append(other)
        mod.imports = sorted(set(expanded))

    # Reverse-import graph
    importers: dict[str, set[str]] = defaultdict(set)
    for mod in modules.values():
        for imp in mod.imports + mod.relative_imports:
            # Find the longest existing prefix that matches a known module
            target = _resolve_to_known(imp, modules)
            if target:
                importers[target].add(mod.dotted)

    orphans: list[str] = []
    broken: list[dict] = []
    dangling: list[dict] = []
    cli_no_main: list[str] = []
    importable_but_empty: list[str] = []

    for mod in modules.values():
        # orphan: not imported by anyone + not a CLI entry + not __init__.py
        is_init = mod.path.name == "__init__.py"
        is_test = mod.path.name.startswith("test_")
        is_main = mod.path.name == "__main__.py" or mod.has_main_block
        has_callers = bool(importers.get(mod.dotted))
        if not is_init and not is_test and not is_main and not has_callers:
            # only flag if the parent package's __init__ doesn't reach it
            parent = ".".join(mod.dotted.split(".")[:-1])
            if parent and parent in modules:
                if mod.dotted not in set(modules[parent].imports) \
                        and mod.dotted not in set(modules[parent].relative_imports):
                    orphans.append(mod.dotted)
            else:
                orphans.append(mod.dotted)

        # broken imports: from X import Y where X is a VIPER package but
        # we can't find a matching dotted module
        for imp in mod.imports:
            head = imp.split(".")[0]
            if head not in VIPER_PACKAGES:
                continue
            target = _resolve_to_known(imp, modules)
            if not target and not _resolve_symbol(imp, modules):
                broken.append({"in": mod.dotted, "import": imp})

        # cli without main block
        if mod.has_argparse and not mod.has_main_block and not is_init:
            cli_no_main.append(mod.dotted)

        # importable but empty: __init__ that exports nothing AND doesn't
        # re-export anything from siblings (those have empty defined +
        # empty imports of sibling modules)
        if is_init and not mod.public_exports \
                and not any(i.startswith(mod.dotted + ".") for i in mod.imports):
            # only flag if the package has at least one sibling that
            # could have been re-exported
            siblings = [m for m in modules.values()
                        if m.dotted.startswith(mod.dotted + ".")
                        and m.path.name not in ("__init__.py", "__main__.py")]
            if siblings:
                importable_but_empty.append(mod.dotted)

        # dangling registrations
        for reg in mod.registrations:
            args = reg.get("args", [])
            if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], str):
                # find the parent package and confirm this module is reachable
                parent = ".".join(mod.dotted.split(".")[:-1])
                parent_init = modules.get(parent)
                if parent_init is None:
                    continue
                reachable = (
                    mod.dotted.split(".")[-1] in parent_init.public_exports
                    or any(mod.dotted == r or r.startswith(mod.dotted + ".")
                           for r in parent_init.imports + parent_init.relative_imports)
                    or mod.dotted in parent_init.imports
                )
                if not reachable:
                    dangling.append({
                        "module": mod.dotted,
                        "phase": args[0],
                        "technique": args[1],
                        "reason": (f"parent {parent}/__init__.py never imports "
                                   f"{mod.dotted.split('.')[-1]} — registration "
                                   f"will never fire"),
                    })

    # missing __init__
    seen_pkg_dirs: set[Path] = set()
    missing_init: list[str] = []
    for mod in modules.values():
        for parent_path in mod.path.parents:
            if parent_path == REPO_ROOT or REPO_ROOT not in parent_path.parents:
                break
            if any(part in SKIP_DIRS for part in parent_path.parts):
                continue
            if parent_path in seen_pkg_dirs:
                continue
            seen_pkg_dirs.add(parent_path)
            init_file = parent_path / "__init__.py"
            has_py = any((parent_path / f).is_file()
                         and f.endswith(".py") for f in
                         (p.name for p in parent_path.iterdir()
                          if p.is_file()))
            if has_py and not init_file.exists() and \
                    parent_path.name not in SKIP_DIRS:
                rel = parent_path.relative_to(REPO_ROOT)
                missing_init.append(str(rel).replace("\\", "/"))

    return AuditReport(
        modules=modules,
        orphan_modules=sorted(set(orphans)),
        broken_imports=broken,
        register_dangling=dangling,
        cli_no_main=sorted(set(cli_no_main)),
        missing_init=sorted(set(missing_init)),
        importable_but_empty=sorted(set(importable_but_empty)),
    )


def _resolve_to_known(imp: str, modules: dict[str, ModuleInfo]) -> Optional[str]:
    """Try shrinking the dotted name until it matches a known module."""
    if imp.endswith(".*"):
        imp = imp[:-2]
    parts = imp.split(".")
    for i in range(len(parts), 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in modules:
            return candidate
    return None


def _resolve_symbol(imp: str, modules: dict[str, ModuleInfo]) -> bool:
    """Is the trailing name a symbol defined in the longest-matching module?"""
    parts = imp.split(".")
    for i in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:i])
        mod = modules.get(candidate)
        if mod:
            tail = ".".join(parts[i:])
            head = tail.split(".")[0]
            return head in mod.defined or head in mod.public_exports
    return False


# ─── CLI ──────────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="VIPER wiring audit")
    p.add_argument("--root", default=str(REPO_ROOT),
                   help="Repo root (default: detected from this file's location)")
    p.add_argument("--json", default=None, help="Write JSON to this path")
    p.add_argument("--quick", action="store_true",
                   help="Only emit orphans + broken_imports")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s — %(message)s",
    )

    root = Path(args.root).resolve()
    print(f"[audit] root = {root}", file=sys.stderr)

    modules: dict[str, ModuleInfo] = {}
    for path in iter_python_files(root):
        try:
            dotted = dotted_for_path(root, path)
        except ValueError:
            continue
        if not dotted:
            continue
        modules[dotted] = analyse_module(path, dotted)

    report = build_report(modules)
    payload = report.to_dict()

    # Always show summary on stderr
    summary = report.summary()
    print("=" * 60, file=sys.stderr)
    print(f"VIPER Wiring Audit — {summary['total_modules']} modules", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    for k, v in summary.items():
        if k == "total_modules":
            continue
        flag = "!" if v else " "
        print(f"  {flag} {k:24} {v}", file=sys.stderr)

    if args.quick:
        payload = {
            "summary": payload["summary"],
            "orphan_modules": payload["orphan_modules"],
            "broken_imports": payload["broken_imports"],
        }

    out = json.dumps(payload, indent=2, default=str)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(out, encoding="utf-8")
        print(f"[audit] wrote JSON to {args.json}", file=sys.stderr)
    else:
        print(out)

    return 0 if not (report.broken_imports
                     or report.register_dangling) else 1


if __name__ == "__main__":
    raise SystemExit(main())
