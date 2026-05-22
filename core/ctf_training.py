"""
VIPER 5.0 - CTF Training Loop
===============================
Autonomous training pipeline that ingests public CTF writeups and
extracts technique patterns into VIPER's knowledge base and feedback
store.

Sources supported:
  - Raw markdown/text URLs (writeup links)
  - GitHub repos (whole writeup collections like ctfs/write-ups)
  - Local directory of writeup files (.md, .txt)

Stages per writeup:
  1. Fetch content (stdlib urllib only, no deps)
  2. Parse: detect challenge name, category, tech stack, techniques
  3. Score: identify the winning technique(s) vs dead-ends
  4. Ingest into CTFFeedbackStore as a FeedbackEntry
  5. KB gets a chunk via the feedback auto-KB write path

Usage (CLI)::

    python -m core.ctf_training from-url https://raw.githubusercontent.com/...
    python -m core.ctf_training from-dir ./writeups/
    python -m core.ctf_training summary
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("viper.core.ctf_training")


# ── Category inference from writeup text ────────────────────────────────────

CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "web": [
        "sqli", "xss", "ssrf", "ssti", "csrf", "idor", "jwt", "cors",
        "graphql", "prototype pollution", "deserialization", "sql injection",
        "cross-site", "race condition", "lfi", "rfi", "file upload",
        "wordpress", "path traversal", "cve-202", "url", "http",
    ],
    "pwn": [
        "rop", "ret2", "buffer overflow", "stack smash", "format string",
        "heap", "fastbin", "tcache", "shellcode", "canary", "aslr", "pie",
        "gdb", "pwntools", "libc", "one_gadget",
    ],
    "crypto": [
        "aes", "rsa", "padding oracle", "ecb", "cbc", "stream cipher",
        "xor", "hash collision", "lll", "lattice", "diffie", "discrete log",
        "factorize", "modular", "ciphertext", "key reuse",
    ],
    "rev": [
        "reverse", "ghidra", "ida pro", "radare", "disassembl",
        "decompil", "binary analysis", "angr", "strings", "objdump",
        "elf", "pe file", "patch",
    ],
    "forensics": [
        "wireshark", "pcap", "volatility", "memory dump", "disk image",
        "autopsy", "foremost", "binwalk", "steganography", "stegsolve",
        "exiftool", "zsteg", "hidden file", "slack space",
    ],
    "misc": [
        "osint", "ctftime", "recon only", "game hacking", "esoteric",
        "brainfuck", "whitespace", "qr code", "morse",
    ],
    "osint": [
        "osint", "social media", "reverse image", "exif", "shodan",
        "google dork", "linkedin", "github search",
    ],
}


TECHNIQUE_PATTERNS: Dict[str, List[re.Pattern]] = {
    "sqli_union": [re.compile(r"UNION\s+SELECT", re.I), re.compile(r"sqlmap", re.I)],
    "sqli_blind": [re.compile(r"sleep\(\s*\d+\s*\)", re.I),
                   re.compile(r"blind\s+sqli", re.I)],
    "xss_stored": [re.compile(r"stored\s+xss", re.I), re.compile(r"<script>alert", re.I)],
    "xss_reflected": [re.compile(r"reflected\s+xss", re.I)],
    "ssrf": [re.compile(r"169\.254\.169\.254"), re.compile(r"ssrf\b", re.I),
            re.compile(r"gopher://", re.I)],
    "ssti_jinja": [re.compile(r"\{\{\s*7\s*\*\s*7"), re.compile(r"jinja", re.I)],
    "ssti_twig": [re.compile(r"_self\.env", re.I)],
    "ssti_generic": [re.compile(r"ssti\b", re.I),
                     re.compile(r"server.side template", re.I)],
    "jwt_alg_none": [re.compile(r'"alg"\s*:\s*"none"', re.I)],
    "jwt_weak_secret": [re.compile(r"jwt.{0,20}crack", re.I),
                        re.compile(r"hashcat.{0,20}jwt", re.I),
                        re.compile(r"jwt.{0,20}secret", re.I)],
    "prototype_pollution": [re.compile(r"__proto__", re.I),
                             re.compile(r"prototype\s+pollution", re.I)],
    "command_injection": [re.compile(r"command\s+injection", re.I),
                          re.compile(r";\s*id\s*;"),
                          re.compile(r"\|\s*nc\s+"),
                          re.compile(r"rce\b", re.I)],
    "lfi": [re.compile(r"\.\./\.\./"), re.compile(r"lfi\b", re.I),
            re.compile(r"/etc/passwd")],
    "file_upload_bypass": [re.compile(r"\.phtml"), re.compile(r"\.htaccess"),
                           re.compile(r"double\s+extension", re.I)],
    "deserialization": [re.compile(r"pickle", re.I), re.compile(r"unserialize", re.I),
                        re.compile(r"insecure\s+deserialization", re.I)],
    "xxe": [re.compile(r"<!DOCTYPE.{0,80}<!ENTITY"), re.compile(r"\bxxe\b", re.I)],
    "path_traversal": [re.compile(r"\.\./"), re.compile(r"directory\s+traversal", re.I)],
    "race_condition": [re.compile(r"race\s+condition", re.I),
                        re.compile(r"turbo.?intruder", re.I)],
    "default_creds": [re.compile(r"admin:admin", re.I),
                       re.compile(r"default\s+cred", re.I)],
    "idor": [re.compile(r"\bidor\b", re.I),
             re.compile(r"insecure\s+direct\s+object", re.I)],
    "source_map_leak": [re.compile(r"\.js\.map"), re.compile(r"source\s*maps?", re.I)],
    "git_leak": [re.compile(r"/\.git/"), re.compile(r"git.?dumper", re.I)],
}

TECH_STACK_HINTS: Dict[str, List[str]] = {
    "php": ["php", "laravel", "symfony", "wordpress", ".php"],
    "node": ["node.js", "nodejs", "express", "next.js", " npm "],
    "python": ["flask", "django", "fastapi", "python", " pip "],
    "ruby": ["ruby on rails", "rails"],
    "java": ["spring boot", "java", "tomcat", ".jsp"],
    "go": ["golang", " go "],
    "dotnet": [".net", "asp.net", "iis"],
    "wordpress": ["wordpress", " wp "],
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgres", "postgresql"],
    "mongo": ["mongodb", " mongo "],
    "redis": ["redis"],
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
}


@dataclass
class ExtractedWriteup:
    challenge: str
    category: str
    tech_stack: List[str]
    techniques: List[Dict]
    platform: str
    source_url: str
    raw_excerpt: str


def _http_get(url: str, timeout: int = 20) -> Optional[str]:
    try:
        req = Request(url, headers={"User-Agent": "VIPER/5.0"})
        with urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = resp.read()
                return data.decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError) as exc:
        logger.debug("HTTP GET %s failed: %s", url, exc)
    return None


def infer_category(text: str) -> str:
    text_lower = text.lower()[:20000]
    scores: Dict[str, int] = {}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        scores[cat] = sum(text_lower.count(kw) for kw in keywords)
    best = max(scores, key=scores.get)
    # Prefer "web" over "misc" unless misc dominates by 3x
    if scores["web"] >= scores[best] * 0.6 and scores["web"] >= 3:
        return "web"
    return best if scores[best] else "misc"


def infer_tech_stack(text: str) -> List[str]:
    text_lower = text.lower()[:20000]
    stack: List[str] = []
    for tech, hints in TECH_STACK_HINTS.items():
        if any(h in text_lower for h in hints):
            stack.append(tech)
    return sorted(set(stack))


def extract_techniques(text: str) -> List[Dict]:
    """Find technique markers and infer which 'worked'.

    Heuristic: if a technique keyword appears near 'flag', 'success',
    'worked', or 'got shell', mark worked=True. Otherwise include as
    attempted (worked=False).
    """
    found: Dict[str, Dict] = {}
    # Find positions of success indicators
    success_markers = [
        m.start() for m in re.finditer(
            r"(?i)(got\s+the?\s+flag|flag\s+is|root\.txt|user\.txt|"
            r"successfully|worked|gave\s+us|we\s+have\s+a\s+shell|"
            r"pwned|hashcat\s+cracked)", text)
    ]

    for name, patterns in TECHNIQUE_PATTERNS.items():
        for pat in patterns:
            for m in pat.finditer(text):
                pos = m.start()
                near_success = any(
                    abs(pos - sm) < 500 for sm in success_markers
                )
                entry = found.setdefault(name, {
                    "name": name, "worked": False, "payload": "",
                })
                if near_success:
                    entry["worked"] = True
                    # Capture up to 200 chars around the match as payload
                    ctx = text[max(0, pos-40):pos+160].replace("\n", " ")
                    if not entry["payload"]:
                        entry["payload"] = ctx[:300]
    return list(found.values())


def extract_challenge_name(text: str, source_url: str = "") -> str:
    # Try H1 heading first
    for m in re.finditer(r"^#\s+(.{3,120})$", text[:4000], re.M):
        title = m.group(1).strip(" #\n")
        if len(title) >= 3:
            return title
    # Fall back to filename
    if source_url:
        name = source_url.rstrip("/").rsplit("/", 1)[-1]
        name = re.sub(r"\.(md|txt|html?)$", "", name, flags=re.I)
        if name:
            return name.replace("_", " ").replace("-", " ").strip()
    return "Unknown Challenge"


def parse_writeup(text: str, source_url: str = "",
                  platform: str = "unknown") -> ExtractedWriteup:
    return ExtractedWriteup(
        challenge=extract_challenge_name(text, source_url),
        category=infer_category(text),
        tech_stack=infer_tech_stack(text),
        techniques=extract_techniques(text),
        platform=platform,
        source_url=source_url,
        raw_excerpt=text[:800],
    )


# ── High-level training operations ──────────────────────────────────────────

def train_from_url(url: str, platform: str = "web_writeup") -> Optional[int]:
    """Fetch one writeup URL → parse → ingest. Returns feedback id."""
    text = _http_get(url)
    if not text:
        logger.warning("Skipping %s (fetch failed)", url)
        return None
    extracted = parse_writeup(text, source_url=url, platform=platform)
    return _ingest_extracted(extracted)


def train_from_dir(path: Path, platform: str = "local_writeup") -> int:
    """Walk a directory and ingest every .md/.txt file as a writeup."""
    root = Path(path)
    if not root.exists():
        logger.warning("Directory not found: %s", path)
        return 0
    n = 0
    for f in root.rglob("*.md"):
        text = f.read_text(encoding="utf-8", errors="replace")
        extracted = parse_writeup(text, source_url=str(f), platform=platform)
        if _ingest_extracted(extracted):
            n += 1
    for f in root.rglob("*.txt"):
        text = f.read_text(encoding="utf-8", errors="replace")
        extracted = parse_writeup(text, source_url=str(f), platform=platform)
        if _ingest_extracted(extracted):
            n += 1
    return n


def train_from_github_repo(owner: str, repo: str,
                           branch: str = "master",
                           max_files: int = 50) -> int:
    """Use GitHub's tree API to find writeup markdown files, then ingest."""
    tree_url = (
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/"
        f"{branch}?recursive=1"
    )
    resp = _http_get(tree_url)
    if not resp:
        return 0
    try:
        tree = json.loads(resp)
    except json.JSONDecodeError:
        return 0

    md_files = [
        item["path"] for item in tree.get("tree", [])
        if item.get("type") == "blob" and item.get("path", "").endswith(".md")
    ][:max_files]

    n = 0
    for path in md_files:
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        fb_id = train_from_url(raw, platform=f"github:{owner}/{repo}")
        if fb_id:
            n += 1
    return n


def _ingest_extracted(extracted: ExtractedWriteup) -> Optional[int]:
    from core.ctf_feedback import CTFFeedbackStore, FeedbackEntry
    if not extracted.techniques:
        return None
    store = CTFFeedbackStore()
    entry = FeedbackEntry(
        challenge=extracted.challenge,
        category=extracted.category,
        platform=extracted.platform,
        tech_stack=extracted.tech_stack,
        techniques_tried=extracted.techniques,
        winning_path=_derive_path(extracted.techniques),
        notes=extracted.raw_excerpt,
        writeup_url=extracted.source_url,
    )
    return store.add(entry)


def _derive_path(techniques: List[Dict]) -> str:
    winning = [t["name"] for t in techniques if t.get("worked")]
    if not winning:
        return "no winning technique identified"
    return " → ".join(winning[:5])


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(description="VIPER CTF training pipeline")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_url = sub.add_parser("from-url", help="Train from a single writeup URL")
    s_url.add_argument("url")

    s_dir = sub.add_parser("from-dir", help="Train from a local writeup dir")
    s_dir.add_argument("path")

    s_repo = sub.add_parser("from-github", help="Train from a GitHub repo")
    s_repo.add_argument("owner")
    s_repo.add_argument("repo")
    s_repo.add_argument("--branch", default="master")
    s_repo.add_argument("--max-files", type=int, default=50)

    s_sum = sub.add_parser("summary", help="Show training summary")

    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.cmd == "from-url":
        fb_id = train_from_url(args.url)
        print(f"Ingested feedback id={fb_id}" if fb_id else "Nothing ingested")
        return 0

    if args.cmd == "from-dir":
        n = train_from_dir(Path(args.path))
        print(f"Ingested {n} writeups from {args.path}")
        return 0

    if args.cmd == "from-github":
        n = train_from_github_repo(
            args.owner, args.repo, args.branch, args.max_files,
        )
        print(f"Ingested {n} writeups from GitHub "
              f"{args.owner}/{args.repo}@{args.branch}")
        return 0

    if args.cmd == "summary":
        from core.ctf_feedback import CTFFeedbackStore
        from core.knowledge_base import KnowledgeBase
        store = CTFFeedbackStore()
        kb = KnowledgeBase()
        stats = store.stats()
        print("=== VIPER CTF Training Summary ===")
        print(f"  Feedback entries:     {stats['total_entries']}")
        print(f"  KB entries total:     {kb.count()}")
        print(f"  Techniques tried:     {stats['techniques_tried_total']}")
        print(f"  Wins recorded:        {stats['wins_total']}")
        print(f"  Tech-stack recipes:   {stats['tech_recipes']}")
        print("  By category:")
        for cat, n in sorted(stats["by_category"].items()):
            print(f"    {cat:<15} {n}")
        print("  Top winning techniques:")
        for t in stats["top_winning_techniques"][:10]:
            print(f"    {t['technique']:<25} wins={t['wins']}")
        return 0

    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
