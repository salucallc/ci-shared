"""Shared types and repo helpers for the merge gate.

Severity is a property of the check code, never of a repo's config. A repo's `.gate.toml` can
only WAIVE one named finding, with a reason and an issue link, and every waiver is printed. It
cannot lower a severity, turn a check off or widen an exclusion. That is the estate rule
"config may only narrow" applied to a gate: the code is the gate.

Statuses:
  pass          nothing blocking, nothing to warn about
  warn          only warnings (does not fail the gate)
  fail          at least one blocking finding that is neither waived nor baselined
  cannot-tell   the check could not be evaluated (missing tool, no network, unreadable file).
                Cannot tell is never a pass: it fails the gate with exit code 2.
  n/a           the check does not apply to this repo, with the reason in `notes`
  ci-only       the check runs only in CI (named in notes); a local run does not claim it
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

BLOCK = "block"
WARN = "warn"

PASS, WARN_S, FAIL, CANNOT, NA, CI_ONLY = "pass", "warn", "fail", "cannot-tell", "n/a", "ci-only"

# Paths the gate never reads: dependencies, build output, lockfiles, minified bundles.
# A constant on purpose: a repo cannot add to it. Anything else is waived by name, with a reason.
EXCLUDE_GLOBS = (
    "node_modules/*", "*/node_modules/*", "vendor/*", "*/vendor/*", "third_party/*", "*/third_party/*",
    "dist/*", "*/dist/*", "build/*", "*/build/*", ".venv/*", "*/.venv/*", "venv/*", "*/site-packages/*",
    ".gate-baseline.json", "*.min.js", "*.min.css", "*.map", "package-lock.json", "*/package-lock.json", "pnpm-lock.yaml",
    "*/pnpm-lock.yaml", "yarn.lock", "*/yarn.lock", "poetry.lock", "uv.lock", "Cargo.lock", "*.lock",
)

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".psd", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar", ".whl", ".jar", ".war", ".class", ".so",
    ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".mov", ".avi", ".mkv", ".webm", ".glb", ".gltf",
    ".stl", ".obj", ".fbx", ".blend", ".npy", ".npz", ".pt", ".pth", ".onnx", ".safetensors", ".parquet",
    ".feather", ".h5", ".hdf5", ".sqlite", ".db", ".pkl", ".pickle", ".xlsx", ".xls", ".docx", ".pptx",
    ".svgz", ".icns", ".3mf", ".step", ".stp",
}

PROSE_SUFFIXES = {".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc", ".html", ".htm"}
CODE_SUFFIXES = {
    ".py", ".pyi", ".ipynb", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".go",
    ".rs", ".java", ".kt", ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift", ".sh", ".bash",
    ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf",
    ".env", ".sql", ".tf", ".hcl", ".lua", ".r", ".jl", ".scala", ".vue", ".svelte",
}
SOURCE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".cs", ".c", ".cpp", ".swift", ".sh", ".ps1", ".lua", ".r", ".jl", ".scala", ".vue",
    ".svelte",
}
CODE_NAMES = {"Dockerfile", "Makefile", "Procfile", "crontab", "Justfile"}


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    path: str = ""
    line: int = 0
    key: str = ""  # stable identity for waivers and the baseline (no line numbers in it)
    state: str = "open"  # open | waived | baselined
    note: str = ""

    def ident(self) -> str:
        return self.key or f"{self.path}|{self.message}"

    def where(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        return self.path or "(repo)"


@dataclass
class Result:
    check: str
    title: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    forced: str = ""  # cannot-tell / n/a / ci-only set by the check

    @property
    def status(self) -> str:
        if self.forced in (CANNOT,):
            return CANNOT
        open_block = [f for f in self.findings if f.severity == BLOCK and f.state == "open"]
        if open_block:
            return FAIL
        if self.forced in (NA, CI_ONLY):
            return self.forced
        if any(f.severity == WARN or f.state != "open" for f in self.findings):
            return WARN_S
        return PASS

    def add(self, severity: str, message: str, path: str = "", line: int = 0, key: str = "", note: str = "") -> Finding:
        f = Finding(self.check, severity, message, path, line, key, note=note)
        self.findings.append(f)
        return f

    def cannot(self, why: str) -> "Result":
        self.forced = CANNOT
        self.notes.append(why)
        return self

    def na(self, why: str) -> "Result":
        self.forced = NA
        self.notes.append(why)
        return self


class Repo:
    """A checked-out git repo. Every file list comes from git, never from walking the disk."""

    def __init__(self, root: Path, files: list[str] | None = None, base_ref: str | None = None):
        self.root = Path(root).resolve()
        self._files = files
        self.base_ref = base_ref
        self._cache: dict[str, str | None] = {}
        self.config: dict = {}

    def git(self, *args: str, check: bool = True, binary: bool = False) -> str | bytes:
        out = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True)
        if check and out.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.decode('utf-8', 'replace').strip()}")
        return out.stdout if binary else out.stdout.decode("utf-8", "replace")

    def is_git(self) -> bool:
        try:
            return self.git("rev-parse", "--is-inside-work-tree").strip() == "true"
        except (RuntimeError, OSError):
            return False

    def tracked(self) -> list[str]:
        if self._files is not None:
            return [f for f in self._files if not excluded(f)]
        raw = self.git("ls-files", "-z", binary=True)
        names = [n.decode("utf-8", "replace") for n in raw.split(b"\0") if n]
        return [n for n in names if not excluded(n)]

    def all_tracked(self) -> list[str]:
        raw = self.git("ls-files", "-z", binary=True)
        return [n.decode("utf-8", "replace") for n in raw.split(b"\0") if n]

    def text(self, rel: str) -> str | None:
        """UTF-8 text of a tracked file, or None for binary or unreadable files."""
        if rel in self._cache:
            return self._cache[rel]
        p = self.root / rel
        val: str | None = None
        if Path(rel).suffix.lower() not in BINARY_SUFFIXES and p.is_file():
            try:
                data = p.read_bytes()
            except OSError:
                data = None
            if data is not None and b"\0" not in data[:8192]:
                val = data.decode("utf-8", "replace")
        self._cache[rel] = val
        return val

    def exists(self, rel: str) -> bool:
        return (self.root / rel).is_file()


def excluded(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(rel, g) for g in EXCLUDE_GLOBS)


def kind_of(rel: str) -> str:
    """prose | code | test | other"""
    p = Path(rel)
    low = rel.replace("\\", "/").lower()
    if is_test_path(low):
        return "test"
    if p.suffix.lower() in PROSE_SUFFIXES or p.name.upper().startswith(("README", "LICENSE", "NOTICE", "CHANGELOG")):
        return "prose"
    if p.suffix.lower() in CODE_SUFFIXES or p.name in CODE_NAMES or p.name.startswith(("Dockerfile", ".env")):
        return "code"
    return "other"


def is_test_path(low: str) -> bool:
    parts = low.split("/")
    name = parts[-1]
    return (any(d in ("tests", "test", "__tests__", "spec", "testdata", "fixtures") for d in parts[:-1])
            or name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".test.ts", ".test.tsx",
                                                           ".spec.js", ".spec.ts", ".spec.tsx", "_test.go",
                                                           ".test.mjs", ".test.jsx"))
            or name == "conftest.py")


def fp12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


PLACEHOLDER_RE = re.compile(
    r"""(?ix)^(
        |changeme|change[_-]?me|change[_-]?this|replace[_-]?me|replace[_-]?with.*|todo|tbd|none|null|nil
        |example|example[_-].*|.*[_-]example|sample|dummy|fake|fake[_-].*|test|testing|test[_-]?password
        |password|passwd|pass|secret|your[_-].*|my[_-].*|<[^>]*>|\[[^\]]*\]|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*
        |\{\{.*\}\}|%\(.*\)s|%s|x+|\*+|\.+|0+|123|1234|12345|123456|12345678|abc|abc123|abcdef
        |foo|bar|baz|postgres|root|admin|user|username
        |localdev|local|dev|development|insecure.*|not[_-]?a[_-]?secret.*|redacted|xxx.*|placeholder.*
    )$""")


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    return bool(PLACEHOLDER_RE.match(v))


def shannon(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def env_token() -> str | None:
    """A GitHub token for read-only API calls: GH_TOKEN / GITHUB_TOKEN, else `gh auth token`.
    The value is held in memory only and never printed."""
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def origin_slug(repo: Repo) -> str | None:
    try:
        url = repo.git("remote", "get-url", "origin").strip()
    except RuntimeError:
        return None
    m = re.search(r"github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else None
