"""TST-3 / EXP-1: hardcoded absolute paths and internal hostnames.

Blocking everywhere: a real user's home directory (a Windows Users folder or a POSIX /Users or
/home folder with a non-placeholder name), a WSL drive mount, a tailnet host (*.ts.net), and
anything matching GATE_EXTRA_PATH_PATTERNS. Blocking in code and config: any absolute drive or
home path. In prose, Python docstrings and comments, and tests, a generic example path is a
warning, because docs and path-handling tests legitimately show one.

GATE_EXTRA_PATH_PATTERNS is a ';'-separated list of regexes for an organisation's own internal
paths (its workstation layout, mapped drives). It only ADDS blocking patterns, so setting it can
only make the gate stricter. The patterns live outside this public repo on purpose: a list of
internal paths published in the checker would itself be the exposure the checker exists to stop.
"""
from __future__ import annotations

import ast
import io
import os
import re
import tokenize

from ..core import BLOCK, WARN, Repo, Result, kind_of

DRIVE = re.compile(r"(?<![A-Za-z0-9_%$])([A-Za-z]):(\\\\|\\|/)(?=[A-Za-z0-9_.$~ -])")
WIN_HOME = re.compile(r"(?i)(?<![A-Za-z0-9_])[a-z]:(?:\\\\|\\|/)users(?:\\\\|\\|/)([A-Za-z][\w.-]*)")
UNIX_HOME = re.compile(r"(?<![\w.~$-])/(Users|home)/([A-Za-z_][\w.-]*)")
OS_PATH = re.compile(r"(?i)[a-z]:(\\\\|\\|/)+(windows|program files( \(x86\))?|programdata|system volume information|"
                     r"\$recycle\.bin|users(\\\\|\\|/)+(public|default|all users))\b")
WSL = re.compile(r"(?<![\w.-])/mnt/[a-z]/")
TAILNET = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.ts\.net\b")
PLACEHOLDER_USERS = {"user", "username", "you", "your-name", "yourname", "yourusername", "me", "name", "someone",
                     "example", "runner", "jdoe", "john", "jane", "alice", "bob", "foo", "dev", "ubuntu", "app", "node",
                     "user_name", "default", "public", "all", "shared", "<user>", "%username%", "admin", "vagrant",
                     "ec2-user", "codespace", "vscode", "test", "tester", "demo", "x"}


def extra_patterns() -> list[re.Pattern]:
    raw = os.environ.get("GATE_EXTRA_PATH_PATTERNS", "")
    out = []
    for p in (x.strip() for x in raw.split(";")):
        if p:
            out.append(re.compile(p, re.I))
    return out


def prose_lines_in_python(text: str) -> set[int]:
    """Line numbers that hold a docstring or a comment."""
    lines: set[int] = set()
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                    and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
                lines |= set(range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1))
        for t in tokenize.generate_tokens(io.StringIO(text).readline):
            if t.type == tokenize.COMMENT:
                lines.add(t.start[0])
    except (SyntaxError, tokenize.TokenError, IndentationError, ValueError):
        pass
    return lines


def scan_text(rel: str, text: str, extra: list[re.Pattern] | None = None):
    """Yield (severity, line, message, token)."""
    kind = kind_of(rel)
    prose_lines = prose_lines_in_python(text) if rel.endswith(".py") else set()
    extra = extra if extra is not None else extra_patterns()
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        strict = kind == "code" and n not in prose_lines
        hard = False
        for pat in extra:
            for m in pat.finditer(line):
                hard = True
                yield BLOCK, n, f"EXP-1: internal path {m.group(0)!r} (GATE_EXTRA_PATH_PATTERNS); never ship it", m.group(0)
        for m in WIN_HOME.finditer(line):
            if m.group(1).lower() not in PLACEHOLDER_USERS:
                hard = True
                yield BLOCK, n, f"EXP-1: a real user's home folder ({m.group(0)!r}); never ship it", m.group(0)
        for m in UNIX_HOME.finditer(line):
            if m.group(2).lower() not in PLACEHOLDER_USERS:
                hard = True
                yield BLOCK, n, f"EXP-1: a real user's home folder ('/{m.group(1)}/{m.group(2)}'); never ship it", m.group(0)
            elif strict:
                hard = True
                yield BLOCK, n, f"TST-3: hardcoded home path '/{m.group(1)}/{m.group(2)}'", m.group(0)
        for m in TAILNET.finditer(line):
            yield BLOCK, n, f"EXP-1: tailnet host {m.group(0)!r}; internal hostnames never ship", m.group(0)
        if hard:
            continue
        for m in DRIVE.finditer(line):
            if "://" in line[m.start():m.start() + 4]:
                continue
            tok = line[m.start():m.start() + 24]
            if OS_PATH.match(line[m.start():]):
                # C:\Windows\System32, C:\Program Files: an OS location (detection rules, docs), nobody's machine
                yield WARN, n, f"TST-3: well-known OS path {tok.strip()!r} (fine as data; never as a place to read or write)", tok
                continue
            yield (BLOCK if strict else WARN), n, f"TST-3: hardcoded Windows path {tok.strip()!r}", tok
        for m in WSL.finditer(line):
            yield BLOCK, n, f"EXP-1: WSL drive path {m.group(0)!r}", m.group(0)


def run(repo: Repo, opts) -> Result:
    r = Result("paths", "Hardcoded absolute paths and internal hostnames")
    files = opts.files if getattr(opts, "files", None) else repo.tracked()
    extra = extra_patterns()
    if extra:
        r.notes.append(f"{len(extra)} extra internal-path pattern(s) from GATE_EXTRA_PATH_PATTERNS")
    private = getattr(opts, "visibility", None) == "private"
    if private:
        r.notes.append("private repo: EXP-1 (exposure) in prose is a warning; hardcoded paths in code still block")
    for rel in files:
        text = repo.text(rel)
        if text is None:
            continue
        for sev, n, msg, tok in scan_text(rel, text, extra):
            if private and msg.startswith("EXP-1") and kind_of(rel) != "code":
                sev = WARN  # an internal path in a private KB or runbook is not an exposure
            r.add(sev, msg + " (use a path relative to the file, an env var or a config value)", rel, n,
                  key=f"{rel}|{tok.strip()}")
    return r
