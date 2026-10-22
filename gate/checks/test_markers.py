"""TST-1 / TST-2: a repo with code has tests; every skip and xfail carries a reason AND an issue
link, there are at most MAX_MARKERS of them, and nothing forces a whole module or session to
xfail (Tony's review, 2026-10-22: 40 tests forced to xfail).
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..core import BLOCK, SOURCE_SUFFIXES, WARN, Repo, Result, is_test_path
from .security import code_view

MAX_MARKERS = 10  # a constant: a repo cannot raise it

ISSUE = re.compile(r"(https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+/(?:issues|pull)/\d+|\bgh-\d+\b|\b(?:issue|issues|bug|tracked in)\s*#\d+)", re.I)

PY_MARKERS = re.compile(
    r"(?P<m>@pytest\.mark\.(?:xfail|skip|skipif)\b|pytest\.(?:skip|xfail)\s*\(|@unittest\.(?:skip|skipIf|skipUnless|expectedFailure)\b"
    r"|self\.skipTest\s*\(|raise\s+(?:unittest\.)?SkipTest\s*\()")
PY_BULK = re.compile(r"(?P<m>^\s*pytestmark\s*=.*pytest\.mark\.(?:xfail|skip|skipif)|add_marker\s*\(\s*pytest\.mark\.(?:xfail|skip|skipif))", re.M)
JS_MARKERS = re.compile(r"(?P<m>\b(?:it|test|describe|context|suite)\.(?:skip|todo|failing|fixme)\b|\bx(?:it|describe|test)\s*\(|\.skip\.each\b)")
REASON_KW = re.compile(r"reason\s*=\s*(['\"]).{6,}?\1|reason\s*=\s*[A-Za-z_]", re.S)


def span(text: str, start: int) -> str:
    """The marker text up to its balanced closing paren (or end of line when there is none)."""
    i = text.find("(", start)
    eol = text.find("\n", start)
    if i == -1 or (eol != -1 and i > eol and not text[start:i].strip().endswith(("xfail", "skip", "skipif"))):
        return text[start: eol if eol != -1 else len(text)]
    depth = 0
    for j in range(i, min(len(text), i + 2000)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    return text[start: start + 400]


def context_before(text: str, start: int, lines: int = 3) -> str:
    head = text[:start].splitlines()[-lines:]
    return "\n".join(h for h in head if h.strip().startswith(("#", "//", "*", "/*")))


def judge(rel: str, text: str):
    """Yield (severity, line, message, kind) for one file."""
    suffix = PurePosixPath(rel).suffix.lower()
    if suffix == ".py":
        view = code_view(rel, text)  # same offsets; markers quoted inside strings (fixtures) are not markers
        for m in PY_BULK.finditer(view):
            ln = text.count("\n", 0, m.start()) + 1
            seg = span(text, m.start("m")) if "(" in m.group(0) else text[m.start():text.find("\n", m.start())]
            if "xfail" in m.group(0):
                yield BLOCK, ln, ("TST-2: bulk xfail (pytestmark or add_marker) forces every test in scope to "
                                  "'expected failure', so the suite cannot fail; mark each test with its own reason and issue"), "bulk"
            elif not (REASON_KW.search(seg) and (ISSUE.search(seg) or ISSUE.search(context_before(text, m.start())))):
                yield BLOCK, ln, "TST-2: bulk skip without a reason and an issue link", "bulk"
            else:
                yield WARN, ln, "TST-2: bulk skip (reason and issue present); check it is still needed", "bulk"
        for m in PY_MARKERS.finditer(view):
            ln = text.count("\n", 0, m.start()) + 1
            seg = span(text, m.start("m"))
            has_reason = bool(REASON_KW.search(seg) or re.search(r"\(\s*(['\"]).{6,}?\1", seg, re.S))
            if "expectedFailure" in seg:
                has_reason = False
            has_issue = bool(ISSUE.search(seg) or ISSUE.search(context_before(text, m.start())))
            yield from _verdict(ln, has_reason, has_issue, m.group("m"))
    elif suffix in SOURCE_SUFFIXES:
        for m in JS_MARKERS.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            line = text.splitlines()[ln - 1] if text.splitlines() else ""
            ctx = context_before(text, m.start()) + "\n" + line
            has_issue = bool(ISSUE.search(ctx))
            has_reason = bool(re.search(r"(//|/\*|\*)\s*\S.{6,}", ctx))
            yield from _verdict(ln, has_reason, has_issue, m.group("m"))


def _verdict(ln: int, has_reason: bool, has_issue: bool, marker: str):
    missing = [w for w, ok in (("a reason", has_reason), ("an issue link", has_issue)) if not ok]
    if missing:
        yield BLOCK, ln, f"TST-2: {marker.strip()} without {' and '.join(missing)}", "marker"
    else:
        yield "count", ln, marker.strip(), "marker"


def has_code(files: list[str]) -> bool:
    return any(PurePosixPath(f).suffix.lower() in SOURCE_SUFFIXES and not is_test_path(f.lower())
               and not f.startswith((".github/", "scripts/", "tools/")) for f in files)


def has_tests(files: list[str]) -> bool:
    return any(is_test_path(f.lower()) and PurePosixPath(f).suffix.lower() in SOURCE_SUFFIXES for f in files)


def run(repo: Repo, opts) -> Result:
    r = Result("test-markers", "Tests exist; skip/xfail markers carry a reason and an issue; cap on markers")
    files = repo.tracked()
    if has_code(files) and not has_tests(files):
        r.add(BLOCK, "TST-1: the repo has source code and no test files; CI cannot show the code works", key="no-tests")
    count = 0
    for rel in files:
        if PurePosixPath(rel).suffix.lower() not in SOURCE_SUFFIXES:
            continue
        text = repo.text(rel)
        if not text or not re.search(r"skip|xfail|expectedFailure|todo|failing|fixme|\bx(it|describe|test)\b", text):
            continue
        lines = text.splitlines()
        for sev, ln, msg, _kind in judge(rel, text):
            count += 1
            if sev != "count":
                src = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
                r.add(sev, msg, rel, ln, key=f"{rel}|{msg}|{src}")
    r.notes.append(f"{count} skip/xfail marker(s); cap {MAX_MARKERS}")
    if count > MAX_MARKERS:
        r.add(BLOCK, f"TST-2: {count} skip/xfail markers, over the cap of {MAX_MARKERS}; fix or delete tests "
              "rather than parking them", key="marker-cap")
    return r
