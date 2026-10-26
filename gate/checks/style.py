"""STY-1 / STY-3: no em-dashes in prose; container shell and cron files are LF and LF-pinned.

STY-1 covers every prose file (README, llms.txt, AGENTS.md, docs/, CHANGELOG, HTML), not only
the three repo-docs.yml checks; merge-gate.yml calls repo-docs.yml with check-em-dash off so the
check runs once. The single sanctioned exception is the "Saluca Labs" sign-off, as a bare line or
as an HTML element whose whole text content is the sign-off and nothing else.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..core import BLOCK, PROSE_SUFFIXES, Repo, Result

EM = "\u2014"
# The sanctioned sign-off, matched against TEXT, not against source. Prose here includes HTML
# (`PROSE_SUFFIXES`), where the sign-off is its own element - `<p>\u2014 Saluca Labs</p>`, measured in
# saluca-campus `docs/_PDF/SALUCA-LABS-CAMPUS-DESIGN.html:1044` on 2026-10-26 - so the old
# bare-line-only pattern called a correctly signed-off published page an em-dash violation. The
# line is reduced to its text content and must then be nothing but the sign-off; an em-dash
# anywhere else on the line still fails, which is the point of the check.
SIGNOFF = re.compile(r"^\s*[*_]*\s*\u2014\s*Saluca Labs\s*[*_]*\s*$")
TAG = re.compile(r"<[^>]*>")


def is_signoff(line: str) -> bool:
    """True only when the whole line is the sanctioned sign-off, as written or stripped of markup."""
    return bool(SIGNOFF.match(line) or SIGNOFF.match(TAG.sub("", line)))
LF_FILES = re.compile(r"(?i)(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|[^/]*\.sh|[^/]*\.bash|crontab[^/]*|[^/]*\.cron"
                      r"|[^/]*entrypoint[^/]*|cron\.d/[^/]+)$")


def is_prose(rel: str) -> bool:
    p = PurePosixPath(rel)
    return p.suffix.lower() in PROSE_SUFFIXES or p.name in ("llms.txt", "llms-full.txt", "AGENTS.md", "CITATION.cff")


def run(repo: Repo, opts) -> Result:
    r = Result("style", "Estate style: no em-dashes in prose; LF for container shell and cron files")
    files = opts.files if getattr(opts, "files", None) else repo.tracked()
    for rel in files:
        if not is_prose(rel):
            continue
        text = repo.text(rel)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if EM in line and not is_signoff(line):
                r.add(BLOCK, "STY-1: em-dash in prose (house style: a hyphen in plain docs; in published prose "
                      "an ellipsis or a comma)", rel, n, key=f"{rel}|em|{line.strip()[:80]}")
    lf = [f for f in files if LF_FILES.search(f)]
    if lf:
        try:
            eol = repo.git("ls-files", "--eol", "--", *lf)
        except RuntimeError as e:
            return r.cannot(f"git ls-files --eol failed: {e}")
        for line in eol.splitlines():
            meta, sep, path = line.partition("\t")  # "i/lf    w/lf    attr/text eol=lf      \tpath"
            if not sep:
                continue
            index_eol = meta.split()[0] if meta.split() else ""
            attr = meta.partition("attr/")[2]
            if index_eol in ("i/crlf", "i/mixed"):
                r.add(BLOCK, f"STY-3: container shell/cron file stored with CRLF ({index_eol}); a CR breaks "
                      "the shebang and cron parsing", path, key=f"{path}|crlf")
            if "eol=lf" not in attr:
                r.add(BLOCK, "STY-3: not LF-pinned; add a .gitattributes rule such as '*.sh text eol=lf' "
                      "(or '* text=auto eol=lf')", path, key=f"{path}|unpinned")
    return r
