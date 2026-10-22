"""DOC-1: the repo-docs standard (README skeleton, llms.txt shape), public repos only.

The check is NOT reimplemented here. It is the inline Python block of
.github/workflows/repo-docs.yml, extracted at run time (as saluca-handoff's run_local.py does),
so the local gate and CI cannot drift. Em-dashes are left to the style check, and gitleaks to
the secrets check, so each runs once.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

from ..core import BLOCK, Repo, Result

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "repo-docs.yml"
if not WORKFLOW.is_file():  # installed from the wheel (pre-commit): pyproject ships the same file
    try:
        from importlib.resources import files as _files
        WORKFLOW = Path(str(_files("gate_workflows") / "repo-docs.yml"))
    except (ModuleNotFoundError, TypeError):
        pass
DEFAULT_HEADINGS = "Status,Install,Quickstart,Usage,Citation,License,Links"


def run(repo: Repo, opts) -> Result:
    r = Result("docs", "Repo docs standard: README skeleton and llms.txt (public repos)")
    vis = getattr(opts, "visibility", None) or repo.config.get("gate", {}).get("visibility")
    if vis == "private":
        return r.na("private repo: the docs standard applies to public repos")
    if not WORKFLOW.is_file():
        return r.cannot(f"{WORKFLOW} not found; the docs check is extracted from it")
    m = re.search(r"<<'PY'\n(.*?)\n\s*PY\n", WORKFLOW.read_text(encoding="utf-8"), re.S)
    if not m:
        return r.cannot("could not find the inline check in repo-docs.yml")
    headings = repo.config.get("docs", {}).get("required-headings", DEFAULT_HEADINGS)
    if set(h.strip() for h in headings.split(",")) - set(DEFAULT_HEADINGS.split(",")):
        return r.cannot("docs.required-headings may only narrow the default list")
    env = dict(os.environ, REQUIRED=headings, CHECK_DASH="false", PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, "-I", "-c", textwrap.dedent(m.group(1))], cwd=repo.root, env=env,
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    for line in out.stdout.splitlines():
        if line.startswith("::error::"):
            msg = line[len("::error::"):]
            r.add(BLOCK, f"DOC-1: {msg}", msg.split(":")[0] if msg.split(":")[0].endswith((".md", ".txt")) else "",
                  key=f"doc|{msg}")
    if out.returncode not in (0, 1):
        r.cannot(f"docs check exited {out.returncode}: {out.stderr.strip()[-300:]}")
    elif out.returncode == 1 and not r.findings:
        r.cannot("docs check failed without an ::error:: line")
    return r
