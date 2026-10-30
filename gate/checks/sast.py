"""SEC-10: generic SAST, bandit (Python) and semgrep rulepacks, run by the gate itself.

Until 2026-10-30 these ran ONLY in CI, through reusable-sast-python.yml (`bandit -r .`) and
reusable-semgrep.yml (`semgrep ... --error .`), which scan the whole tree and never read
`.gate-baseline.json`. A local `gate run` listed SAST as ci-only and could be green while CI was
red, and `gate baseline` could not record SAST debt. tiresias-zt adopted the gate on a green local
run with 989 baseline entries, and main went red on 45 pre-existing findings. Now the same check
code runs here and in CI (merge-gate.yml runs `python -m gate run --only bandit` and
`--only semgrep`), so the two cannot disagree, and SAST findings are baselined like any other.

The tool, its version, its flags and its rulesets are constants below. A repo cannot change
them (config may only narrow). A tool that is missing, is the wrong version, cannot reach the
semgrep registry, or exits with an error is cannot tell (exit 2), never a pass.

Fingerprints carry no line number: a finding's key is the tool, the rule, the path and a hash of
the flagged source text with whitespace collapsed. Moving the code keeps its baseline entry;
editing the flagged lines makes it a new finding, which blocks (touched debt is new debt).

Files scanned: the tracked files the gate reads (`Repo.tracked()`, so the constant exclusions
apply). Untracked files never count, so a local run and a CI checkout see the same set, and the
gate's own checkout in CI (`.merge-gate/`) is not scanned as if it were the repo.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from ..core import BLOCK, WARN, Repo, Result

# The pins. merge-gate.yml installs exactly these (it reads them from this file), and a unit test
# holds the defaults of reusable-sast-python.yml and reusable-semgrep.yml to the same values.
BANDIT_VERSION = "1.9.4"
BANDIT_SEVERITY = "medium"
BANDIT_CONFIDENCE = "medium"
SEMGREP_VERSION = "1.160.0"
SEMGREP_CONFIGS = ("p/owasp-top-ten", "p/python", "p/secrets", "p/ci")
SEMGREP_SEVERITY = "ERROR"
SEMGREP_IMAGE = f"semgrep/semgrep:{SEMGREP_VERSION}"

CACHE = Path.home() / ".cache" / "saluca-gate"
BANDIT_SUFFIXES = (".py", ".pyw")  # what `bandit -r` picks up
BANDIT_CHUNK = 150  # files per bandit call: keeps a Windows command line well under its limit
_RANK = {"low": 0, "medium": 1, "high": 2}


def _bin(venv_dir: Path, name: str) -> Path:
    return venv_dir / ("Scripts" if platform.system() == "Windows" else "bin") / (
        name + (".exe" if platform.system() == "Windows" else ""))


def _version(cmd: list[str], pattern: str) -> str:
    try:
        out = subprocess.run(cmd + ["--version"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(pattern, out.stdout + out.stderr)
    return m.group(1) if m else ""


def bandit_command() -> tuple[list[str] | None, str]:
    """The pinned bandit as a command prefix, or (None, why). Candidates: GATE_BANDIT, the gate
    cache venv (`python -m gate bootstrap`), then PATH. A wrong version is not a candidate."""
    cands = []
    if os.environ.get("GATE_BANDIT"):
        cands.append(os.environ["GATE_BANDIT"])
    cands.append(str(_bin(CACHE / "venv", "bandit")))
    which = shutil.which("bandit")
    if which:
        cands.append(which)
    seen = []
    for c in cands:
        if not Path(c).is_file():
            continue
        v = _version([c], r"(?i)bandit\S*\s+(\d+\.\d+\.\d+)")  # it prints its argv[0]: "bandit.EXE 1.9.4"
        if v == BANDIT_VERSION:
            return [c], ""
        seen.append(f"{c} is {v or 'unknown'}")
    why = f"bandit {BANDIT_VERSION} not found" + (f" ({'; '.join(seen)})" if seen else "")
    return None, why + "; run `python -m gate bootstrap` (installs it into a venv under the gate cache) or set GATE_BANDIT"


def semgrep_command(root: Path) -> tuple[list[str] | None, str]:
    """The pinned semgrep as a command prefix run from `root`, or (None, why). Candidates:
    GATE_SEMGREP, the gate cache venv, PATH, then the official image under Docker (semgrep has no
    native Windows build; this is how the 1.160.0 runs on Windows hosts are reproduced)."""
    cands = []
    if os.environ.get("GATE_SEMGREP"):
        cands.append(os.environ["GATE_SEMGREP"])
    cands.append(str(_bin(CACHE / f"semgrep-{SEMGREP_VERSION}", "semgrep")))
    which = shutil.which("semgrep")
    if which:
        cands.append(which)
    seen = []
    for c in cands:
        if not Path(c).is_file():
            continue
        v = _version([c], r"(\d+\.\d+\.\d+)")
        if v == SEMGREP_VERSION:
            return [c], ""
        seen.append(f"{c} is {v or 'unknown'}")
    docker = shutil.which("docker")
    if docker and not os.environ.get("GATE_SEMGREP"):
        cmd = [docker, "run", "--rm", "-v", f"{root}:/src", "-w", "/src", SEMGREP_IMAGE, "semgrep"]
        v = _version(cmd, r"(\d+\.\d+\.\d+)")
        if v == SEMGREP_VERSION:
            return cmd, ""
        seen.append(f"docker {SEMGREP_IMAGE} did not run ({v or 'no version printed; is the daemon up?'})")
    why = f"semgrep {SEMGREP_VERSION} not found" + (f" ({'; '.join(seen)})" if seen else "")
    return None, why + ("; run `python -m gate bootstrap`, install semgrep==" + SEMGREP_VERSION +
                        f", set GATE_SEMGREP, or start Docker for {SEMGREP_IMAGE}")


def _norm(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def snippet_hash(repo: Repo, rel: str, first: int, last: int) -> str:
    """A hash of the flagged lines, whitespace collapsed: the line-number-free part of the key."""
    lines = (repo.text(rel) or "").splitlines()
    first, last = max(first, 1), max(last, first)
    body = "\n".join(" ".join(ln.split()) for ln in lines[first - 1:last] if ln.strip())
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def run_bandit(repo: Repo, opts) -> Result:
    r = Result("bandit", f"Generic SAST: bandit {BANDIT_VERSION} (severity and confidence >= {BANDIT_SEVERITY})")
    files = [f for f in repo.tracked() if f.lower().endswith(BANDIT_SUFFIXES)]
    if not files:
        return r.na("no tracked Python files")
    cmd, why = bandit_command()
    if not cmd:
        return r.cannot(why)
    unparsed = 0
    for i in range(0, len(files), BANDIT_CHUNK):
        chunk = files[i:i + BANDIT_CHUNK]
        try:
            out = subprocess.run(cmd + ["-r", *chunk, "-f", "json", "-q", "--severity-level", BANDIT_SEVERITY,
                                        "--confidence-level", BANDIT_CONFIDENCE], cwd=repo.root, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=1800)
        except (OSError, subprocess.TimeoutExpired) as e:
            return r.cannot(f"bandit did not run: {type(e).__name__}: {e}")
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            return r.cannot(f"bandit exited {out.returncode} without a JSON report: {out.stderr.strip()[-300:]}")
        if out.returncode not in (0, 1):
            return r.cannot(f"bandit exited {out.returncode}: {out.stderr.strip()[-300:]}")
        for e in data.get("errors", []):
            unparsed += 1
            rel = _norm(str(e.get("filename", "")))
            r.add(WARN, f"SEC-10: bandit could not scan this file ({e.get('reason', 'no reason given')}); "
                  "CI's bandit skips it the same way", rel, key=f"bandit-error|{rel}")
        for f in data.get("results", []):
            sev, conf = str(f.get("issue_severity", "")).lower(), str(f.get("issue_confidence", "")).lower()
            if _RANK.get(sev, -1) < _RANK[BANDIT_SEVERITY] or _RANK.get(conf, -1) < _RANK[BANDIT_CONFIDENCE]:
                continue
            rel = _norm(str(f.get("filename", "")))
            rng = f.get("line_range") or [f.get("line_number", 0)]
            line = int(f.get("line_number") or rng[0] or 0)
            tid = f.get("test_id", "?")
            h = snippet_hash(repo, rel, int(min(rng)), int(max(rng)))
            r.add(BLOCK, f"SEC-10: bandit {tid} {f.get('test_name', '')} ({sev}/{conf}): {f.get('issue_text', '').strip()}",
                  rel, line, key=f"bandit|{tid}|{rel}|{h}")
    r.notes.append(f"bandit {BANDIT_VERSION} over {len(files)} tracked Python file(s); `# nosec <id>` with a reason "
                   "suppresses one line" + (f"; {unparsed} file(s) could not be parsed" if unparsed else ""))
    return r


def run_semgrep(repo: Repo, opts) -> Result:
    r = Result("semgrep", f"Generic SAST: semgrep {SEMGREP_VERSION} ({', '.join(SEMGREP_CONFIGS)}; {SEMGREP_SEVERITY})")
    tracked = set(repo.tracked())
    if not tracked:
        return r.na("no tracked files")
    if getattr(opts, "offline", False):
        return r.cannot("--offline: semgrep fetches its rulepacks from the registry")
    cmd, why = semgrep_command(repo.root)
    if not cmd:
        return r.cannot(why)
    args = []
    for c in SEMGREP_CONFIGS:
        args += ["--config", c]
    try:
        out = subprocess.run(cmd + args + [f"--severity={SEMGREP_SEVERITY}", "--error", "--json", "--quiet",
                                           "--disable-version-check", "."], cwd=repo.root, capture_output=True,
                             text=True, encoding="utf-8", errors="replace", timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as e:
        return r.cannot(f"semgrep did not run: {type(e).__name__}: {e}")
    if out.returncode not in (0, 1):
        return r.cannot(f"semgrep exited {out.returncode} (0 clean, 1 findings; anything else is an error): "
                        f"{(out.stderr or out.stdout).strip()[-400:]}")
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return r.cannot(f"semgrep exited {out.returncode} without a JSON report: {out.stderr.strip()[-300:]}")
    if not isinstance(data, dict) or "results" not in data:
        return r.cannot("semgrep printed JSON with no results list")
    outside = 0
    for f in data["results"]:
        rel = _norm(str(f.get("path", "")))
        if rel not in tracked:
            outside += 1  # untracked or excluded: neither a local run nor CI judges it
            continue
        start = int((f.get("start") or {}).get("line") or 0)
        end = int((f.get("end") or {}).get("line") or start)
        rule = str(f.get("check_id", "?"))
        msg = " ".join(str((f.get("extra") or {}).get("message", "")).split())
        h = snippet_hash(repo, rel, start, end)
        r.add(BLOCK, f"SEC-10: semgrep {rule}: {msg[:300]}", rel, start, key=f"semgrep|{rule}|{rel}|{h}")
    errs = [e for e in data.get("errors", []) if isinstance(e, dict)]
    r.notes.append(f"semgrep {SEMGREP_VERSION} via {'docker ' + SEMGREP_IMAGE if 'docker' in Path(cmd[0]).name else cmd[0]}; "
                   "`# nosemgrep: <rule-id>` with a reason suppresses one line"
                   + (f"; {outside} result(s) in untracked or excluded files ignored" if outside else "")
                   + (f"; {len(errs)} non-fatal semgrep error(s) (parse or timeout)" if errs else ""))
    return r
