"""DEP-1..DEP-3: dependencies are pinned and audited.

DEP-1  a Node project with dependencies has a lockfile (block): without one, `npm ci` cannot run
       and `npm audit` has nothing to read. In a workspace (one root `package.json` declaring
       `workspaces`, one lockfile at that root) a member is covered by the root's lockfile: a
       second lockfile inside a member is the bug, not the fix.
DEP-2  Python requirements are pinned (`==`, or a lockfile: uv.lock, poetry.lock, pdm.lock);
       an unpinned line is a warning.
DEP-3  with --audit (the default in CI and before a push): pip-audit over each requirements file
       and npm audit over each lockfile. A known vulnerability with a fixed version is blocking;
       one with no fix yet is a warning. A missing auditor in audit mode is cannot-tell.
"""
from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

from ..core import BLOCK, WARN, Repo, Result

REQ_FILE = re.compile(r"(^|/)[\w.-]*requirements[\w.-]*\.txt$")
CACHE_PY = Path.home() / ".cache" / "saluca-gate" / "venv" / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")


def pip_audit_cmd() -> list[str] | None:
    if shutil.which("pip-audit"):
        return ["pip-audit"]
    if CACHE_PY.is_file():
        return [str(CACHE_PY), "-m", "pip_audit"]
    return None


NODE_LOCKS = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")


def _seg_match(pattern: str, parts: list[str]) -> bool:
    """Does one workspace glob match this path, segment by segment?

    `*` matches within one segment and never across `/`, `**` matches zero or more whole segments.
    A plain `fnmatch` would let `packages/*` swallow `packages/a/b`, which npm does not: that would
    report a member as covered when it is not, and a false pass here hides an unpinned repo.
    """
    if pattern == "**" or pattern.startswith("**/"):
        rest = "" if pattern == "**" else pattern[3:]
        return any(_seg_match(rest, parts[i:]) for i in range(len(parts) + 1))
    if not parts:
        return not pattern
    if not pattern:
        return False
    head, _, tail = pattern.partition("/")
    if not head:
        return False
    return re.fullmatch(re.escape(head).replace(r"\*", "[^/]*").replace(r"\?", "[^/]"), parts[0]) is not None \
        and _seg_match(tail, parts[1:])


def _workspace_patterns(data: dict) -> list[str] | None:
    """The `workspaces` globs a package.json declares, or None when it declares none.

    `workspaces` is a list, or an object whose `packages` key is the list (Yarn Berry). Anything
    else is a shape this check does not understand, and the caller must not read that as "covered".
    """
    ws = data.get("workspaces")
    if ws is None:
        return None
    if isinstance(ws, dict):
        ws = ws.get("packages")
        if ws is None:
            return []
    if isinstance(ws, str):
        ws = [ws]
    if not isinstance(ws, list) or not all(isinstance(p, str) for p in ws):
        return []
    return [p.strip().strip("/") for p in ws if p.strip()]


def _workspace_lock(pj: str, repo: Repo, names: set[str]) -> str:
    """The root lockfile of the workspace `pj` is a member of, or ''.

    Walks up from the member to the repo root looking for an ancestor `package.json` that declares
    `workspaces` covering this path. Both the declaration and the coverage are required, so a
    package.json merely sitting above a member proves nothing.
    """
    parts = PurePosixPath(pj).parts[:-1]
    for cut in range(len(parts) - 1, -1, -1):
        parent_dir = "/".join(parts[:cut])
        parent_pj = (parent_dir + "/" if parent_dir else "") + "package.json"
        if parent_pj == pj or (parent_pj not in names and not (repo.root / parent_pj).is_file()):
            continue
        try:
            parent = json.loads(repo.text(parent_pj) or "{}")
        except json.JSONDecodeError:
            continue
        globs = _workspace_patterns(parent)
        if not globs:
            continue
        rel = parts[cut:]
        if not any(_seg_match(g, rel) for g in globs):
            continue
        root = parent_dir + "/" if parent_dir else ""
        lock = next((root + n for n in NODE_LOCKS if root + n in names or (repo.root / (root + n)).is_file()), None)
        return lock or ""
    return ""


def run(repo: Repo, opts) -> Result:
    r = Result("deps", "Dependencies pinned (lockfiles) and audited (pip-audit, npm audit)")
    files = repo.tracked()
    names = set(files)
    pkgs = [f for f in files if PurePosixPath(f).name == "package.json"]
    # Any basename containing "requirements" and ending in .txt: requirements.txt, requirements-dev.txt,
    # and also ci-requirements.txt or dev-requirements.txt. The old pattern demanded a basename that
    # STARTS with "requirements", so life-os's .github/ci-requirements.txt (the whole CI toolchain, 41
    # open advisories) was never audited and the check read n/a. Found 2026-11-04.
    reqs = [f for f in files if REQ_FILE.search(f)]
    pyprojects = [f for f in files if PurePosixPath(f).name == "pyproject.toml"]
    if not (pkgs or reqs or pyprojects):
        return r.na("no package.json, *requirements*.txt or pyproject.toml")
    node_locks = []
    for pj in pkgs:
        d = str(PurePosixPath(pj).parent)
        d = "" if d == "." else d + "/"
        try:
            data = json.loads(repo.text(pj) or "{}")
        except json.JSONDecodeError:
            r.add(BLOCK, "DEP-1: package.json is not valid JSON", pj, key=f"badjson|{pj}")
            continue
        has_deps = bool(data.get("dependencies") or data.get("devDependencies"))
        lock = next((d + n for n in NODE_LOCKS if d + n in names or (repo.root / (d + n)).is_file()), None)
        if has_deps and not lock:
            # A workspace member has no lockfile of its own by design: the root's covers it.
            lock = _workspace_lock(pj, repo, names)
        if has_deps and not lock:
            r.add(BLOCK, "DEP-1: Node dependencies with no lockfile; installs are not reproducible and cannot be audited",
                  pj, key=f"nolock|{pj}")
        elif lock and lock not in node_locks:
            node_locks.append(lock)
    for req in reqs:
        for n, line in enumerate((repo.text(req) or "").splitlines(), 1):
            s = line.split("#")[0].strip()
            if not s or s.startswith(("-", "git+", "http", ".", "/")):
                continue
            if not re.search(r"===?|@\s*(https?|file)://|--hash", s):
                r.add(WARN, f"DEP-2: unpinned requirement {s!r}", req, n, key=f"{req}|{s}")
    for pp in pyprojects:
        d = str(PurePosixPath(pp).parent)
        d = "" if d == "." else d + "/"
        text = repo.text(pp) or ""
        has_deps = re.search(r"(?m)^dependencies\s*=\s*\[\s*\S", text) or "[tool.poetry.dependencies]" in text
        locked = any(d + n in names for n in ("uv.lock", "poetry.lock", "pdm.lock", "requirements.txt", "requirements.lock"))
        if has_deps and not locked:
            r.add(WARN, "DEP-2: pyproject dependencies with no lockfile (uv.lock, poetry.lock, pdm.lock or pinned requirements)",
                  pp, key=f"nolock|{pp}")
    if not getattr(opts, "audit", True):
        r.notes.append("audit skipped (--no-audit); this is not a push verdict")
        return r
    if reqs:
        cmd = pip_audit_cmd()
        if not cmd:
            return r.cannot("pip-audit not found; run `python -m gate bootstrap` (installs it into a venv under the gate cache)")
        for req in reqs:
            # A hash-pinned file names the exact wheels, often for another platform (an image's
            # linux/amd64 wheels). Letting pip resolve it on Windows fails on the hashes, so the
            # file is audited as written (--disable-pip), which is also what it means.
            hashed = "--hash" in (repo.text(req) or "")
            out = subprocess.run(cmd + ["-r", str(repo.root / req), "--format", "json", "--progress-spinner", "off"]
                                 + (["--disable-pip"] if hashed else []),
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
            if not out.stdout.strip():
                # pip-audit exits 1 both for "vulnerabilities found" and for "could not install or
                # resolve"; only the first prints a report. Reading an empty report as "no
                # dependencies" passed tiresias-report's image requirements on every Windows run
                # while CI found PYSEC-2026-3552 in them (2026-11-08). Cannot tell, never a pass.
                r.cannot(f"pip-audit on {req} exited {out.returncode} with no report: {out.stderr.strip()[-300:]}")
                continue
            try:
                data = json.loads(out.stdout)
            except json.JSONDecodeError:
                r.cannot(f"pip-audit on {req} exited {out.returncode}: {out.stderr.strip()[-300:]}")
                continue
            deps = data.get("dependencies", data if isinstance(data, list) else [])
            for dep in deps:
                for v in dep.get("vulns", []):
                    fixed = v.get("fix_versions") or []
                    sev = BLOCK if fixed else WARN
                    r.add(sev, f"DEP-3: {dep.get('name')} {dep.get('version')} has {v.get('id')}"
                          f"{' (fixed in ' + ', '.join(fixed) + ')' if fixed else ' (no fix released)'}", req,
                          key=f"{req}|{dep.get('name')}|{v.get('id')}")
            if out.returncode not in (0, 1) and not deps:
                r.cannot(f"pip-audit on {req} exited {out.returncode}: {out.stderr.strip()[-300:]}")
    for lock in node_locks:
        if not lock.endswith("package-lock.json"):
            r.notes.append(f"{lock}: only npm lockfiles are audited here; CI's node workflow installs and can audit others")
            continue
        npm = shutil.which("npm") or shutil.which("npm.cmd")
        if not npm:
            return r.cannot("npm not found, so npm audit cannot run")
        cwd = repo.root / (str(PurePosixPath(lock).parent))
        out = subprocess.run([npm, "audit", "--package-lock-only", "--omit=dev", "--json"], cwd=cwd, capture_output=True,
                             text=True, encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            r.cannot(f"npm audit in {lock} printed no JSON: {out.stderr.strip()[-300:]}")
            continue
        if "error" in data and not data.get("vulnerabilities"):
            r.cannot(f"npm audit in {lock}: {str(data['error'])[:200]}")
            continue
        for name, v in (data.get("vulnerabilities") or {}).items():
            sev = v.get("severity", "")
            fix = v.get("fixAvailable")
            r.add(BLOCK if sev in ("high", "critical") and fix else WARN,
                  f"DEP-3: npm {name} {sev}{' (fix available)' if fix else ' (no fix)'}", lock, key=f"{lock}|{name}|{sev}")
    return r
