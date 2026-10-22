"""DEP-1..DEP-3: dependencies are pinned and audited.

DEP-1  a Node project with dependencies has a lockfile (block): without one, `npm ci` cannot run
       and `npm audit` has nothing to read.
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

CACHE_PY = Path.home() / ".cache" / "saluca-gate" / "venv" / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")


def pip_audit_cmd() -> list[str] | None:
    if shutil.which("pip-audit"):
        return ["pip-audit"]
    if CACHE_PY.is_file():
        return [str(CACHE_PY), "-m", "pip_audit"]
    return None


def run(repo: Repo, opts) -> Result:
    r = Result("deps", "Dependencies pinned (lockfiles) and audited (pip-audit, npm audit)")
    files = repo.tracked()
    names = set(files)
    pkgs = [f for f in files if PurePosixPath(f).name == "package.json"]
    reqs = [f for f in files if re.search(r"(^|/)requirements[\w.-]*\.(txt|in)$", f) and not f.endswith(".in")]
    pyprojects = [f for f in files if PurePosixPath(f).name == "pyproject.toml"]
    if not (pkgs or reqs or pyprojects):
        return r.na("no package.json, requirements*.txt or pyproject.toml")
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
        lock = next((d + n for n in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")
                     if d + n in names or (repo.root / (d + n)).is_file()), None)
        if has_deps and not lock:
            r.add(BLOCK, "DEP-1: Node dependencies with no lockfile; installs are not reproducible and cannot be audited",
                  pj, key=f"nolock|{pj}")
        elif lock:
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
            out = subprocess.run(cmd + ["-r", str(repo.root / req), "--format", "json", "--progress-spinner", "off"],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
            try:
                data = json.loads(out.stdout or "{}")
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
