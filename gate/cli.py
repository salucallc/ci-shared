"""saluca merge gate: run the estate's merge standard against a repo, locally or in CI.

  python -m gate run [--repo DIR] [--only a,b] [--json out.json] [--offline] [--deep]
  python -m gate fast FILE...          pre-commit: paths, control chars, style, secrets on files
  python -m gate baseline [--repo DIR] write .gate-baseline.json from today's blocking findings
  python -m gate detect                print python=/node= for the CI workflow
  python -m gate list                  the checks and their requirement ids
  python -m gate bootstrap             fetch pinned gitleaks and a pip-audit venv into ~/.cache

Exit codes: 0 green (warnings allowed), 1 a blocking finding, 2 cannot tell. Cannot tell is
never a pass. A red gate is never pushed. The standard is saluca-handoff
KB/workflows/repo-merge-gate.md; requirement ids (SEC-1, CLM-3, ...) are its section ids.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import tomllib
from pathlib import Path

from .checks import (ci_hygiene, claims, consistency, control_chars, deps, docs, licence, log_redaction, mutation,
                     packaging, paths, secrets, security, style, test_markers)
from .core import BLOCK, CANNOT, CI_ONLY, FAIL, NA, PASS, WARN, WARN_S, Repo, Result

CHECKS = {  # name: (runner, requirement ids, kind)
    "secrets": (secrets.run, "SEC-1..SEC-4", "change"),
    "paths": (paths.run, "TST-3, EXP-1", "change"),
    "control-chars": (control_chars.run, "TST-4", "change"),
    "style": (style.run, "STY-1, STY-3", "change"),
    "test-markers": (test_markers.run, "TST-1, TST-2", "change"),
    "claims": (claims.run, "CLM-1..CLM-7", "change"),
    "packaging": (packaging.run, "PKG-1, PKG-2", "change"),
    "licence": (licence.run, "LIC-1..LIC-4", "change"),
    "ci-hygiene": (ci_hygiene.run, "CI-1..CI-5", "change"),
    "deps": (deps.run, "DEP-1..DEP-3", "change"),
    "security": (security.run, "SEC-5..SEC-8", "change"),
    "log-redaction": (log_redaction.run, "SEC-9", "change"),
    "consistency": (consistency.run, "CON-1, CON-2", "change"),
    "docs": (docs.run, "DOC-1", "change"),
    "mutation": (mutation.run, "TST-5", "change"),
    "sast": (None, "SEC-10", "ci-only"),
    "branch-protection": (ci_hygiene.run_protection, "CI-6", "settings"),
}
FAST = ("paths", "control-chars", "style", "secrets")
NO_WAIVE = {"secrets"}  # a secret is rotated, never waived; reviewed gitleaks fixtures go in .gitleaksignore
NO_BASELINE = {"secrets"}
CONFIG_KEYS = {"gate": {"visibility"}, "claims": {"none"}, "docs": {"required-headings"},
               "mutation": {"targets", "test-command", "install-command", "max-mutants"}, "waive": None}
ISSUE_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/(issues|pull)/\d+$")


def load_config(repo: Repo, cfg_result: Result) -> None:
    p = repo.root / ".gate.toml"
    if not p.is_file():
        return
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        cfg_result.cannot(f".gate.toml does not parse: {e}")
        return
    for k, v in data.items():
        if k not in CONFIG_KEYS:
            cfg_result.add(BLOCK, f"GATE-1: unknown .gate.toml section [{k}] (config may only waive named findings "
                           "or describe the repo; it cannot switch checks off)", ".gate.toml", key=f"unknown|{k}")
        elif CONFIG_KEYS[k] is not None and isinstance(v, dict):
            for kk in v:
                if kk not in CONFIG_KEYS[k]:
                    cfg_result.add(BLOCK, f"GATE-1: unknown key {k}.{kk} in .gate.toml", ".gate.toml", key=f"unknown|{k}.{kk}")
    repo.config = data


def waivers(repo: Repo, cfg_result: Result, today: dt.date) -> list[dict]:
    out = []
    for i, w in enumerate(repo.config.get("waive", []) or [], 1):
        where = f"waive #{i}"
        problems = []
        if w.get("check") not in CHECKS:
            problems.append(f"check {w.get('check')!r} is not a gate check")
        if w.get("check") in NO_WAIVE:
            problems.append(f"{w.get('check')} findings cannot be waived (rotate the secret; reviewed gitleaks fixtures "
                            "go in .gitleaksignore with a reason)")
        if len(str(w.get("reason", "")).strip()) < 20:
            problems.append("reason missing or under 20 characters")
        if not ISSUE_URL.match(str(w.get("issue", ""))):
            problems.append("issue must be a full GitHub issue or PR URL")
        try:
            exp = dt.date.fromisoformat(str(w.get("expires", "")))
            if (exp - today).days > 366:
                problems.append("expires more than a year out")
        except ValueError:
            exp = None
            problems.append("expires must be a YYYY-MM-DD date")
        if not w.get("path") and not w.get("match"):
            problems.append("needs path (a glob) or match (text in the message), so it names a finding")
        if problems:
            cfg_result.add(BLOCK, f"GATE-2: {where} is invalid: {'; '.join(problems)}", ".gate.toml", key=f"waiver|{i}")
            continue
        if exp and exp < today:
            cfg_result.add(WARN, f"GATE-2: {where} expired on {exp}; it no longer applies", ".gate.toml", key=f"expired|{i}")
            continue
        out.append(dict(w, _n=i, _used=0))
    return out


def apply_waivers(results: list[Result], ws: list[dict]) -> None:
    for r in results:
        for f in r.findings:
            if f.severity != BLOCK or f.state != "open":
                continue
            for w in ws:
                if w["check"] != r.check:
                    continue
                if w.get("path") and not fnmatch.fnmatch(f.path, w["path"]):
                    continue
                if w.get("match") and w["match"] not in f.message:
                    continue
                f.state, f.note = "waived", f"waived until {w['expires']}: {w['reason']} ({w['issue']})"
                w["_used"] += 1
                break


def baseline_path(repo: Repo) -> Path:
    return repo.root / ".gate-baseline.json"


def apply_baseline(repo: Repo, results: list[Result], cfg_result: Result, base_ref: str | None) -> None:
    p = baseline_path(repo)
    if not p.is_file():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        entries = {(e["check"], e["key"]) for e in data.get("entries", [])}
    except (json.JSONDecodeError, KeyError, TypeError):
        cfg_result.cannot(".gate-baseline.json is not valid")
        return
    if base_ref:
        try:
            old = json.loads(repo.git("show", f"{base_ref}:.gate-baseline.json"))
            old_entries = {(e["check"], e["key"]) for e in old.get("entries", [])}
            grown = entries - old_entries
            if grown:
                cfg_result.add(BLOCK, f"GATE-3: the baseline grew by {len(grown)} entr{'y' if len(grown) == 1 else 'ies'} "
                               f"against {base_ref}; debt may only shrink (new findings are fixed or waived with a reason)",
                               ".gate-baseline.json", key="grown")
        except RuntimeError:
            pass  # no baseline on the base branch: this PR adopts the gate, and the reviewer reads the file
        except (json.JSONDecodeError, KeyError, TypeError):
            cfg_result.cannot(f"{base_ref}:.gate-baseline.json is not valid")
    used = set()
    for r in results:
        if r.check in NO_BASELINE:
            continue
        for f in r.findings:
            if f.severity == BLOCK and f.state == "open" and (r.check, f.ident()) in entries:
                f.state, f.note = "baselined", "pre-existing debt recorded in .gate-baseline.json"
                used.add((r.check, f.ident()))
    stale = entries - used
    if stale:
        cfg_result.add(WARN, f"GATE-3: {len(stale)} baseline entr{'y is' if len(stale) == 1 else 'ies are'} fixed; "
                       "run `python -m gate baseline` to shrink the file", ".gate-baseline.json", key="stale")


def visibility(repo: Repo, a) -> str | None:
    if a.visibility:
        return a.visibility
    if not a.offline:
        from .core import origin_slug, env_token
        slug = a.repo_slug or origin_slug(repo)
        if slug:
            code, meta = ci_hygiene.api(f"/repos/{slug}", env_token())
            if code == 200 and isinstance(meta, dict):
                return "private" if meta.get("private") else "public"
    return repo.config.get("gate", {}).get("visibility") or "public"


def run_checks(repo: Repo, names: list[str], a) -> list[Result]:
    results = []
    for name in names:
        fn, _ids, kind = CHECKS[name]
        if fn is None:
            r = Result(name, "Generic SAST: bandit and semgrep rulepacks")
            r.forced = CI_ONLY
            r.notes.append("runs in CI only (merge-gate.yml calls reusable-sast-python.yml and reusable-semgrep.yml); "
                           "CI is the final verdict for this check")
            results.append(r)
            continue
        try:
            results.append(fn(repo, a))
        except Exception as e:  # noqa: BLE001 - a crashing check is cannot-tell, never a pass
            r = Result(name, name)
            r.cannot(f"check crashed: {type(e).__name__}: {e}")
            results.append(r)
    return results


def render(repo: Repo, results: list[Result], out=None, max_items: int = 40) -> None:
    out = out or sys.stdout  # resolved per call, so contextlib.redirect_stdout (gate_matrix.py) captures it
    print(f"saluca merge gate: {repo.root.name}  ({dt.date.today().isoformat()})", file=out)
    print(f"{'check':<19}{'status':<13}{'block':>6}{'warn':>6}{'waived':>8}{'debt':>6}", file=out)
    for r in results:
        b = sum(1 for f in r.findings if f.severity == BLOCK and f.state == "open")
        w = sum(1 for f in r.findings if f.severity == WARN)
        wv = sum(1 for f in r.findings if f.state == "waived")
        d = sum(1 for f in r.findings if f.state == "baselined")
        print(f"{r.check:<19}{r.status:<13}{b:>6}{w:>6}{wv:>8}{d:>6}", file=out)
    for r in results:
        shown = [f for f in r.findings if f.state == "open" and f.severity == BLOCK] + \
            [f for f in r.findings if f.severity == WARN] + [f for f in r.findings if f.state == "waived"]
        if not shown and not (r.notes and r.status in (CANNOT, NA, CI_ONLY)):
            continue
        print(f"\n[{r.check}] {r.title}: {r.status}", file=out)
        for n in r.notes:
            print(f"  note: {n}", file=out)
        for f in shown[:max_items]:
            tag = "WAIVED" if f.state == "waived" else ("BLOCK" if f.severity == BLOCK else "warn")
            print(f"  {tag:<6} {f.where()}  {f.message}" + (f"  [{f.note}]" if f.note else ""), file=out)
        if len(shown) > max_items:
            print(f"  ... {len(shown) - max_items} more (use --json for all)", file=out)


def verdict(results: list[Result]) -> int:
    st = [r.status for r in results]
    if FAIL in st:
        return 1
    if CANNOT in st:
        return 2
    return 0


def annotate(results: list[Result]) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for r in results:
        for f in r.findings:
            if f.state != "open":
                continue
            level = "error" if f.severity == BLOCK else "warning"
            loc = f" file={f.path}" + (f",line={f.line}" if f.line else "") if f.path and not f.path.startswith("(") else ""
            msg = f.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::{level}{loc},title=merge gate: {r.check}::{msg}" if loc else f"::{level} title=merge gate: {r.check}::{msg}")
        if r.status == CANNOT:
            print(f"::error title=merge gate: {r.check}::cannot tell: {'; '.join(r.notes)[:900]}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("| check | status | block | warn |\n|---|---|---|---|\n")
            for r in results:
                b = sum(1 for f in r.findings if f.severity == BLOCK and f.state == "open")
                w = sum(1 for f in r.findings if f.severity == WARN)
                fh.write(f"| {r.check} | {r.status} | {b} | {w} |\n")


def to_json(repo: Repo, results: list[Result]) -> dict:
    return {"repo": repo.root.name, "date": dt.date.today().isoformat(), "exit": verdict(results),
            "checks": [{"check": r.check, "status": r.status, "title": r.title, "notes": r.notes,
                        "findings": [f.__dict__ for f in r.findings]} for r in results]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gate", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="run", choices=["run", "fast", "baseline", "detect", "list", "bootstrap"])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--only", help="comma-separated check names")
    ap.add_argument("--skip-settings", action="store_true", help="leave out branch-protection (a repo setting)")
    ap.add_argument("--json")
    ap.add_argument("--offline", action="store_true", help="no network: online checks become cannot-tell")
    ap.add_argument("--deep", action="store_true", help="also pip download every PyPI package the README installs")
    ap.add_argument("--no-audit", dest="audit", action="store_false")
    ap.add_argument("--no-history", action="store_true", help="secrets: tree only (pre-commit speed; never a push verdict)")
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--base-ref", help="the PR's base, for the baseline-may-only-shrink rule")
    ap.add_argument("--repo-slug")
    ap.add_argument("--branch")
    ap.add_argument("--visibility", choices=["public", "private"])
    ap.add_argument("--today", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    if a.command == "bootstrap":
        from . import bootstrap
        return bootstrap.main(a.files)
    if a.command == "list":
        for name, (_fn, ids, kind) in CHECKS.items():
            print(f"{name:<19}{ids:<16}{kind}")
        return 0
    repo = Repo(Path(a.repo), base_ref=a.base_ref)
    if a.command == "detect":
        files = set(repo.tracked())
        py = any(f in files for f in ("pyproject.toml", "setup.py", "setup.cfg")) or any(
            re.match(r"requirements[\w.-]*\.txt$", f) for f in files)
        node = "package.json" in files
        lines = [f"python={'true' if py else 'false'}", f"node={'true' if node else 'false'}"]
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        print("\n".join(lines))
        return 0
    if not repo.is_git():
        print(f"gate: {repo.root} is not a git work tree; cannot tell", file=sys.stderr)
        return 2
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    cfg = Result("gate-config", "Gate configuration (.gate.toml waivers, .gate-baseline.json)")
    load_config(repo, cfg)
    ws = waivers(repo, cfg, today)

    if a.command == "fast":
        a.files = [f.replace("\\", "/") for f in a.files] or None
        a.no_history = True
        names = list(FAST)
    else:
        a.files = None
        names = list(CHECKS)
        if a.only:
            names = [n.strip() for n in a.only.split(",") if n.strip()]
            bad = [n for n in names if n not in CHECKS]
            if bad:
                print(f"gate: unknown check(s) {bad}; see `python -m gate list`", file=sys.stderr)
                return 2
        if a.skip_settings and "branch-protection" in names:
            names.remove("branch-protection")
    if "docs" in names:
        a.visibility = visibility(repo, a)
    results = run_checks(repo, names, a)
    if a.command == "baseline":
        entries = [{"check": r.check, "key": f.ident(), "path": f.path, "message": f.message[:200]}
                   for r in results if r.check not in NO_BASELINE for f in r.findings
                   if f.severity == BLOCK and f.state == "open"]
        baseline_path(repo).write_text(json.dumps({"version": 1, "written": today.isoformat(),
                                                   "rule": "debt may only shrink; see repo-merge-gate.md GATE-3",
                                                   "entries": entries}, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {baseline_path(repo)} with {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
        return 0
    apply_waivers(results, ws)
    apply_baseline(repo, results, cfg, a.base_ref)
    for w in ws:
        if not w["_used"]:
            cfg.add(WARN, f"GATE-2: waive #{w['_n']} matches no finding; delete it", ".gate.toml", key=f"unused|{w['_n']}")
    if cfg.findings or cfg.forced:
        results.insert(0, cfg)
    render(repo, results)
    annotate(results)
    code = verdict(results)
    if a.json:
        Path(a.json).write_text(json.dumps(to_json(repo, results), indent=1, default=str), encoding="utf-8")
    word = {0: "GREEN", 1: "RED", 2: "RED (cannot tell)"}[code]
    ci_only = [r.check for r in results if r.status == CI_ONLY]
    print(f"\nVerdict: {word}." + (" Do not push." if code else "") +
          (f" CI-only, not judged here: {', '.join(ci_only)}." if ci_only else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
