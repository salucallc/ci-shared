"""CI-1..CI-5: CI exists, runs on pull requests, runs tests, and nothing in it is allowed to fail
quietly. CI-6 (online, repo settings): the default branch is protected, requires a PR, and
requires the merge gate's fan-in check.

Tony's review, 2026-10-22: CI where lint and build do not block a merge. The patterns that make
a red step look green are `continue-on-error: true`, `|| true` / `|| exit 0` after a command, and
`if: false` on a job.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from ..core import BLOCK, WARN, Repo, Result, env_token, origin_slug

GATE_USES = re.compile(r"uses:\s*(salucallc/ci-shared/\.github/workflows/merge-gate\.yml@[0-9a-f]{40}\b|\./\.github/workflows/merge-gate\.yml)")
TEST_HINT = re.compile(r"(?i)\b(pytest|unittest|tox|nox|npm (run )?test|pnpm (run )?test|yarn test|vitest|jest|go test|cargo test|"
                       r"reusable-python-ci|reusable-node-ci|merge-gate\.yml|make test|bun test|deno test)\b")
LINT_HINT = re.compile(r"(?i)\b(ruff|flake8|pylint|eslint|black --check|mypy|pyright|tsc|prettier --check|golangci|clippy|"
                       r"actionlint|yamllint|shellcheck|lint)\b")
SWALLOW = re.compile(r"(?m)^\s*[^#\n]*\b(pytest|npm|pnpm|yarn|ruff|flake8|eslint|tsc|mypy|make|go|cargo|python|lint|test|build)\b"
                     r"[^\n#]*(\|\|\s*(true|:|exit 0)(\s|$)|--exit-zero)")
FANIN_CONTEXT = "Merge gate all"


def workflows(repo: Repo) -> dict[str, str]:
    return {f: repo.text(f) or "" for f in repo.tracked()
            if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))}


def static(repo: Repo, r: Result) -> None:
    wfs = workflows(repo)
    if not wfs:
        r.add(BLOCK, "CI-1: no GitHub Actions workflow; nothing checks a PR before merge", key="no-ci")
        return
    on_pr = {f for f, t in wfs.items() if re.search(r"(?m)^\s*(on:\s*\[?[^\n]*\bpull_request\b|pull_request(_target)?:)", t)}
    if not on_pr:
        r.add(BLOCK, "CI-2: no workflow runs on pull_request", key="no-pr")
    if not any(TEST_HINT.search(t) for t in wfs.values()):
        r.add(BLOCK, "CI-3: no workflow runs tests", key="no-test")
    if not any(LINT_HINT.search(t) for t in wfs.values()) and not any(GATE_USES.search(t) for t in wfs.values()):
        r.add(WARN, "CI-3: no workflow runs a linter or type check", key="no-lint")
    for f, t in wfs.items():
        for m in re.finditer(r"(?m)^\s*continue-on-error:\s*(true|\$\{\{[^}]*\}\})\s*$", t):
            ln = t.count("\n", 0, m.start()) + 1
            r.add(BLOCK, "CI-4: continue-on-error lets a failing step or job report success", f, ln, key=f"{f}|coe|{ln}")
        for m in SWALLOW.finditer(t):
            ln = t.count("\n", 0, m.start()) + 1
            r.add(BLOCK, "CI-4: a check's failure is swallowed ('|| true', '|| exit 0' or --exit-zero)", f, ln,
                  key=f"{f}|swallow|{m.group(0).strip()[:60]}")
        for m in re.finditer(r"(?m)^\s{2,4}if:\s*(false|\$\{\{\s*false\s*\}\})\s*$", t):
            ln = t.count("\n", 0, m.start()) + 1
            r.add(WARN, "CI-4: a job is disabled with 'if: false'", f, ln, key=f"{f}|iffalse|{ln}")
        for m in re.finditer(r"(?m)^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@([^\s#]+)", t):
            if not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith("./"):
                ln = t.count("\n", 0, m.start()) + 1
                r.add(WARN, f"CI-5: {m.group(1)}@{m.group(2)} is not pinned to a commit SHA", f, ln,
                      key=f"{f}|pin|{m.group(1)}@{m.group(2)}")
    if not any(GATE_USES.search(t) for t in wfs.values()):
        r.add(BLOCK, "CI-5: the merge gate is not adopted (no workflow calls "
              "salucallc/ci-shared/.github/workflows/merge-gate.yml@<40-hex sha>)", key="no-gate")


def api(path: str, token: str | None):
    req = urllib.request.Request(f"https://api.github.com{path}", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310  (fixed https host)
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def protection(repo: Repo, r: Result, slug: str | None, branch: str | None) -> None:
    slug = slug or origin_slug(repo)
    if not slug:
        r.cannot("CI-6: cannot tell which GitHub repo this is (no github.com origin); pass --repo-slug")
        return
    token = env_token()
    code, meta = api(f"/repos/{slug}", token)
    if code != 200 or not isinstance(meta, dict):
        r.cannot(f"CI-6: GET /repos/{slug} returned {code}")
        return
    branch = branch or meta.get("default_branch")
    code, b = api(f"/repos/{slug}/branches/{branch}", token)
    code2, rules = api(f"/repos/{slug}/rules/branches/{branch}", token)
    if code != 200 or code2 not in (200, 404):
        r.cannot(f"CI-6: branch or rules read failed ({code}, {code2})")
        return
    rules = rules if isinstance(rules, list) else []
    rule_types = {x.get("type") for x in rules}
    classic = (b or {}).get("protection") or {}
    protected = bool((b or {}).get("protected")) or bool(rule_types)
    contexts = set((classic.get("required_status_checks") or {}).get("contexts") or [])
    for x in rules:
        if x.get("type") == "required_status_checks":
            for c in (x.get("parameters") or {}).get("required_status_checks", []):
                contexts.add(c.get("context", ""))
    requires_pr = "pull_request" in rule_types
    if not protected:
        r.add(BLOCK, f"CI-6: {slug}@{branch} is not protected: anyone with write access can push to it directly",
              key="unprotected")
    else:
        if not contexts:
            r.add(BLOCK, f"CI-6: {slug}@{branch} is protected but requires no status checks", key="no-required")
        elif not any(FANIN_CONTEXT in c for c in contexts):
            r.add(BLOCK, f"CI-6: required checks on {branch} ({', '.join(sorted(contexts))}) do not include the merge "
                  f"gate's '{FANIN_CONTEXT}'", key="gate-not-required")
        if not requires_pr and classic.get("enabled") is not True:
            r.add(WARN, f"CI-6: cannot confirm {branch} requires a pull request (the classic protection detail needs "
                  "admin read; a ruleset with a pull_request rule is visible to readers)", key="pr-unknown")
    r.notes.append(f"{slug}@{branch}: protected={protected}, required={sorted(contexts) or 'none'}, "
                   f"rulesets={sorted(t for t in rule_types if t) or 'none'}")


def run(repo: Repo, opts) -> Result:
    r = Result("ci-hygiene", "CI runs on PRs, runs tests, and cannot pass quietly; merge gate adopted")
    static(repo, r)
    return r


def run_protection(repo: Repo, opts) -> Result:
    r = Result("branch-protection", "Default branch protected, PR required, merge gate required (repo setting, online)")
    if getattr(opts, "offline", False):
        return r.cannot("branch protection is a live repo setting and --offline was given")
    protection(repo, r, getattr(opts, "repo_slug", None), getattr(opts, "branch", None))
    return r
