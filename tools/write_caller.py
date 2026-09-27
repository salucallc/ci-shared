"""Write a caller workflow (.github/workflows/ci.yml) that adopts ci-shared's stack CI.

Usage:
  python tools/write_caller.py <repo_dir> --branch main --sha <ci-shared commit> \
      [--node DIR[:key=value,...]]... [--python DIR[:key=value,...]]... [--no-secret-scan]

Each --node / --python adds one job running that stack workflow in DIR (use . for the root);
key=value pairs become `with:` inputs (e.g. test-command=skip, node-version=20). The SHA must
be a full 40-character commit on ci-shared main: consumers pin by SHA, never by tag or branch.
Refuses to overwrite an existing ci.yml unless --force.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WF = "salucallc/ci-shared/.github/workflows"


def job(kind: str, spec: str) -> tuple[str, list[str]]:
    d, _, kv = spec.partition(":")
    name = kind if d in (".", "") else f"{kind}-{re.sub(r'[^a-z0-9]+', '-', d.lower()).strip('-')}"
    inputs = {} if d in (".", "") else {"working-directory": d}
    for pair in filter(None, kv.split(",")):
        k, sep, v = pair.partition("=")
        if not sep:
            raise SystemExit(f"bad input {pair!r}: expected key=value")
        inputs[k] = v
    return name, [f"{k}: {v!r}" if not re.fullmatch(r"[\w./:-]+", v) else f"{k}: {v}"
                  for k, v in inputs.items()]


def render(branch: str, sha: str, jobs: list[tuple[str, str, list[str]]], secret_scan: bool) -> str:
    out = [
        "# CI via salucallc/ci-shared reusable workflows (pinned by commit SHA).",
        "# Inputs, adoption and re-pinning: see the salucallc/ci-shared README.",
        "name: CI",
        "",
        "on:",
        "  pull_request:",
        "  push:",
        f"    branches: [{branch}]",
        "  workflow_dispatch:",
        "",
        "concurrency:",
        "  group: ${{ github.workflow }}-${{ github.ref }}",
        "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
        "",
        "permissions:",
        "  contents: read",
        "",
        "jobs:",
    ]
    for name, wf, inputs in jobs:
        out.append(f"  {name}:")
        out.append(f"    uses: {WF}/{wf}@{sha}")
        if inputs:
            out.append("    with:")
            out += [f"      {i}" for i in inputs]
    if secret_scan:
        out += ["  secret-scan:", f"    uses: {WF}/reusable-secret-scan.yml@{sha}"]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_dir")
    ap.add_argument("--branch", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--node", action="append", default=[])
    ap.add_argument("--python", action="append", default=[])
    ap.add_argument("--no-secret-scan", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", a.sha):
        raise SystemExit("--sha must be a full 40-character commit SHA")
    if not (a.node or a.python):
        raise SystemExit("at least one --node or --python job is required")
    jobs = [(n, "reusable-node-ci.yml", i) for n, i in (job("node", s) for s in a.node)]
    jobs += [(n, "reusable-python-ci.yml", i) for n, i in (job("python", s) for s in a.python)]
    dest = Path(a.repo_dir) / ".github" / "workflows" / "ci.yml"
    if dest.exists() and not a.force:
        raise SystemExit(f"{dest} exists; pass --force to overwrite")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render(a.branch, a.sha, jobs, not a.no_secret_scan), encoding="utf-8", newline="\n")
    print(dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
