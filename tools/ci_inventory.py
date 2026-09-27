"""Inventory of CI coverage across the estate's GitHub orgs.

Read-only. Uses the gh CLI (GraphQL) for one query per page of repos. For each repo: visibility,
archived, primary language, detected stack (manifest files at the root), whether
.github/workflows exists, the CI rollup on the default branch head, and open dependency PRs
(head branch dependabot/ or sec/depwatch-).

Usage: python tools/ci_inventory.py [--json out.json] [org ...]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

ORGS = ["salucallc", "saluca-labs"]
DEP_PREFIXES = ("dependabot/", "sec/depwatch-")
MANIFESTS = {
    "pkg": "package.json", "pyproject": "pyproject.toml", "req": "requirements.txt",
    "setup": "setup.py", "gomod": "go.mod", "cargo": "Cargo.toml", "docker": "Dockerfile",
    "tsconfig": "tsconfig.json", "wrangler": "wrangler.toml", "tests": "tests", "test": "test",
}

QUERY = """
query($org:String!, $cursor:String) {
  organization(login:$org) {
    repositories(first:10, after:$cursor, orderBy:{field:NAME, direction:ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        name isArchived isFork visibility pushedAt
        primaryLanguage { name }
        defaultBranchRef { name target { ... on Commit { statusCheckRollup { state } } } }
        workflows: object(expression:"HEAD:.github/workflows") { ... on Tree { entries { name } } }
        %s
        pullRequests(states:OPEN, first:30) { nodes { number headRefName
          commits(last:1) { nodes { commit { statusCheckRollup { state } } } } } }
      }
    }
  }
}
""" % "\n        ".join(f'{k}: object(expression:"HEAD:{v}") {{ id }}' for k, v in MANIFESTS.items())


def gql(org: str, cursor: str | None) -> dict:
    args = ["gh", "api", "graphql", "-f", f"query={QUERY}", "-F", f"org={org}"]
    if cursor:
        args += ["-f", f"cursor={cursor}"]
    for attempt in range(4):  # GitHub returns transient 502s on heavy GraphQL pages
        out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
        if out.returncode == 0:
            break
    else:
        raise SystemExit(f"gh graphql failed for {org}: {out.stderr.strip()}")
    return json.loads(out.stdout)["data"]["organization"]["repositories"]


def stack(n: dict) -> str:
    has = {k for k in MANIFESTS if n.get(k)}
    parts = []
    if "pkg" in has:
        parts.append("node-ts" if "tsconfig" in has else "node")
    if has & {"pyproject", "req", "setup"}:
        parts.append("python")
    if "gomod" in has:
        parts.append("go")
    if "cargo" in has:
        parts.append("rust")
    if "docker" in has:
        parts.append("docker")
    return "+".join(parts) or "none"


def rows(org: str) -> list[dict]:
    res, cursor = [], None
    while True:
        page = gql(org, cursor)
        for n in page["nodes"]:
            wf = n.get("workflows")
            dbr = n.get("defaultBranchRef") or {}
            roll = ((dbr.get("target") or {}).get("statusCheckRollup") or {}).get("state")
            deps = [p for p in n["pullRequests"]["nodes"] if p["headRefName"].startswith(DEP_PREFIXES)]
            dep_states = [((p["commits"]["nodes"] or [{}])[0].get("commit", {}).get("statusCheckRollup") or {}).get("state") for p in deps]
            res.append({
                "repo": f"{org}/{n['name']}", "archived": n["isArchived"], "fork": n["isFork"],
                "visibility": n["visibility"], "pushed": (n["pushedAt"] or "")[:10],
                "language": (n.get("primaryLanguage") or {}).get("name"), "stack": stack(n),
                "has_tests": bool(n.get("tests") or n.get("test")),
                "workflows": [e["name"] for e in wf["entries"]] if wf else [],
                "default_ci": roll or ("NONE" if not wf else "NO_RUN"),
                "dep_prs": [p["number"] for p in deps], "dep_pr_ci": dep_states,
            })
        if not page["pageInfo"]["hasNextPage"]:
            return res
        cursor = page["pageInfo"]["endCursor"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("orgs", nargs="*", default=ORGS)
    ap.add_argument("--json")
    a = ap.parse_args()
    allrows = [r for o in a.orgs for r in rows(o)]
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(allrows, f, indent=1)
    for r in allrows:
        print(f"{r['repo']:<50} {'ARCH' if r['archived'] else r['visibility'][:4]:<5} {r['stack']:<18} "
              f"wf={len(r['workflows'])} ci={r['default_ci']:<8} tests={int(r['has_tests'])} "
              f"deps={r['dep_prs']} {r['dep_pr_ci']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
