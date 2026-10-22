"""Propose (and, only with --apply, set) branch protection for the merge gate on public repos.

Dry run is the default: it reads each repo's default branch and current protection and prints
what it WOULD set. Changing repo settings is Cristian's call; an agent runs this without --apply.

Per repo, the proposal is:
  - required status check "<caller job> / Merge gate all" (strict: the branch must be up to date),
    merged with any checks already required;
  - a pull request is required (0 approvals, because a sole maintainer cannot approve their own
    PR), stale reviews dismissed, conversations resolved;
  - enforce_admins on (no direct push, including the owner's credential, which agents use);
  - no force pushes, no deletion.
A check that has never reported on the default branch is NOT required (it would block every
merge until the caller lands) unless --force-contexts is given. Adopt the caller first.

Usage:
  python tools/branch_protection.py                      # both orgs, public repos, dry run
  python tools/branch_protection.py --repo saluca-labs/cct
  python tools/branch_protection.py --json plan.json
  python tools/branch_protection.py --apply --repo saluca-labs/cct   # Cristian only
Needs an authenticated gh CLI (reading protection needs admin on the repo).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

ORGS = ["saluca-labs", "salucallc"]
GATE_CHECK = "Merge gate all"


def gh(*args: str, input_: str | None = None) -> tuple[int, str]:
    out = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", input=input_)
    return out.returncode, out.stdout if out.returncode == 0 else out.stderr


def public_repos(org: str) -> list[dict]:
    code, out = gh("repo", "list", org, "--visibility", "public", "--no-archived", "--limit", "200",
                   "--json", "nameWithOwner,defaultBranchRef,isFork")
    if code:
        raise SystemExit(f"gh repo list {org} failed: {out.strip()}")
    return [r for r in json.loads(out) if not r.get("isFork")]


def current(slug: str, branch: str) -> dict:
    code, out = gh("api", f"repos/{slug}/branches/{branch}/protection")
    if code:
        return {"protected": False, "detail": "not protected" if "Not Found" in out or "not protected" in out.lower()
                else out.strip()[:120]}
    p = json.loads(out)
    return {"protected": True, "contexts": (p.get("required_status_checks") or {}).get("contexts", []),
            "strict": (p.get("required_status_checks") or {}).get("strict"),
            "enforce_admins": (p.get("enforce_admins") or {}).get("enabled"),
            "pr_required": p.get("required_pull_request_reviews") is not None,
            "force_pushes": (p.get("allow_force_pushes") or {}).get("enabled")}


def gate_context(slug: str, branch: str) -> str | None:
    """The full context name of the gate's fan-in check if it has reported on the branch head."""
    code, out = gh("api", f"repos/{slug}/commits/{branch}/check-runs?per_page=100")
    if code:
        return None
    for run in json.loads(out).get("check_runs", []):
        if run.get("name", "").endswith(GATE_CHECK):
            return run["name"]
    return None


def proposal(cur: dict, ctx: str) -> dict:
    contexts = sorted(set(cur.get("contexts") or []) | {ctx})
    return {
        "required_status_checks": {"strict": True, "contexts": contexts},
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": True},
        "restrictions": None,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_conversation_resolution": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", action="append", default=[], help="owner/name; default: every public repo in both orgs")
    ap.add_argument("--caller-job", default="gate", help="the job id in the caller workflow (context prefix)")
    ap.add_argument("--apply", action="store_true", help="actually PUT the protection (Cristian's go only)")
    ap.add_argument("--force-contexts", action="store_true", help="require the gate check even if it never reported")
    ap.add_argument("--json")
    a = ap.parse_args()

    repos = []
    if a.repo:
        for slug in a.repo:
            code, out = gh("repo", "view", slug, "--json", "nameWithOwner,defaultBranchRef")
            if code:
                raise SystemExit(f"gh repo view {slug}: {out.strip()}")
            repos.append(json.loads(out))
    else:
        for org in ORGS:
            repos += public_repos(org)
    plan = []
    for r in repos:
        slug, branch = r["nameWithOwner"], (r.get("defaultBranchRef") or {}).get("name") or "main"
        cur = current(slug, branch)
        seen = gate_context(slug, branch)
        ctx = seen or f"{a.caller_job} / {GATE_CHECK}"
        action = "would set" if not a.apply else "set"
        note = ""
        if not seen and not a.force_contexts:
            action, note = "hold", "the gate has never reported on this branch: merge the caller workflow first"
        payload = proposal(cur, ctx)
        if a.apply and action == "set":
            code, out = gh("api", "-X", "PUT", f"repos/{slug}/branches/{branch}/protection",
                           "-H", "Accept: application/vnd.github+json", "--input", "-", input_=json.dumps(payload))
            action = "set" if code == 0 else f"FAILED: {out.strip()[:160]}"
        plan.append({"repo": slug, "branch": branch, "current": cur, "gate_reporting": bool(seen),
                     "action": action, "note": note, "payload": payload})
    print(f"{'repo':<42}{'branch':<16}{'protected':<11}{'gate seen':<11}action")
    for p in plan:
        print(f"{p['repo']:<42}{p['branch']:<16}{str(p['current'].get('protected')):<11}{str(p['gate_reporting']):<11}"
              f"{p['action']}{'  (' + p['note'] + ')' if p['note'] else ''}")
    if not a.apply:
        print("\nDry run: nothing was changed. Each row's payload is in --json; to apply one repo:\n"
              "  python tools/branch_protection.py --apply --repo <owner/name>")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
