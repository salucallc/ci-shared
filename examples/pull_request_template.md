<!-- Merge standard, human half (saluca-handoff KB/workflows/repo-merge-gate.md). The gate checks the rest. -->

## What changed

## Merge gate
- [ ] `python -m gate run` is green locally (or the pre-push hook ran), and CI's "Merge gate all" is green.
- [ ] No waiver or baseline entry was added; or each one is listed here with its reason and issue.

## Human review (REV items)
- [ ] REV-1 Every new or changed capability claim has a CLAIMS.md row, and the wording matches what the code does.
- [ ] REV-2 New behaviour has a test that failed before the change (say how you saw it fail).
- [ ] REV-3 Proxy, auth and installer changes: header allowlist, auth on by default, consent plus backup.
- [ ] REV-4 Licence: unchanged, or the change is dated and Cristian approved it (link).
- [ ] REV-5 Screenshots and output in docs come from a real run of this branch.
- [ ] REV-6 Agent-authored: the commit body or this PR says the act was the agent's, with the attribution lines.
- [ ] REV-7 A public claim that changed or was withdrawn has a dated correction note.
