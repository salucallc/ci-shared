"""CON-1 / CON-2 (warnings until the estate designates one format).

Tony's review, 2026-10-22: three incompatible audit-chain formats across repos, chains that cannot
detect truncation, and a "hash chain" in a search library. Until Cristian designates one chain
format and one library (the open decision recorded in saluca-handoff
KB/workflows/repo-merge-gate.md, section "CON"), this check WARNS on every repo that implements
its own chain and on chains with no truncation test. Once a format is designated, CON-1 becomes
blocking for any chain that does not use it, by a change to this file and the standard.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..core import SOURCE_SUFFIXES, WARN, Repo, Result, is_test_path
from .security import code_view

CHAIN = re.compile(r"\b(prev_hash|previous_hash|prev_digest|parent_hash|chain_hash|hash_chain|prevHash|previousHash|chainHash)\b")
DECISION = "saluca-handoff KB/workflows/repo-merge-gate.md (CON: open decision, no designated chain format yet)"


def run(repo: Repo, opts) -> Result:
    r = Result("consistency", "Shared formats: audit/hash chains (warning until a format is designated)")
    files = repo.tracked()
    sites = []
    for rel in files:
        if is_test_path(rel.lower()) or PurePosixPath(rel).suffix.lower() not in SOURCE_SUFFIXES:
            continue
        text = repo.text(rel) or ""
        text = code_view(rel, text)  # ignore chain field names that only appear inside regex or prose strings
        m = CHAIN.search(text)
        if m:
            sites.append((rel, text.count("\n", 0, m.start()) + 1))
    if not sites:
        return r.na("no hash-chain implementation found")
    for rel, ln in sites:
        r.add(WARN, f"CON-1: implements its own hash chain; the estate format is an open decision, see {DECISION}", rel, ln,
              key=f"{rel}|chain")
    tests = "\n".join(repo.text(f) or "" for f in files if is_test_path(f.lower()))
    if not re.search(r"(?i)truncat", tests):
        r.add(WARN, "CON-2: a hash chain with no truncation test; a chain that verifies from its own first entry cannot "
              "see entries cut off the end (commit to the head and length somewhere outside the chain, and test it)",
              key="no-truncation-test")
    return r
