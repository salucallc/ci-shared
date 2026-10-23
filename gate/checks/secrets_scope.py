"""SEC-4 scope: which secret findings belong to the change, and which were already there.

The rule (estate-rules#8, repo-merge-gate.md section 2, SEC-4): a push that ADDS or TOUCHES a
secret is blocked everywhere. A secret already in history does not block an unrelated push; it is
reported as pre-existing, by fingerprint and never by value, so the PR body can list it.

The change is base..HEAD, where base is the merge-base of HEAD with the base ref (the PR base in
CI, else the remote default branch), plus the working tree against that base. A finding blocks
when it is in a commit of that range (history-only commits included, so a secret added and then
removed inside the branch still blocks) or in the working tree, AND either

  - its value (rule plus fp12) is not present anywhere at base, or
  - it sits on a line the commit adds (so touching the line of an old secret blocks), or
  - it is a secrets FILE (SEC-3) and the commit adds or modifies that file.

Merge commits count only what is new against EVERY parent, so merging the base into a branch does
not make the base's old secrets the branch's. No base that can be resolved, a shallow clone, or a
failing git call is cannot tell, never a pass.
"""
from __future__ import annotations
import re
from ..core import Repo
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
HUNK = re.compile('^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,(\\d+))? @@')
DIFF_OPTS = ('--no-color', '--no-ext-diff', '--no-textconv', '--no-renames')

class CannotTell(Exception):
    pass

def _git(repo: Repo, *args: str) -> str:
    try:
        return repo.git(*args)
    except (RuntimeError, OSError) as e:
        raise CannotTell(str(e)) from e

def default_base_candidates(repo: Repo) -> list[str]:
    """The remote default branch: origin/HEAD if it is set, else origin/main, else origin/master."""
    out = []
    sym = repo.git('symbolic-ref', '-q', 'refs/remotes/origin/HEAD', check=False).strip()
    if sym:
        out.append(sym)
    out += ['refs/remotes/origin/main', 'refs/remotes/origin/master']
    return out

def _verify(repo: Repo, ref: str) -> str | None:
    sha = repo.git('rev-parse', '--verify', '--quiet', f'{ref}^{{commit}}', check=False).strip()
    return sha or None

def resolve_base(repo: Repo, base_ref: str | None) -> tuple[str, str]:
    """Return (merge-base sha, label). A named ref that does not resolve never falls back."""
    if _git(repo, 'rev-parse', '--is-shallow-repository').strip() == 'true':
        raise CannotTell('shallow clone: history is incomplete, so the change cannot be told from what was already there; fetch full history (fetch-depth: 0)')
    if not _verify(repo, 'HEAD'):
        raise CannotTell('HEAD does not resolve to a commit')
    if base_ref:
        sha = _verify(repo, base_ref)
        if not sha:
            raise CannotTell(f'base ref {base_ref!r} does not resolve to a commit; fetch it, or name the PR base')
        label = base_ref
    else:
        sha = label = None
        for cand in default_base_candidates(repo):
            sha = _verify(repo, cand)
            if sha:
                label = cand.removeprefix('refs/remotes/')
                break
        if not sha:
            raise CannotTell('no base: pass --base-ref (the PR base), or fetch the remote default branch (origin/HEAD, origin/main or origin/master); --whole-repo treats every commit as the change')
    mb = repo.git('merge-base', sha, 'HEAD', check=False).strip()
    if not mb:
        raise CannotTell(f'no merge-base between {label} and HEAD (unrelated histories)')
    return (mb, label)

def range_commits(repo: Repo, base: str) -> list[str]:
    out = _git(repo, 'rev-list', '--reverse', f'{base}..HEAD')
    return [c for c in out.split() if c]

def parents(repo: Repo, commit: str) -> list[str]:
    parts = _git(repo, 'rev-list', '--parents', '-n', '1', commit).split()
    return parts[1:]

def changed_blobs(repo: Repo, old: str, new: str) -> dict[str, str]:
    """{path: new blob sha} for regular files added or modified between two tree-ishes."""
    raw = _git(repo, 'diff-tree', '-r', '-z', '--raw', *DIFF_OPTS[3:], old, new)
    toks = raw.split('\x00')
    out: dict[str, str] = {}
    i = 0
    while i < len(toks) - 1:
        meta, path = (toks[i], toks[i + 1])
        i += 2
        if not meta.startswith(':'):
            continue
        f = meta[1:].split()
        if len(f) < 5:
            continue
        mode, sha, status = (f[1], f[3], f[4])
        if status.startswith('D') or not mode.startswith('100'):
            continue
        out[path] = sha
    return out

def commit_changes(repo: Repo, commit: str) -> tuple[list[str], dict[str, str]]:
    """(parents, {path: blob}) of what the commit itself introduces. For a merge, only paths whose new
    content differs from every parent."""
    ps = parents(repo, commit) or [EMPTY_TREE]
    per = [changed_blobs(repo, p, commit) for p in ps]
    common = {k: v for k, v in per[0].items() if all((k in d for d in per[1:]))}
    return (ps, common)

def added_lines(repo: Repo, old: str, new: str | None, path: str) -> set[int]:
    """Line numbers (in the new version) that the diff old -> new adds. new None is the working tree."""
    args = ['diff', *DIFF_OPTS, '-U0', old] + ([new] if new else []) + ['--', f':(literal){path}']
    out: set[int] = set()
    for line in _git(repo, *args).splitlines():
        m = HUNK.match(line)
        if m:
            start, count = (int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1))
            out.update(range(start, start + count))
    return out

def added_in_commit(repo: Repo, ps: list[str], commit: str, path: str) -> set[int]:
    sets = [added_lines(repo, p, commit, path) for p in ps]
    return set.intersection(*sets) if sets else set()

def tree_changes(repo: Repo, base: str) -> list[str]:
    """Paths whose working-tree content differs from base (tracked or staged)."""
    raw = _git(repo, 'diff', *DIFF_OPTS, '--name-only', '-z', '--diff-filter=d', base)
    return [p for p in raw.split('\x00') if p]

def reachable_blobs(repo: Repo, *revs: str) -> dict[str, str]:
    """{blob sha: one path} for every object rev-list reaches from revs."""
    out: dict[str, str] = {}
    for line in _git(repo, 'rev-list', '--objects', *revs).splitlines():
        sha, _, path = line.partition(' ')
        if path and sha not in out:
            out[sha] = path
    return out

def blocks(rule: str, fp: str, line: int, added: set[int], base_fps: set[tuple[str, str]]) -> bool:
    """The change adds or touches this secret."""
    return rule == 'SEC-3' or (rule, fp) not in base_fps or line in added