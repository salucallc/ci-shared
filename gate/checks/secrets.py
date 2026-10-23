"""SEC-1..SEC-4: secrets, over the tree AND every blob in history.

Two layers, because one missed the 2026-10-22 pantheon leak:
  1. gitleaks (pinned 8.30.1, checksum-verified) with gate/gitleaks.toml: the default rules plus
     estate rules (DSN passwords, estate key prefixes, the life-os shapes, a test canary).
  2. A stdlib sweep for what gitleaks cannot express as a regex: base64 values under a k8s
     Secret's `data:` (decoded, then judged), `stringData:` values, DSNs with a real password,
     secret-shaped keys in `.env.example`, and committed secrets FILES (.env, private keys,
     service-account JSON, .npmrc tokens).
No secret value is ever printed: a finding names the rule, path, commit or blob, and `fp12`
(first 12 hex of SHA-256 of the value).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from ..core import BLOCK, WARN, Repo, Result, fp12, is_placeholder, line_of, shannon
from . import secrets_scope as scope

GITLEAKS_VERSION = "8.30.1"
HERE = Path(__file__).resolve().parent.parent
CONFIG = HERE / "gitleaks.toml"

DSN_RE = re.compile(
    r"(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)"
    r"(?:\+[a-z0-9]+)?://([^\s:/@'\"`]+):([^\s@'\"`/]+)@")
SECRET_FILE_NAMES = re.compile(
    r"(?ix)(^|/)(\.env(\.[\w-]+)?|[\w.-]+\.env|id_rsa|id_dsa|id_ecdsa|id_ed25519"
    r"|[\w.-]+\.p12|[\w.-]+\.pfx|[\w.-]+\.jks|[\w.-]+\.keystore|credentials\.json|service[-_]?account[\w.-]*\.json"
    r"|\.pypirc|\.netrc|\.htpasswd)$")
ENV_TEMPLATE = re.compile(r"(?i)\.(example|sample|template|dist|defaults?|tmpl)$|(^|/)example\.env$")
SECRETISH_KEY = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|dsn|database_url|"
                           r"conn(ection)?[_-]?str(ing)?|credential|license[_-]?key|signing[_-]?key|webhook)")
# SOULAUTH_JWT_PRIVATE_KEY_PATH=./keys/private.pem names where a secret lives, not the secret
NOT_A_VALUE_KEY = re.compile(r"(?i)_(path|file|dir|filename|name|id|url_?base|algorithm|alg|issuer|audience|ttl|expires?|"
                             r"expiry|length|len|header|prefix|enabled|required|mode|type|version)$")
K8S_KIND = re.compile(r"(?m)^kind:\s*Secret\s*$")
PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
REVIEWED_FILE = ".secrets-reviewed"
PRE_EXISTING = "pre-existing"  # a Finding state: found, outside the change, reported, not blocking (SEC-4)
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".woff2")


def gitleaks_binary() -> tuple[str | None, str]:
    """Locate the pinned gitleaks. Returns (path, why-not)."""
    cands = []
    if os.environ.get("GATE_GITLEAKS"):
        cands.append(os.environ["GATE_GITLEAKS"])
    exe = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    cands.append(str(Path.home() / ".cache" / "saluca-gate" / f"gitleaks-{GITLEAKS_VERSION}" / exe))
    which = shutil.which("gitleaks")
    if which:
        cands.append(which)
    seen_versions = []
    for c in cands:
        if not Path(c).is_file():
            continue
        try:
            v = subprocess.run([c, "version"], capture_output=True, text=True, timeout=30).stdout.strip().lstrip("v")
        except (OSError, subprocess.TimeoutExpired):
            continue
        if v == GITLEAKS_VERSION:
            return c, ""
        seen_versions.append(f"{c} is {v or 'unknown'}")
    why = f"gitleaks {GITLEAKS_VERSION} not found"
    if seen_versions:
        why += f" ({'; '.join(seen_versions)})"
    return None, why + "; run `python -m gate bootstrap` (downloads the pinned, checksum-verified binary)"


def ignore_file_problems(repo: Repo, r: Result) -> None:
    """Every fingerprint in .gitleaksignore must sit under a comment that says why."""
    p = repo.root / ".gitleaksignore"
    if not p.is_file():
        return
    commented = False
    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = line.strip()
        if not s:
            commented = False
        elif s.startswith("#"):
            commented = len(s.lstrip("#").strip()) >= 8
        elif not commented:
            r.add(BLOCK, "SEC-1: .gitleaksignore entry with no reason; put a '# why this is not a secret' "
                  "comment line above it", ".gitleaksignore", n, key=f"ignore-noreason|{s}")


def read_secrets_reviewed(repo: Repo, r: Result) -> dict[tuple[str, str], int]:
    """Parse `.secrets-reviewed`: `<fp12> <path>`, every entry under a comment saying why.

    An entry silences exactly ONE SEC-2 HISTORY finding: one value, identified by `fp12` (the first
    12 hex of SHA-256 of the value itself) at one path. It cannot name a rule, a directory, a glob
    or a pattern, so there is no spelling of it that widens into a blanket exemption, and the value
    hash means an entry written for a fixture cannot be repointed at a different value.

    Three properties are the point, and each has a test in gate/tests/test_gate.py:

      - HISTORY ONLY. A value still present in the HEAD tree is refused: the entry is reported and
        the tree finding stays a BLOCK. Reviewing a fixture you can still fix invites leaving it
        there; the tree is the copy that ships.
      - NEVER A RULE. `read_secrets_reviewed` is consulted by `sweep_history` alone, for a
        (fp12, path) pair. `sweep_tree` only uses it to detect the refusal above, and
        `sweep_change` only to mark a pre-existing report as reviewed: it never unblocks a
        secret the change adds or touches.
      - NEVER SILENT. A matched entry still emits a WARN naming the file and line, so the report
        shows what is being excused. An entry that matches nothing is a note telling you to delete
        it, and a malformed line is a BLOCK, because cannot tell is never a pass.

    This is deliberately NOT `.gitleaksignore`. That file silences SEC-1, the third-party scanner.
    SEC-2 is the stdlib sweep precisely because the gate does not trust one scanner's judgement;
    pointing both at one file would let the weaker check's remedy silence the stronger one. Two
    files means a repo that wants both must make two separate, separately reasoned acts.
    """
    p = repo.root / REVIEWED_FILE
    if not p.is_file():
        return {}
    out: dict[tuple[str, str], int] = {}
    reason_ok = False
    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = line.strip()
        if not s:
            reason_ok = False
            continue
        if s.startswith("#"):
            reason_ok = len(s.lstrip("#").strip()) >= 8
            continue
        parts = s.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{12}", parts[0]):
            r.add(BLOCK, f"SEC-2: {REVIEWED_FILE} line is not `<fp12> <path>`; a fingerprint is the 12 "
                  "lowercase hex characters this gate prints as 'fp12', and a path has no spaces",
                  REVIEWED_FILE, n, key=f"reviewed-badline|{n}")
            continue
        if "\\" in parts[1]:
            r.add(BLOCK, f"SEC-2: {REVIEWED_FILE} entry names a path with a backslash; use the "
                  "forward-slash path git reports, or the entry will never match anything",
                  REVIEWED_FILE, n, key=f"reviewed-backslash|{n}")
            continue
        if not reason_ok:
            r.add(BLOCK, "SEC-2: .secrets-reviewed entry with no reason; put a '# why this is not a "
                  "secret' comment line above it", REVIEWED_FILE, n, key=f"reviewed-noreason|{s}")
        out[(parts[0], parts[1])] = n
    return out


def run_gitleaks(repo: Repo, r: Result, staged: bool = False, change: set[str] | None = None,
                 label: str = "") -> None:
    """change None: every finding blocks (staged, or --whole-repo). Otherwise a finding blocks only when its
    commit is in the change. gitleaks reads each commit's ADDED lines, so a touched line is a hit in the
    commit that touched it. The rest are pre-existing: reported by fingerprint, not blocking (SEC-4)."""
    exe, why = gitleaks_binary()
    if not exe:
        r.cannot(why)
        return
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gl.json"
        cmd = [exe, "git", "--config", str(CONFIG), "--redact", "--no-banner", "--exit-code", "1",
               "--report-format", "json", "--report-path", str(report), "--gitleaks-ignore-path", str(repo.root)]
        if staged:
            cmd += ["--pre-commit", "--staged"]
        else:
            cmd += ["--log-opts=--all"]
        cmd.append(str(repo.root))
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if out.returncode not in (0, 1):
            r.cannot(f"gitleaks exited {out.returncode}: {out.stderr.strip()[-400:]}")
            return
        try:
            rows = json.loads(report.read_text(encoding="utf-8") or "[]") if report.exists() else []
        except json.JSONDecodeError:
            r.cannot("gitleaks report was not valid JSON")
            return
        if out.returncode == 1 and not rows:
            r.cannot("gitleaks reported leaks but wrote no report rows")
            return
    r.notes.append(f"gitleaks {GITLEAKS_VERSION}, estate config, {'staged changes' if staged else 'all refs, full history'}: {len(rows)} finding(s)")
    for row in rows:
        fpr = row.get("Fingerprint", "")
        full = row.get("Commit") or ""
        commit = full[:10]
        if change is not None and full not in change:
            f = r.add(BLOCK, f"SEC-1: pre-existing secret, gitleaks rule {row.get('RuleID')} at commit {commit} "
                      f"(fingerprint {fpr}), outside this change ({label}..HEAD). Not blocking this push: list it in "
                      "the PR body by fingerprint, and treat it as an incident (rotate first)",
                      row.get("File", ""), int(row.get("StartLine") or 0), key=f"gitleaks|{fpr}")
            f.state = PRE_EXISTING
            continue
        scope_note = f" in this change ({label}..HEAD)" if change is not None else ""
        r.add(BLOCK, f"SEC-1: gitleaks rule {row.get('RuleID')} at commit {commit or 'staged'}{scope_note}"
              f" (fingerprint {fpr}). If it is a reviewed fixture, add the fingerprint to .gitleaksignore "
              f"under a comment saying why; if it is real, stop: a secret in history is an incident, not a fix",
              row.get("File", ""), int(row.get("StartLine") or 0), key=f"gitleaks|{fpr}")


# ---------------------------------------------------------------- the stdlib sweep

def env_value(raw: str) -> str:
    """The value of a dotenv line, given everything after '='. As dotenv (Node) reads it: a quoted value is
    the text inside the quotes ('#' included); unquoted, whitespace then '#' starts a comment, so
    `KEY=  # note` is empty, while `KEY=a#b` keeps its '#'."""
    s = raw.strip()
    if s[:1] in ("'", '"'):
        end = s.find(s[0], 1)
        return s[1:end] if end > 0 else s[1:]
    m = re.search(r"\s#", raw)
    return (raw[:m.start()] if m else raw).strip()


def judge_text(path: str, text: str, where: str):
    """Yield (rule, line, fp, message) for one file's text. Pure: no repo access."""
    name = PurePosixPath(path).name
    low = path.lower()
    # committed secrets files (by name), unless they are templates
    # (.pem/.key files are judged by content below: a certificate or public key is not a secret)
    if SECRET_FILE_NAMES.search(path) and not ENV_TEMPLATE.search(path):
        yield ("SEC-3", 1, fp12(path + text[:256]),
               f"SEC-3: secrets file committed ({name}); remove it, rotate what it held, add it to .gitignore")
    if PEM_PRIVATE.search(text):
        for m in re.finditer(r"-----BEGIN [A-Z ]*PRIVATE KEY-----([\s\S]{0,6000}?)-----END", text):
            body = re.sub(r"\s", "", m.group(1))
            if len(body) >= 200:  # truncated test stubs are not keys
                yield ("SEC-2", line_of(text, m.start()), fp12(body), "SEC-2: PEM private key")
    if name.endswith(".json") and '"private_key"' in text and "BEGIN" in text:
        yield ("SEC-3", 1, fp12(text[:512]), "SEC-3: service-account style JSON with a private_key")
    if name == ".npmrc":
        for m in re.finditer(r"(?m)_authToken\s*=\s*(\S+)", text):
            if not m.group(1).startswith("${") and not is_placeholder(m.group(1)):
                yield ("SEC-2", line_of(text, m.start()), fp12(m.group(1)), "SEC-2: npm auth token in .npmrc")
    # DSNs with a password
    for m in DSN_RE.finditer(text):
        pw = m.group(3)
        if is_placeholder(pw) or pw.startswith(("$", "{", "%", "<")) or "${" in pw:
            continue
        yield ("SEC-2", line_of(text, m.start()), fp12(pw),
               f"SEC-2: {m.group(1)} URL carries a password (user {m.group(2)!r}); read it from the environment or the vault")
    # k8s Secret manifests: decode data:, read stringData:
    if low.endswith((".yaml", ".yml", ".json")) and K8S_KIND.search(text):
        yield from _k8s(text)
    # .env templates: secret-shaped keys must hold placeholders
    if ENV_TEMPLATE.search(path) or name.startswith(".env"):
        for n, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
            if not m or not SECRETISH_KEY.search(m.group(1)) or NOT_A_VALUE_KEY.search(m.group(1)):
                continue
            val = env_value(m.group(2))
            if len(val) < 8 or is_placeholder(val) or val.startswith(("$", "<", "{")) or "${" in val:
                continue
            if "://" in val:
                continue  # a URL: the DSN rule above judges its password
            if shannon(val) >= 3.0 or re.search(r"\d", val) and re.search(r"[A-Za-z]", val):
                yield ("SEC-2", n, fp12(val), f"SEC-2: {m.group(1)} in an env template holds a real-looking value; "
                       "templates carry placeholders only")


def _k8s(text: str):
    for doc in re.split(r"(?m)^---\s*$", text):
        if not K8S_KIND.search(doc):
            continue
        offset = text.find(doc)
        block = None
        for n, line in enumerate(doc.splitlines(), 1):
            if re.match(r"^(data|stringData):\s*$", line):
                block = line.split(":")[0]
                continue
            if block and re.match(r"^\S", line):
                block = None
            if not block:
                continue
            m = re.match(r"^\s+([\w.-]+):\s*['\"]?([^'\"#]*?)['\"]?\s*(#.*)?$", line)
            if not m or not m.group(2):
                continue
            raw = m.group(2).strip()
            if raw in ("|", ">", "|-", ">-"):
                continue
            if block == "data":
                try:
                    val = base64.b64decode(raw, validate=True).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
            else:
                val = raw
            if is_placeholder(val) or val.startswith(("${", "{{")) or len(val) < 4:
                continue
            ln = line_of(text, offset) + n - 1
            yield ("SEC-2", ln, fp12(val),
                   f"SEC-2: k8s Secret {block}.{m.group(1)} holds a real value"
                   f"{' (base64-decoded)' if block == 'data' else ''}; use an external secret store or sealed secret")


def sweep_tree(repo: Repo, r: Result, files: list[str] | None = None,
               reviewed: dict[tuple[str, str], int] | None = None,
               used: set[tuple[str, str]] | None = None) -> None:
    reviewed = reviewed or {}
    for rel in files if files is not None else repo.all_tracked():
        text = repo.text(rel)
        if text is None:
            if SECRET_FILE_NAMES.search(rel) and not ENV_TEMPLATE.search(rel):
                r.add(BLOCK, "SEC-3: binary secrets file committed (keystore or certificate bundle)", rel, 1,
                      key=f"tree|SEC-3|{rel}")
            continue
        for rule, ln, f, msg in judge_text(rel, text, "tree"):
            if (f, rel) in reviewed:
                if used is not None:
                    used.add((f, rel))
                msg += (f" [{REVIEWED_FILE} has an entry for this value at this path, but a reviewed entry "
                        "excuses HISTORY only; the value is in the tree now, so fix it here and let the "
                        "history entry stand on its own]")
            r.add(BLOCK, f"{msg} [fp12 {f}]", rel, ln, key=f"tree|{rule}|{rel}|{f}")


def read_blobs(repo: Repo, wanted: dict[str, str]):
    """Yield (sha, path, text) for each text blob in {sha: path}; binaries and blobs over 2 MB are skipped."""
    wanted = {sha: p for sha, p in wanted.items() if PurePosixPath(p).suffix.lower() not in SKIP_SUFFIXES}
    if not wanted:
        return
    proc = subprocess.Popen(["git", "-C", str(repo.root), "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    assert proc.stdin and proc.stdout
    try:
        for sha, path in wanted.items():
            proc.stdin.write((sha + "\n").encode())
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) < 3:
                continue
            size = int(header[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            if header[1] != b"blob" or size > 2_000_000 or b"\0" in data[:8192]:
                continue
            yield sha, path, data.decode("utf-8", "replace")
    finally:
        proc.stdin.close()
        proc.wait()


def sweep_history(repo: Repo, r: Result, reviewed: dict[tuple[str, str], int] | None = None,
                  used: set[tuple[str, str]] | None = None) -> None:
    """Every blob reachable from any ref, once. HEAD-tree hits are already reported by sweep_tree."""
    reviewed = reviewed or {}
    try:
        listing = repo.git("rev-list", "--objects", "--all")
    except RuntimeError as e:
        r.cannot(f"history sweep: {e}")
        return
    head_blobs = set()
    try:
        for line in repo.git("ls-tree", "-r", "HEAD").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                head_blobs.add(parts[2])
    except RuntimeError:
        pass
    wanted: dict[str, str] = {}
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        if path and sha not in wanted and sha not in head_blobs:
            wanted[sha] = path
    if not wanted:
        r.notes.append("history sweep: no blobs outside the HEAD tree")
        return
    n_scanned = 0
    warned: set[tuple[str, str, str]] = set()
    for sha, path, text in read_blobs(repo, wanted):
        n_scanned += 1
        for rule, ln, f, msg in judge_text(path, text, "history"):
            k = (f, path)
            if k in reviewed:
                # Already excused. Still reported, so the suppression is visible in the run rather
                # than inferred from a finding's absence; one WARN per value and path, not per blob.
                if used is not None:
                    used.add(k)
                if (rule, path, f) not in warned:
                    warned.add((rule, path, f))
                    r.add(WARN, f"{msg} [in history only, blob {sha[:10]}; fp12 {f}]. Reviewed as a fixture "
                          f"at {REVIEWED_FILE}:{reviewed[k]}; not blocking", path, ln,
                          key=f"reviewed-hist|{rule}|{path}|{f}")
                continue
            r.add(BLOCK, f"{msg} [in history only, blob {sha[:10]}; fp12 {f}]. A secret in history is an incident: "
                  f"rotate first, then decide on a history rewrite. If it is a reviewed fixture, put "
                  f"'{f} {path}' in {REVIEWED_FILE} under a comment saying why",
                  path, ln, key=f"hist|{rule}|{path}|{f}")
    r.notes.append(f"history sweep: {n_scanned} blob(s) outside HEAD scanned")


def tree_blobs(repo: Repo, rev: str) -> dict[str, str]:
    """{blob sha: path} of one commit's tree (regular files only)."""
    out: dict[str, str] = {}
    try:
        raw = repo.git("ls-tree", "-r", "-z", rev)
    except RuntimeError as e:
        raise scope.CannotTell(str(e)) from e
    for entry in raw.split("\0"):
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) >= 3 and parts[1] == "blob" and parts[0].startswith("100"):
            out.setdefault(parts[2], path)
    return out


def sweep_change(repo: Repo, r: Result, opts, reviewed: dict[tuple[str, str], int] | None = None,
                 used: set[tuple[str, str]] | None = None) -> tuple[set[str], str]:
    """The stdlib sweep scoped to base..HEAD plus the working tree (SEC-4; the rules are in secrets_scope).
    Returns (the range's commits, the base label) for gitleaks. Raises scope.CannotTell.

    A `.secrets-reviewed` entry never changes what blocks here. A finding the change adds or touches
    blocks whatever the file says; an entry can only mark a PRE-EXISTING report as reviewed (which
    does not block either way), so the file stays visible in the run and its unmatched entries can
    still be named."""
    reviewed = reviewed or {}
    base, label = scope.resolve_base(repo, getattr(opts, "base_ref", None))
    commits = scope.range_commits(repo, base)
    no_history = getattr(opts, "no_history", False)
    r.notes.append(f"change: merge-base of {label} and HEAD ({base[:10]}), {len(commits)} commit(s) in range, plus "
                   "the working tree. A secret the change adds or touches blocks; one already there is reported")

    # what was already there: every blob reachable from base (its tree only, under --no-history)
    base_blobs = tree_blobs(repo, base) if no_history else scope.reachable_blobs(repo, base)
    base_fps: set[tuple[str, str]] = set()
    pre: dict[tuple[str, str, str], tuple[str, int, str]] = {}
    for sha, path, text in read_blobs(repo, base_blobs):
        for rule, ln, f, msg in judge_text(path, text, "history"):
            base_fps.add((rule, f))
            pre.setdefault((rule, path, f), (msg, ln, f"at {label}, blob {sha[:10]}"))

    blocked: set[tuple[str, str, str]] = set()

    def hit(rule: str, path: str, ln: int, f: str, msg: str, where: str) -> None:
        if (rule, path, f) in blocked:
            return
        blocked.add((rule, path, f))
        r.add(BLOCK, f"{msg} [this change: {where}; fp12 {f}]. Remove it before pushing; if it was ever real, it "
              "is an incident: rotate first", path, ln, key=f"change|{rule}|{path}|{f}")

    # every commit in the range, history-only ones included
    if not no_history:
        for c in commits:
            ps, changed = scope.commit_changes(repo, c)
            for sha, path, text in read_blobs(repo, {b: p for p, b in changed.items()}):
                hits = list(judge_text(path, text, "history"))
                if not hits:
                    continue
                added = scope.added_in_commit(repo, ps, c, path)
                for rule, ln, f, msg in hits:
                    if scope.blocks(rule, f, ln, added, base_fps):
                        hit(rule, path, ln, f, msg, f"commit {c[:10]}")

    # the working tree (and the index) against base
    for rel in scope.tree_changes(repo, base):
        text = repo.text(rel)
        if text is None:
            if repo.exists(rel) and SECRET_FILE_NAMES.search(rel) and not ENV_TEMPLATE.search(rel):
                hit("SEC-3", rel, 1, fp12(rel), "SEC-3: binary secrets file committed (keystore or certificate bundle)",
                    f"working tree against {label}")
            continue
        hits = list(judge_text(rel, text, "tree"))
        if not hits:
            continue
        added = scope.added_lines(repo, base, None, rel)
        for rule, ln, f, msg in hits:
            if scope.blocks(rule, f, ln, added, base_fps):
                hit(rule, rel, ln, f, msg, f"working tree against {label}")

    # other refs (stale branches, refs/pull/*): never this change, always reported
    if not no_history:
        other = scope.reachable_blobs(repo, "--all", "--not", "HEAD", base)
        for sha, path, text in read_blobs(repo, {b: p for b, p in other.items() if b not in base_blobs}):
            for rule, ln, f, msg in judge_text(path, text, "history"):
                pre.setdefault((rule, path, f), (msg, ln, f"on another ref, blob {sha[:10]}"))

    for (rule, path, f), (msg, ln, where) in pre.items():
        if (rule, path, f) in blocked:
            continue
        note = ""
        if (f, path) in reviewed:
            if used is not None:
                used.add((f, path))
            note = f" Reviewed as a fixture at {REVIEWED_FILE}:{reviewed[(f, path)]}."
        fnd = r.add(BLOCK, f"{msg} [pre-existing: {where}; fp12 {f}]. Not blocking this push: list it in the PR "
                    f"body by fingerprint, and treat it as an incident (rotate first).{note}", path, ln,
                    key=f"pre|{rule}|{path}|{f}")
        fnd.state = PRE_EXISTING
    return set(commits), label


def run(repo: Repo, opts) -> Result:
    r = Result("secrets", "Secrets: gitleaks (estate rules) + k8s/DSN/env/secrets-file sweep, tree and history")
    ignore_file_problems(repo, r)
    reviewed = read_secrets_reviewed(repo, r)
    used: set[tuple[str, str]] = set()
    if getattr(opts, "files", None):
        sweep_tree(repo, r, opts.files, reviewed, used)
        if getattr(opts, "staged", False):
            run_gitleaks(repo, r, staged=True)
        return r
    if getattr(opts, "whole_repo", False):
        r.notes.append("--whole-repo: every commit of every ref is the change, so every finding blocks")
        sweep_tree(repo, r, reviewed=reviewed, used=used)
        if not getattr(opts, "no_history", False):
            sweep_history(repo, r, reviewed, used)
            _unmatched(r, reviewed, used)
        run_gitleaks(repo, r)
        return r
    try:
        change, label = sweep_change(repo, r, opts, reviewed, used)
    except scope.CannotTell as e:
        return r.cannot(f"cannot tell the change from what was already there: {e}")
    if not getattr(opts, "no_history", False):
        _unmatched(r, reviewed, used)
    run_gitleaks(repo, r, change=change, label=label)
    pre = sum(1 for f in r.findings if f.state == PRE_EXISTING)
    if pre:
        r.notes.append(f"{pre} pre-existing secret finding(s) outside this change: not blocking, listed by "
                       "fingerprint below; name them in the PR body (repo-merge-gate.md SEC-4)")
    return r


def _unmatched(r: Result, reviewed: dict[tuple[str, str], int], used: set[tuple[str, str]]) -> None:
    # An entry that matched nothing is not a finding (the value may simply have been fixed and
    # the entry forgotten), but leaving it means the file no longer describes the repo.
    for f, path in sorted(set(reviewed) - used):
        r.notes.append(f"{REVIEWED_FILE}: '{f} {path}' (line {reviewed[(f, path)]}) matches nothing now; "
                       "delete the entry")
