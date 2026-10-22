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

from ..core import BLOCK, Repo, Result, fp12, is_placeholder, line_of, shannon

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


def run_gitleaks(repo: Repo, r: Result, staged: bool = False) -> None:
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
        commit = (row.get("Commit") or "")[:10]
        r.add(BLOCK, f"SEC-1: gitleaks rule {row.get('RuleID')} at commit {commit or 'staged'}"
              f" (fingerprint {fpr}). If it is a reviewed fixture, add the fingerprint to .gitleaksignore "
              f"under a comment saying why; if it is real, stop: a secret in history is an incident, not a fix",
              row.get("File", ""), int(row.get("StartLine") or 0), key=f"gitleaks|{fpr}")


# ---------------------------------------------------------------- the stdlib sweep

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
            m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
            if not m or not SECRETISH_KEY.search(m.group(1)) or NOT_A_VALUE_KEY.search(m.group(1)):
                continue
            val = m.group(2).split(" #")[0].strip().strip("'\"")
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


def sweep_tree(repo: Repo, r: Result, files: list[str] | None = None) -> None:
    for rel in files if files is not None else repo.all_tracked():
        text = repo.text(rel)
        if text is None:
            if SECRET_FILE_NAMES.search(rel) and not ENV_TEMPLATE.search(rel):
                r.add(BLOCK, "SEC-3: binary secrets file committed (keystore or certificate bundle)", rel, 1,
                      key=f"tree|SEC-3|{rel}")
            continue
        for rule, ln, f, msg in judge_text(rel, text, "tree"):
            r.add(BLOCK, f"{msg} [fp12 {f}]", rel, ln, key=f"tree|{rule}|{rel}|{f}")


def sweep_history(repo: Repo, r: Result) -> None:
    """Every blob reachable from any ref, once. HEAD-tree hits are already reported by sweep_tree."""
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
            if PurePosixPath(path).suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".woff2"):
                continue
            wanted[sha] = path
    if not wanted:
        r.notes.append("history sweep: no blobs outside the HEAD tree")
        return
    proc = subprocess.Popen(["git", "-C", str(repo.root), "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    assert proc.stdin and proc.stdout
    n_scanned = 0
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
        n_scanned += 1
        text = data.decode("utf-8", "replace")
        for rule, ln, f, msg in judge_text(path, text, "history"):
            r.add(BLOCK, f"{msg} [in history only, blob {sha[:10]}; fp12 {f}]. A secret in history is an incident: "
                  "rotate first, then decide on a history rewrite", path, ln, key=f"hist|{rule}|{path}|{f}")
    proc.stdin.close()
    proc.wait()
    r.notes.append(f"history sweep: {n_scanned} blob(s) outside HEAD scanned")


def run(repo: Repo, opts) -> Result:
    r = Result("secrets", "Secrets: gitleaks (estate rules) + k8s/DSN/env/secrets-file sweep, tree and history")
    ignore_file_problems(repo, r)
    if getattr(opts, "files", None):
        sweep_tree(repo, r, opts.files)
        if getattr(opts, "staged", False):
            run_gitleaks(repo, r, staged=True)
        return r
    sweep_tree(repo, r)
    if not getattr(opts, "no_history", False):
        sweep_history(repo, r)
    run_gitleaks(repo, r)
    return r
