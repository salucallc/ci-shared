"""SEC-9: code that generates keys has a test proving the key never reaches a log.

Tony's review, 2026-10-22: a generated key printed in logs. The check finds key generation
(secrets.token_*, os.urandom, Fernet.generate_key, generate_private_key, SigningKey.generate,
crypto.randomBytes, generateKeyPair) whose result lands in a key-like name, or that sits in a
function named like create/generate/mint/issue/rotate *key/token/secret*. Then it requires at
least one test whose name or file says redaction (redact, not_logged, no_secret, leak, mask).
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from ..core import BLOCK, Repo, Result, is_test_path

GEN = re.compile(r"\b(secrets\.token_(hex|urlsafe|bytes)|os\.urandom|Fernet\.generate_key|generate_private_key|"
                 r"SigningKey\.generate|PrivateKey\.generate|crypto\.randomBytes|generateKeyPair(Sync)?|"
                 r"crypto\.subtle\.generateKey|nacl\.utils\.random)\s*\(")
KEYISH = re.compile(r"(?i)(api_?key|apikey|secret|token|password|soulkey|private_?key|signing_?key|credential)")
FUNC_KEYISH = re.compile(r"(?i)\b(def|function|async function|const)\s+\w*(create|generate|mint|issue|rotate|new)_?\w*"
                         r"(key|token|secret|credential|soulkey)\w*")
REDACT_TEST = re.compile(r"(?i)(def|it\(|test\(|describe\()\s*['\"]?[\w ]*(redact|not_logged|not logged|no_secret|no secret|"
                         r"never_logged|never logged|leak|mask|secret_not|key_not_in)")


def run(repo: Repo, opts) -> Result:
    r = Result("log-redaction", "Key-generating code has a test that the key never reaches a log")
    files = repo.tracked()
    sites = []
    for rel in files:
        if is_test_path(rel.lower()) or PurePosixPath(rel).suffix.lower() not in (".py", ".js", ".ts", ".mjs", ".cjs"):
            continue
        text = repo.text(rel) or ""
        lines = text.splitlines()
        for m in GEN.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            line = lines[ln - 1]
            lhs = line.split("=")[0] if "=" in line.split("(")[0] else ""
            fn_ctx = "\n".join(lines[max(0, ln - 30): ln])
            fns = FUNC_KEYISH.findall(fn_ctx)
            if KEYISH.search(lhs) or fns or re.search(r"(?i)return\s+.*" + re.escape(m.group(1)), line) and fns:
                sites.append((rel, ln))
    if not sites:
        return r.na("no key-generating code found")
    tests = [f for f in files if is_test_path(f.lower())]
    has = any(re.search(r"(?i)redact|leak", PurePosixPath(t).name) for t in tests) or \
        any(REDACT_TEST.search(repo.text(t) or "") for t in tests)
    if not has:
        for rel, ln in sites:
            r.add(BLOCK, "SEC-9: generates a key, and no test proves keys never reach a log (add a test named like "
                  "test_key_not_logged that captures log output and asserts the key is absent)", rel, ln,
                  key=f"{rel}|keygen")
    else:
        r.notes.append(f"{len(sites)} key-generation site(s); a redaction test exists")
    return r
