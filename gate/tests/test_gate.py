"""Tests for the merge gate. Every check has at least one fixture that MUST fail and one that
must pass, and the must-fail fixtures are the proof that each check can fail (verification
rule 2). The gate runs as a subprocess against a throwaway git repo, so these tests judge its
behaviour, not its internals.

Secret-shaped strings are built at run time (never one literal), so this file is not itself a
leak and GitHub push protection has nothing to match. Run:

    python -m unittest discover -s gate/tests -v

The secrets tests need the pinned gitleaks: `python -m gate bootstrap --no-audit` locally, or
GATE_GITLEAKS pointing at it. Without it they FAIL (cannot tell is never a pass), not skip.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _rnd
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # the ci-shared checkout; `python -m gate` runs from here
GIT_ID = ["-c", "user.email=gate-test@example.invalid", "-c", "user.name=gate test", "-c", "commit.gpgsign=false",
          "-c", "core.autocrlf=false"]


def rnd(n: int = 24) -> str:
    return "".join(_rnd.choice("ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789") for _ in range(n))


class GateRepo:
    def __init__(self, files: dict[str, str | bytes], extra_commits: list[dict] | None = None):
        self.td = tempfile.TemporaryDirectory(prefix="repogate-")
        self.path = Path(self.td.name)
        self._git("init", "-q", "-b", "main")
        self.write(files)
        self.commit("initial")
        for c in extra_commits or []:
            self.write({k: v for k, v in c.items() if v is not None})
            for k, v in c.items():
                if v is None:
                    self._git("rm", "-q", k)
            self.commit("change")

    def _git(self, *args):
        subprocess.run(["git", *GIT_ID, "-C", str(self.path), *args], check=True, capture_output=True)

    def _out(self, *args) -> str:
        """stdout of a git command, for the tests that need a sha rather than a side effect."""
        return subprocess.run(["git", *GIT_ID, "-C", str(self.path), *args], check=True,
                              capture_output=True, text=True, encoding="utf-8").stdout.strip()

    def write(self, files):
        for rel, content in files.items():
            p = self.path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_bytes(textwrap.dedent(content).lstrip("\n").encode("utf-8"))

    def commit(self, msg):
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "-m", msg)

    def gate(self, *args, env=None) -> tuple[int, str, dict]:
        out_json = self.path.parent / f"{self.path.name}-gate.json"
        e = dict(os.environ, PYTHONIOENCODING="utf-8", GITHUB_ACTIONS="false")
        e.pop("GITHUB_STEP_SUMMARY", None)
        if env:
            e.update(env)
        res = subprocess.run([sys.executable, "-m", "gate", "run", "--repo", str(self.path), "--json", str(out_json),
                              "--today", "2026-10-22", *args], cwd=ROOT, capture_output=True, text=True,
                             encoding="utf-8", env=e)
        data = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else {}
        if out_json.exists():
            out_json.unlink()
        return res.returncode, res.stdout + res.stderr, data

    def close(self):
        self.td.cleanup()


def status_of(data: dict, check: str) -> str:
    for c in data.get("checks", []):
        if c["check"] == check:
            return c["status"]
    return "absent"


def open_blocks(data: dict, check: str) -> list[str]:
    for c in data.get("checks", []):
        if c["check"] == check:
            return [f["message"] for f in c["findings"] if f["severity"] == "block" and f["state"] == "open"]
    return []


CLEAN_PY = {
    "README.md": "# demo\n\nA demo.\n\n## Status\n\nExperimental.\n\n## License\n\nMIT, see LICENSE.\n",
    "LICENSE": "MIT License\n\nCopyright (c) 2026 Saluca\n\nPermission is hereby granted, free of charge, to any person "
               "obtaining a copy of this software.\n",
    "src/calc.py": "def add(a, b):\n    return a + b\n",
    "tests/test_calc.py": "from src.calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
    ".gitattributes": "* text=auto eol=lf\n",
}


class Base(unittest.TestCase):
    def run_gate(self, files, *args, extra=None, env=None):
        repo = GateRepo(files, extra)
        self.addCleanup(repo.close)
        return repo.gate(*args, env=env)

    def assertFails(self, files, check, needle, *args, extra=None, env=None):
        code, out, data = self.run_gate(files, "--only", check, "--offline", "--no-audit", *args, extra=extra, env=env)
        self.assertEqual(code, 1, f"{check} should FAIL on this fixture; output:\n{out}")
        self.assertTrue(any(needle in m for m in open_blocks(data, check)), f"expected {needle!r} in:\n{out}")
        return out

    def assertPasses(self, files, check, *args, extra=None, env=None, allow=("pass", "warn", "n/a")):
        code, out, data = self.run_gate(files, "--only", check, "--offline", "--no-audit", *args, extra=extra, env=env)
        self.assertIn(status_of(data, check), allow, out)
        self.assertEqual(code, 0, out)
        return data


def gitleaks_env() -> dict:
    env = {}
    if not os.environ.get("GATE_GITLEAKS"):
        exe = Path.home() / ".cache" / "saluca-gate" / "gitleaks-8.30.1" / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
        if exe.is_file():
            env["GATE_GITLEAKS"] = str(exe)
    return env


class Secrets(Base):
    """What the scan finds. These fixtures have no base, so they run with --whole-repo: every commit
    of every ref is the change, and every finding blocks. SecretsScope covers base..HEAD."""

    @classmethod
    def setUpClass(cls):
        cls.env = gitleaks_env()

    def run_gate(self, files, *args, extra=None, env=None):
        return super().run_gate(files, *args, "--whole-repo", extra=extra, env=env)

    def test_canary_with_fake_prefix_fails(self):
        canary = "SALUCA_GATE_" + "CANARY_" + rnd(28)
        self.assertFails(dict(CLEAN_PY, **{"src/conf.py": f'TOKEN = "{canary}"\n'}), "secrets", "estate-gate-canary",
                         env=self.env)

    def test_secret_removed_later_still_fails_from_history(self):
        canary = "SALUCA_GATE_" + "CANARY_" + rnd(28)
        self.assertFails(dict(CLEAN_PY, **{"src/conf.py": f'TOKEN = "{canary}"\n'}), "secrets", "estate-gate-canary",
                         extra=[{"src/conf.py": "TOKEN = None\n"}], env=self.env)

    def test_k8s_secret_base64_value_fails(self):
        val = base64.b64encode(("pw-" + rnd(20)).encode()).decode()
        doc = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  DB_PASSWORD: {val}\n"
        self.assertFails(dict(CLEAN_PY, **{"k8s/secrets.yaml": doc}), "secrets", "k8s Secret data.DB_PASSWORD",
                         env=self.env)

    def test_k8s_secret_placeholder_passes(self):
        val = base64.b64encode(b"CHANGEME").decode()
        doc = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  DB_PASSWORD: {val}\n"
        self.assertPasses(dict(CLEAN_PY, **{"k8s/secrets.yaml": doc}), "secrets", env=self.env)

    def test_dsn_password_in_env_example_fails(self):
        dsn = "postgres" + "ql://svc:" + rnd(16) + "@db.internal:5432/app"
        self.assertFails(dict(CLEAN_PY, **{".env.example": f"DATABASE_URL={dsn}\n"}), "secrets", "postgresql URL carries a password",
                         env=self.env)

    def test_dsn_placeholder_passes(self):
        self.assertPasses(dict(CLEAN_PY, **{".env.example": "DATABASE_URL=postgresql://app:${DB_PASSWORD}@db:5432/app\n"
                                                             "API_KEY=your-api-key\n"}), "secrets", env=self.env)

    def test_env_template_key_path_passes(self):
        # pantheon apps/platform-api/.env.example, 2026-10-22 dry run: a path to a key, not a key
        self.assertPasses(dict(CLEAN_PY, **{".env.example": "SOULAUTH_JWT_PRIVATE_KEY_PATH=./keys/private.pem\n"}), "secrets",
                          env=self.env)

    def test_env_template_empty_value_with_inline_comment_passes(self):
        # tiresias-web .env.example, 2026-10-22: the value is empty; ' # ...' is a dotenv inline comment
        line = "WORKOS_COOKIE_PASSWORD=  # min 32 chars, generate with: openssl rand -hex 32\n"
        self.assertPasses(dict(CLEAN_PY, **{".env.example": line}), "secrets", env=self.env)

    def test_env_template_value_with_inline_comment_fails(self):
        line = f"WORKOS_COOKIE_PASSWORD={rnd(32)}  # min 32 chars\n"
        self.assertFails(dict(CLEAN_PY, **{".env.example": line}), "secrets", "WORKOS_COOKIE_PASSWORD in an env template",
                         env=self.env)

    def test_env_template_hash_inside_value_is_a_value(self):
        # no whitespace before '#', or inside quotes: part of the value, not a comment
        for line in (f"APP_SECRET={rnd(12)}#{rnd(12)}\n", f'APP_SECRET="{rnd(12)} #{rnd(12)}"\n'):
            with self.subTest(line=line[:12]):
                self.assertFails(dict(CLEAN_PY, **{".env.example": line}), "secrets", "APP_SECRET in an env template",
                                 env=self.env)

    def test_committed_env_file_fails(self):
        self.assertFails(dict(CLEAN_PY, **{".env": "DEBUG=1\n"}), "secrets", "secrets file committed", env=self.env)

    def test_unreasoned_gitleaksignore_fails(self):
        self.assertFails(dict(CLEAN_PY, **{".gitleaksignore": "abc123:src/x.py:generic-api-key:3\n"}), "secrets",
                         ".gitleaksignore entry with no reason", env=self.env)

    def test_secret_shaped_text_in_gitleaksignore_passes(self):
        # The remedy file SEC-1 prescribes must not itself be a finding. saluca-campus, 2026-10-26:
        # a reviewed false positive was explained by quoting the JSON the rule matched, and the gate
        # reported .gitleaksignore:9 and :10 as `generic-api-key`. A repo-side fingerprint for that
        # mints a new matching line in the same file, so it recurses: the path is allowlisted in
        # gate/gitleaks.toml instead. The canary here is the strongest case - a shape NO rule can
        # mistake for prose - and the pass is what proves the path allowlist reaches gitleaks.
        canary = "SALUCA_GATE_" + "CANARY_" + rnd(28)
        text = ("# the canary quoted below is a reviewed test fixture, not a credential\n"
                f"# {canary}\n"
                "abc123:src/x.py:generic-api-key:3\n")
        self.assertPasses(dict(CLEAN_PY, **{".gitleaksignore": text}), "secrets", env=self.env)

    def test_secret_shaped_text_beside_gitleaksignore_still_fails(self):
        # The positive control for the allowlist, and the reason its regex is anchored at both ends:
        # a file that merely LOOKS like the remedy file must still be scanned, or the allowlist is a
        # hole a secret can be parked in. Same canary, one directory deep and one suffix off.
        canary = "SALUCA_GATE_" + "CANARY_" + rnd(28)
        for path in ("notes/.gitleaksignore.bak", "old/gitleaksignore"):
            with self.subTest(path=path):
                self.assertFails(dict(CLEAN_PY, **{path: f"TOKEN = '{canary}'\n"}), "secrets",
                                 "estate-gate-canary", env=self.env)

    # ---- .secrets-reviewed: the SEC-2 history fixture path -------------------------------
    # The k8s Secret shape is used throughout because gitleaks CANNOT see it (its
    # kubernetes-secret-yaml rule is disabled in gate/gitleaks.toml, since it flags base64
    # placeholders as loudly as real values), so these fixtures isolate SEC-2 from SEC-1.

    @staticmethod
    def _k8s(value: str) -> str:
        # The key is deliberately not password-shaped: gitleaks' generic-api-key rule keys off the
        # name, so `DB_PASSWORD: <base64>` is an SEC-1 finding and would drown the SEC-2 arm these
        # fixtures are about. The gate's k8s judge decodes whatever the key is called.
        b64 = base64.b64encode(value.encode()).decode()
        return f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  P: {b64}\n"

    @staticmethod
    def _fp(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]

    def test_reviewed_fixture_in_history_passes(self):
        # The whole point of .secrets-reviewed: a value that IS a fixture, present only in an
        # older blob, is excused by one reviewed line, and the excuse still shows in the report.
        val = "pw-" + rnd(20)
        reviewed = ("# Reviewed test fixture, not a credential: it is a synthetic value a test injects\n"
                    "# to prove the k8s Secret judge decodes data: and reports it. See tests/test_db.py.\n"
                    f"{self._fp(val)} k8s/secrets.yaml\n")
        files = dict(CLEAN_PY, **{"k8s/secrets.yaml": self._k8s(val)})
        data = self.assertPasses(files, "secrets",
                                 extra=[{"k8s/secrets.yaml": self._k8s("CHANGEME"),
                                         ".secrets-reviewed": reviewed}], env=self.env)
        blocks = open_blocks(data, "secrets")
        self.assertEqual(blocks, [], f"a reviewed history fixture must not block:\n{blocks}")
        text = json.dumps(data)
        self.assertIn("Reviewed as a fixture", text, "the excuse must be visible, not silent")

    def test_unreviewed_fixture_in_history_still_fails(self):
        # Negative control for the test above: the same shape and the same commits, with no
        # .secrets-reviewed entry, must BLOCK. Without this, a passing review test proves nothing.
        val = "pw-" + rnd(20)
        files = dict(CLEAN_PY, **{"k8s/secrets.yaml": self._k8s(val)})
        self.assertFails(files, "secrets", "in history only",
                         extra=[{"k8s/secrets.yaml": self._k8s("CHANGEME")}], env=self.env)

    def test_reviewed_entry_for_a_value_still_in_the_tree_is_refused(self):
        # A reviewed entry excuses history only. Reviewing a value you can still delete invites
        # leaving it in the tree, which is the copy that ships, so the entry is refused loudly and
        # the tree finding stands.
        val = "pw-" + rnd(20)
        reviewed = ("# Reviewed test fixture, not a credential: this is synthetic test data.\n"
                    f"{self._fp(val)} k8s/secrets.yaml\n")
        self.assertFails(dict(CLEAN_PY, **{"k8s/secrets.yaml": self._k8s(val),
                                           ".secrets-reviewed": reviewed}), "secrets",
                         "excuses HISTORY only", env=self.env)

    def test_reviewed_entry_without_a_reason_fails(self):
        self.assertFails(dict(CLEAN_PY, **{".secrets-reviewed": f"{'0' * 12} src/x.py\n"}), "secrets",
                         ".secrets-reviewed entry with no reason", env=self.env)

    def test_reviewed_entry_that_is_not_a_fingerprint_fails(self):
        for bad in ("some-rule src/x.py", f"{'A' * 12} src/x.py", "0" * 12):
            with self.subTest(bad=bad):
                self.assertFails(dict(CLEAN_PY, **{".secrets-reviewed": "# reviewed synthetic test data\n"
                                                                       f"{bad}\n"}), "secrets",
                                 "is not `<fp12> <path>`", env=self.env)

    def test_reviewed_entry_that_matches_nothing_is_noted(self):
        # Harmless but rotten: the file stops describing the repo. A note, not a block, because the
        # value may simply have been fixed and the entry forgotten.
        text = ("# Reviewed test fixture, not a credential: synthetic value a test injects.\n"
                f"{'0' * 12} src/gone.py\n")
        data = self.assertPasses(dict(CLEAN_PY, **{".secrets-reviewed": text}), "secrets", env=self.env)
        self.assertIn("matches nothing now", json.dumps(data), "a stale entry must be reported, not silently ignored")

    def test_a_secret_parked_in_the_review_file_still_fails(self):
        # The remedy file must not become a hiding place. gitleaks cannot see a k8s Secret value,
        # but SEC-2's own judge reads every tracked file by content, so a real-looking DSN in a
        # comment here is still a finding.
        dsn = "postgres" + "ql://svc:" + rnd(16) + "@db.internal:5432/app"
        text = ("# Reviewed test fixture, not a credential: see the note in the runbook.\n"
                f"# {dsn}\n" + f"{'0' * 12} src/gone.py\n")
        self.assertFails(dict(CLEAN_PY, **{".secrets-reviewed": text}), "secrets",
                         "URL carries a password", env=self.env)

    def test_missing_gitleaks_is_cannot_tell(self):
        home = tempfile.mkdtemp(prefix="repogate-home-")
        env = {"GATE_GITLEAKS": str(Path(home) / "nope"), "HOME": home, "USERPROFILE": home,
               "PATH": os.path.dirname(sys.executable) + os.pathsep + os.path.dirname(_git_exe())}
        code, out, data = self.run_gate(CLEAN_PY, "--only", "secrets", "--offline", env=env)
        self.assertEqual(code, 2, out)
        self.assertEqual(status_of(data, "secrets"), "cannot-tell", out)

    def test_clean_repo_passes(self):
        self.assertPasses(CLEAN_PY, "secrets", env=self.env, allow=("pass",))


def canary() -> str:
    return "SALUCA_GATE_" + "CANARY_" + rnd(28)


def k8s_secret(*pairs: tuple[str, str]) -> str:
    lines = "".join(f"  {k}: {base64.b64encode(v.encode()).decode()}\n" for k, v in pairs)
    return f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n{lines}"


def findings(data: dict, check: str, state: str) -> list[dict]:
    for c in data.get("checks", []):
        if c["check"] == check:
            return [f for f in c["findings"] if f["severity"] == "block" and f["state"] == state]
    return []


class SecretsScope(Base):
    """The amended rule (estate-rules#8, repo-merge-gate.md SEC-4): a secret blocks when the change
    base..HEAD adds or touches it, in the tree or in any commit of the range; a secret that was
    already there is reported, by fingerprint and never by value, and does not block. No base that
    can be resolved is cannot tell."""

    @classmethod
    def setUpClass(cls):
        cls.env = gitleaks_env()

    def repo(self, files: dict) -> GateRepo:
        r = GateRepo(files)
        self.addCleanup(r.close)
        return r

    def step(self, r: GateRepo, files: dict, msg: str = "change") -> None:
        r.write({k: v for k, v in files.items() if v is not None})
        for k, v in files.items():
            if v is None:
                r._git("rm", "-q", k)
        r.commit(msg)

    def scoped(self, r: GateRepo, *args):
        return r.gate("--only", "secrets", "--offline", "--no-audit", *args, env=self.env)

    def assertNoValue(self, out: str, *values: str):
        for v in values:
            self.assertNotIn(v, out, "a secret value reached the output")

    def test_new_secret_in_changed_file_blocks_and_old_one_is_reported(self):
        old, new = canary(), canary()
        r = self.repo(dict(CLEAN_PY, **{"src/old.py": f'TOKEN = "{old}"\n'}))
        r._git("branch", "base")
        self.step(r, {"src/new.py": f'KEY = "{new}"\n'})
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)
        blocking = findings(data, "secrets", "open")
        self.assertTrue(blocking and all(f["path"] == "src/new.py" for f in blocking), out)
        self.assertTrue(all("this change" in f["message"] for f in blocking), out)
        pre = findings(data, "secrets", "pre-existing")
        self.assertTrue(any(f["path"] == "src/old.py" for f in pre), out)
        self.assertIn("pre-existing secrets", out)
        self.assertNoValue(out, old, new)

    def test_secret_only_in_an_old_commit_does_not_block(self):
        old = canary()
        r = self.repo(dict(CLEAN_PY, **{"src/conf.py": f'TOKEN = "{old}"\n'}))
        self.step(r, {"src/conf.py": "TOKEN = None\n"}, "remove the token")
        r._git("branch", "base")
        self.step(r, {"src/calc.py": "def add(a, b):\n    return b + a\n"}, "unrelated change")
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 0, out)
        self.assertEqual(status_of(data, "secrets"), "warn", out)
        pre = findings(data, "secrets", "pre-existing")
        self.assertTrue(any("estate-gate-canary" in f["message"] and "fingerprint" in f["message"] for f in pre), out)
        self.assertNoValue(out, old)

    def test_secret_added_and_removed_inside_the_range_blocks(self):
        old, new = canary(), canary()
        r = self.repo(dict(CLEAN_PY, **{"src/old.py": f'TOKEN = "{old}"\n'}))
        self.step(r, {"src/old.py": "TOKEN = None\n"})
        r._git("branch", "base")
        self.step(r, {"src/x.py": f'KEY = "{new}"\n'}, "add a key")
        self.step(r, {"src/x.py": "KEY = None\n"}, "take it out again")
        val = "pw-" + rnd(20)
        self.step(r, {"k8s/db.yaml": k8s_secret(("DB_PASSWORD", val))}, "a k8s secret")
        self.step(r, {"k8s/db.yaml": None}, "and remove it")
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)
        blocking = findings(data, "secrets", "open")
        self.assertTrue(any("estate-gate-canary" in f["message"] and f["path"] == "src/x.py" for f in blocking), out)
        self.assertTrue(any("k8s Secret data.DB_PASSWORD" in f["message"] for f in blocking), out)
        self.assertTrue(all("this change" in f["message"] for f in blocking), out)
        self.assertFalse(any(f["path"] == "src/old.py" for f in blocking), out)
        self.assertTrue(any(f["path"] == "src/old.py" for f in findings(data, "secrets", "pre-existing")), out)
        self.assertNoValue(out, old, new, val)

    def test_touching_the_line_of_an_old_secret_blocks(self):
        old = canary()
        r = self.repo(dict(CLEAN_PY, **{"src/conf.py": f'TOKEN = "{old}"\nOTHER = 1\n'}))
        r._git("branch", "base")
        self.step(r, {"src/conf.py": f'TOKEN = "{old}"  # still here\nOTHER = 1\n'})
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)
        blocking = findings(data, "secrets", "open")
        self.assertTrue(any("estate-gate-canary" in f["message"] and "this change" in f["message"] for f in blocking), out)
        self.assertNoValue(out, old)

    def test_touching_the_line_of_an_old_k8s_secret_blocks(self):
        val = "pw-" + rnd(20)
        r = self.repo(dict(CLEAN_PY, **{"k8s/db.yaml": k8s_secret(("DB_PASSWORD", val))}))
        r._git("branch", "base")
        self.step(r, {"k8s/db.yaml": k8s_secret(("DB_PASSWORD", val)).rstrip("\n") + "  # touched\n"})
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)
        blocking = findings(data, "secrets", "open")
        self.assertTrue(any("k8s Secret data.DB_PASSWORD" in f["message"] and "this change" in f["message"]
                            for f in blocking), out)
        self.assertNoValue(out, val)

    def test_editing_another_line_of_a_file_with_an_old_secret_does_not_block(self):
        old, val = canary(), "pw-" + rnd(20)
        r = self.repo(dict(CLEAN_PY, **{"src/conf.py": f'TOKEN = "{old}"\nOTHER = 1\n',
                                        "k8s/db.yaml": k8s_secret(("DB_PASSWORD", val))}))
        r._git("branch", "base")
        self.step(r, {"src/conf.py": f'TOKEN = "{old}"\nOTHER = 2\n',
                      "k8s/db.yaml": k8s_secret(("DB_PASSWORD", val), ("DB_USER", "CHANGEME"))})
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 0, out)
        pre = findings(data, "secrets", "pre-existing")
        self.assertTrue(any(f["path"] == "src/conf.py" for f in pre), out)
        self.assertTrue(any("k8s Secret data.DB_PASSWORD" in f["message"] for f in pre), out)
        self.assertNoValue(out, old, val)

    def test_a_new_secret_in_the_working_tree_blocks(self):
        r = self.repo(CLEAN_PY)
        r._git("branch", "base")
        val = "pw-" + rnd(20)
        r.write({"k8s/db.yaml": k8s_secret(("DB_PASSWORD", val))})
        r._git("add", "k8s/db.yaml")  # staged, not committed: the tree sweep reads it
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)
        self.assertTrue(any("k8s Secret data.DB_PASSWORD" in f["message"] for f in findings(data, "secrets", "open")), out)

    def test_merging_the_base_into_the_branch_does_not_block_on_its_old_secrets(self):
        old, val = canary(), "pw-" + rnd(20)
        r = self.repo(CLEAN_PY)
        r._git("checkout", "-q", "-b", "feature")
        self.step(r, {"src/calc.py": "def add(a, b):\n    return b + a\n"}, "feature work")
        r._git("checkout", "-q", "main")
        self.step(r, {"src/conf.py": f'TOKEN = "{old}"\n', "k8s/db.yaml": k8s_secret(("DB_PASSWORD", val))}, "main moves on")
        r._git("checkout", "-q", "feature")
        r._git("merge", "-q", "--no-ff", "--no-edit", "main")
        code, out, data = self.scoped(r, "--base-ref", "main")
        self.assertEqual(code, 0, out)
        self.assertTrue(findings(data, "secrets", "pre-existing"), out)
        self.assertNoValue(out, old, val)

    def test_default_base_is_the_merge_base_with_the_remote_default_branch(self):
        old, new = canary(), canary()
        r = self.repo(dict(CLEAN_PY, **{"src/old.py": f'TOKEN = "{old}"\n'}))
        r._git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.step(r, {"src/calc.py": "def add(a, b):\n    return b + a\n"})
        code, out, data = self.scoped(r)
        self.assertEqual(code, 0, out)
        self.assertIn("origin/main", out)
        self.step(r, {"src/new.py": f'KEY = "{new}"\n'})
        code, out, data = self.scoped(r)
        self.assertEqual(code, 1, out)
        self.assertTrue(all(f["path"] == "src/new.py" for f in findings(data, "secrets", "open")), out)

    def test_unrelated_histories_is_cannot_tell(self):
        # an orphan branch has no merge-base with HEAD: cannot tell, never a traceback and never a pass
        r = self.repo(CLEAN_PY)
        r._git("checkout", "-q", "--orphan", "other")
        r.commit("an unrelated history")
        r._git("checkout", "-q", "main")
        code, out, data = self.scoped(r, "--base-ref", "other")
        self.assertEqual(code, 2, out)
        self.assertIn("unrelated histories", out)

    def test_no_resolvable_base_is_cannot_tell(self):
        r = self.repo(CLEAN_PY)  # no remote, no --base-ref
        code, out, data = self.scoped(r)
        self.assertEqual(code, 2, out)
        self.assertEqual(status_of(data, "secrets"), "cannot-tell", out)
        self.assertIn("base", out)

    def test_an_unknown_base_ref_is_cannot_tell(self):
        r = self.repo(CLEAN_PY)
        r._git("update-ref", "refs/remotes/origin/main", "HEAD")  # a default exists, but the named ref wins
        code, out, data = self.scoped(r, "--base-ref", "no-such-branch")
        self.assertEqual(code, 2, out)
        self.assertEqual(status_of(data, "secrets"), "cannot-tell", out)

    def test_a_reviewed_fixture_in_gitleaksignore_still_passes(self):
        r = self.repo(CLEAN_PY)
        r._git("branch", "base")
        self.step(r, {"tests/fixture_token.py": f'TOKEN = "{canary()}"\n'}, "fixture")
        sha = subprocess.run(["git", "-C", str(r.path), "rev-parse", "HEAD"], capture_output=True, text=True,
                             check=True).stdout.strip()
        self.step(r, {".gitleaksignore": "# reviewed: the gate's own canary, a fake secret planted by a test\n"
                                         f"{sha}:tests/fixture_token.py:estate-gate-canary:1\n"}, "ignore it")
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 0, out)

    def test_secrets_still_cannot_be_baselined(self):
        r = self.repo(CLEAN_PY)
        r._git("branch", "base")
        self.step(r, {"src/new.py": f'KEY = "{canary()}"\n'})
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(r.path), "--only", "secrets", "--offline",
                        "--base-ref", "base"], cwd=ROOT, check=True, capture_output=True, env=dict(os.environ, **self.env))
        self.assertEqual(json.loads((r.path / ".gate-baseline.json").read_text(encoding="utf-8"))["entries"], [])
        r.commit("baseline")
        code, out, data = self.scoped(r, "--base-ref", "base")
        self.assertEqual(code, 1, out)


class SecretsScopeHelpers(Base):
    """The scope helpers directly, not through the CLI. The mutation smoke found three mutants of
    secrets_scope.py that survived the CLI tests (a deleted path let through, a merge commit's shared
    paths emptied, a path-less object line turned into an empty path); each test below is the case
    that catches one."""

    def repo(self, files: dict) -> GateRepo:
        r = GateRepo(files)
        self.addCleanup(r.close)
        return r

    def core(self, r: GateRepo):
        from gate.core import Repo
        return Repo(r.path)

    def test_changed_blobs_skips_deletions_and_non_regular_files(self):
        """A deleted path is not a changed blob, and neither is a symlink (mode 120000). The mutant
        turns the skip into `status.startswith('D') and not mode.startswith('100')`, which lets a
        deletion through carrying its old blob. The symlink goes in through the index
        (`--cacheinfo 120000,...`) so the test does not need symlink privileges on Windows."""
        r = self.repo({"keep.py": "A = 1\n", "gone.py": "B = 2\n"})
        base = r._out("rev-parse", "HEAD")
        (r.path / "_blob.txt").write_text("keep.py\n", encoding="utf-8", newline="\n")
        link_blob = r._out("hash-object", "-w", "_blob.txt")
        r._git("rm", "-q", "gone.py")
        r._git("update-index", "--add", "--cacheinfo", f"120000,{link_blob},link.txt")
        (r.path / "keep.py").write_text("A = 3\n", encoding="utf-8", newline="\n")
        r._git("add", "keep.py")
        r._git("commit", "-q", "-m", "delete one, symlink another")
        from gate.checks.secrets_scope import changed_blobs
        got = changed_blobs(self.core(r), base, "HEAD")
        self.assertEqual(set(got), {"keep.py"}, got)

    def test_commit_changes_of_a_merge_is_the_paths_every_parent_shares(self):
        """A merge commit introduces only what differs from every parent. The mutant flips `k in d`
        to `k not in d`, which makes a path introduced in one parent and not the other count as the
        merge's own change."""
        r = self.repo({"base.py": "X = 1\n"})
        r._git("checkout", "-q", "-b", "left")
        (r.path / "left.py").write_text("L = 1\n", encoding="utf-8", newline="\n")
        r.commit("left adds left.py")
        r._git("checkout", "-q", "main")
        r._git("checkout", "-q", "-b", "right")
        (r.path / "right.py").write_text("R = 1\n", encoding="utf-8", newline="\n")
        r.commit("right adds right.py")
        r._git("merge", "-q", "--no-ff", "-m", "merge left and right", "left")
        from gate.checks.secrets_scope import commit_changes
        ps, common = commit_changes(self.core(r), "HEAD")
        self.assertEqual(len(ps), 2, ps)
        self.assertEqual(common, {}, f"paths added on one side only are not the merge's own change: {common}")

    def test_commit_changes_of_an_ordinary_commit_is_everything_it_touches(self):
        """The same helper on a non-merge: with one parent, every path it changes is its own change.
        (A merge-only test would pass with the mutant if that helper always returned {}.)"""
        r = self.repo({"base.py": "X = 1\n"})
        (r.path / "added.py").write_text("A = 1\n", encoding="utf-8", newline="\n")
        r.commit("add one file")
        from gate.checks.secrets_scope import commit_changes
        ps, common = commit_changes(self.core(r), "HEAD")
        self.assertEqual(len(ps), 1, ps)
        self.assertEqual(set(common), {"added.py"}, common)

    def test_reachable_blobs_maps_only_paths_and_never_an_empty_one(self):
        """`rev-list --objects` also lists commits and trees, which have no path. The mutant turns
        `path and sha not in out` into `path or ...`, so those lines land in the map under an empty
        path, and a caller comparing blob shas then matches nothing useful."""
        r = self.repo({"a.py": "A = 1\n", "copy.py": "A = 1\n"})
        from gate.checks.secrets_scope import reachable_blobs
        got = reachable_blobs(self.core(r), "HEAD")
        self.assertTrue(got, got)
        self.assertTrue(all(p for p in got.values()), f"an object with no path reached the map: {got}")
        self.assertIn("a.py", got.values())
        same = [p for p in got.values() if p in {"a.py", "copy.py"}]
        self.assertEqual(len(same), 1, f"one blob sha is one entry, even at two paths: {got}")


def _git_exe() -> str:
    import shutil
    return shutil.which("git") or "git"


class Paths(Base):
    def test_hardcoded_windows_path_in_code_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": 'DATA = "D:/data/input.csv"\n'}), "paths", "hardcoded Windows path")

    def test_estate_path_in_docs_fails(self):
        # an org's internal layout comes from GATE_EXTRA_PATH_PATTERNS, never from this public repo
        env = {"GATE_EXTRA_PATH_PATTERNS": r"(?<![A-Za-z])q:[\\/]+corp\b;/srv/internal\b"}
        self.assertFails(dict(CLEAN_PY, **{"docs/setup.md": "Clone into Q:/corp/demo first.\n"}), "paths",
                         "GATE_EXTRA_PATH_PATTERNS", env=env)

    def test_extra_patterns_unset_leaves_docs_example_as_warning(self):
        self.assertPasses(dict(CLEAN_PY, **{"docs/setup.md": "Clone into Q:/corp/demo first.\n"}), "paths",
                          env={"GATE_EXTRA_PATH_PATTERNS": ""}, allow=("warn",))

    def test_real_user_home_in_docs_fails(self):
        home = "/Users/" + "mkowalski"  # assembled: this file must not itself carry a user's home path
        self.assertFails(dict(CLEAN_PY, **{"docs/setup.md": f"Logs land in {home}/Library/demo.\n"}), "paths",
                         "a real user's home folder")

    def test_internal_host_in_private_docs_is_warning(self):
        host = "nas" + ".tail1234" + ".ts" + ".net"
        files = dict(CLEAN_PY, **{"docs/runbook.md": f"Mount from {host}.\n"})
        self.assertFails(files, "paths", "tailnet host", "--visibility", "public")
        self.assertPasses(files, "paths", "--visibility", "private", allow=("warn",))

    def test_internal_host_in_private_code_still_fails(self):
        host = "nas" + ".tail1234" + ".ts" + ".net"
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": f'URL = "http://{host}"\n'}), "paths", "tailnet host", "--visibility", "private")

    def test_placeholder_home_in_docs_passes(self):
        self.assertPasses(dict(CLEAN_PY, **{"docs/setup.md": "Logs land in /home/user/.demo.\n"}), "paths", allow=("pass",))

    def test_marker_text_inside_a_string_is_not_a_marker(self):
        t = 'FIXTURE = "@pytest.mark.xfail\\ndef test_x(): pass"\n\n\ndef test_real():\n    assert FIXTURE\n'
        self.assertPasses(dict(CLEAN_PY, **{"tests/test_fixture.py": t}), "test-markers", allow=("pass",))

    def test_home_path_in_code_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": 'CFG = "/home/alice/.demo/cfg.json"\n'}), "paths", "hardcoded home path")

    def test_tailnet_host_fails(self):
        host = "box.tail1234" + ".ts" + ".net"  # built at run time, so this file carries no tailnet name
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": f'URL = "http://{host}:8080"\n'}), "paths", "tailnet host")

    def test_generic_path_in_docs_is_warning_only(self):
        self.assertPasses(dict(CLEAN_PY, **{"docs/setup.md": "On Windows: `D:\\work\\demo`.\n"}), "paths", allow=("warn",))

    def test_os_path_in_detection_rule_is_warning(self):
        # borrowed-trust-detections Sigma rules, 2026-10-22 dry run: an OS location as detection data
        rule = "detection:\n  selection:\n    Image|startswith: 'C:\\Windows\\System32\\'\n"
        self.assertPasses(dict(CLEAN_PY, **{"detections/sigma/rule.yml": rule}), "paths", allow=("warn",))

    def test_relative_paths_pass(self):
        self.assertPasses(dict(CLEAN_PY, **{"src/io.py": 'from pathlib import Path\nDATA = Path(__file__).parent / "data"\n'
                                                         'URL = "https://example.com/a:b"\n'}), "paths", allow=("pass",))

    def test_json_escape_sequence_is_not_a_drive(self):
        # saluca-corp 2026-10-27: 33 blocking findings on generated run records, every one of
        # them a \n or \t escape sequence read as drive `A:` / `f:` / `n:`. None was a path.
        run = json.dumps({"response": "A:\n    ```json\n    {\n", "note": "f:\n- base case"}) + "\n"
        self.assertPasses(dict(CLEAN_PY, **{"rd/results/runs/0008.json": run}), "paths", allow=("pass",))

    def test_real_path_inside_json_still_blocks(self):
        # The escape fix must not blind the check: a doubled backslash is a real path in JSON.
        cfg = json.dumps({"env": "C:\\saluca-deploy\\.env"}) + "\n"
        self.assertFails(dict(CLEAN_PY, **{"rd/config.json": cfg}), "paths", "hardcoded Windows path")


class ControlChars(Base):
    def test_mangled_tab_escape_fails(self):
        # what "C:\temp" in a non-raw string leaves behind: a TAB after text
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": b'P = "C:' + bytes([9]) + b'emp"\n'}), "control-chars", "TAB after text")

    def test_backspace_from_b_escape_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": b'P = "x' + bytes([8]) + b'in"\n'}), "control-chars", "BS (0x08)")

    def test_bidi_override_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"src/io.py": ('ok = "a' + chr(0x202E) + 'b"\n').encode()}), "control-chars", "bidi")

    def test_clean_passes(self):
        self.assertPasses(CLEAN_PY, "control-chars", allow=("pass",))


class Style(Base):
    def test_em_dash_in_readme_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"README.md": CLEAN_PY["README.md"] + "\nFast " + chr(0x2014) + " and small.\n"}),
                         "style", "STY-1")

    def test_signoff_is_allowed(self):
        self.assertPasses(dict(CLEAN_PY, **{"docs/post.md": "Text.\n\n" + chr(0x2014) + " Saluca Labs\n"}), "style", allow=("pass",))

    def test_signoff_in_html_element_is_allowed(self):
        # saluca-campus docs/_PDF/*.html, 2026-10-26: the sanctioned sign-off as its own element
        for elem in ("<p>" + chr(0x2014) + " Saluca Labs</p>", '<p class="signoff">' + chr(0x2014) + " Saluca Labs</p>",
                     "<footer><span>" + chr(0x2014) + " Saluca Labs</span></footer>"):
            with self.subTest(elem=elem):
                self.assertPasses(dict(CLEAN_PY, **{"docs/post.html": "<p>Text.</p>\n" + elem + "\n"}), "style",
                                  allow=("pass",))

    def test_em_dash_in_html_prose_fails(self):
        # the HTML exception must not become an exemption for HTML: same element, more text, still fails
        for line in ("<p>Fast " + chr(0x2014) + " and small.</p>",
                     "<p>We build it " + chr(0x2014) + " Saluca Labs</p>",
                     "<p>" + chr(0x2014) + " Saluca Labs</p><p>and then " + chr(0x2014) + " more</p>"):
            with self.subTest(line=line):
                self.assertFails(dict(CLEAN_PY, **{"docs/post.html": "<p>Text.</p>\n" + line + "\n"}), "style", "STY-1")

    def test_crlf_shell_script_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"entrypoint.sh": b"#!/bin/sh\r\necho hi\r\n", ".gitattributes": "*.py text\n"}),
                         "style", "STY-3")

    def test_unpinned_shell_script_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"run.sh": "#!/bin/sh\necho hi\n", ".gitattributes": "*.py text\n"}), "style",
                         "not LF-pinned")

    def test_pinned_shell_script_passes(self):
        self.assertPasses(dict(CLEAN_PY, **{"run.sh": "#!/bin/sh\necho hi\n"}), "style", allow=("pass",))


class TestMarkers(Base):
    def test_xfail_without_reason_fails(self):
        t = "import pytest\n\n\n@pytest.mark.xfail\ndef test_x():\n    assert False\n"
        self.assertFails(dict(CLEAN_PY, **{"tests/test_x.py": t}), "test-markers", "without a reason and an issue link")

    def test_skip_with_reason_but_no_issue_fails(self):
        t = "import pytest\n\n\n@pytest.mark.skip(reason='flaky on CI runners')\ndef test_x():\n    pass\n"
        self.assertFails(dict(CLEAN_PY, **{"tests/test_x.py": t}), "test-markers", "without an issue link")

    def test_bulk_xfail_fails_even_with_reason(self):
        t = ("import pytest\n\npytestmark = pytest.mark.xfail(reason='wip https://github.com/o/r/issues/1')\n\n\n"
             "def test_x():\n    assert False\n")
        self.assertFails(dict(CLEAN_PY, **{"tests/test_x.py": t}), "test-markers", "bulk xfail")

    def test_js_skip_without_issue_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"web/a.test.js": "it.skip('works', () => {});\n"}), "test-markers", "it.skip")

    def test_over_cap_fails(self):
        body = "import pytest\n" + "".join(
            f"\n\n@pytest.mark.skip(reason='needs a GPU runner, https://github.com/o/r/issues/{i}')\ndef test_{i}():\n    pass\n"
            for i in range(11))
        self.assertFails(dict(CLEAN_PY, **{"tests/test_many.py": body}), "test-markers", "over the cap")

    def test_code_without_tests_fails(self):
        files = {k: v for k, v in CLEAN_PY.items() if not k.startswith("tests/")}
        self.assertFails(files, "test-markers", "no test files")

    def test_reasoned_and_linked_skip_passes(self):
        t = ("import pytest\n\n\n@pytest.mark.skip(reason='needs a GPU runner, https://github.com/o/r/issues/7')\n"
             "def test_x():\n    pass\n")
        self.assertPasses(dict(CLEAN_PY, **{"tests/test_x.py": t}), "test-markers", allow=("pass",))


CLAIMS_HEAD = "| id | claim | source | status | code | wired | test | note |\n|---|---|---|---|---|---|---|---|\n"
CLAIM_FILES = dict(CLEAN_PY, **{
    "README.md": CLEAN_PY["README.md"] + "\nIt verifies the chain and detects truncation.\n\nForgetting is planned, not yet built.\n",
    "src/chain.py": "def verify(entries, head):\n    return len(entries) == head['length']\n",
    "src/cli.py": "from src.chain import verify\n\n\ndef main():\n    return verify([], {'length': 0})\n",
    "tests/test_chain.py": "from src.chain import verify\n\n\ndef test_truncation_detected():\n    assert not verify([1], {'length': 2})\n",
})


def claims(rows: str) -> dict:
    return {"CLAIMS.md": "# Claims\n\n" + CLAIMS_HEAD + rows}


class Claims(Base):
    GOOD = ("| C1 | detects truncation | README.md | shipped | src/chain.py::verify | src/cli.py: verify( | "
            "tests/test_chain.py::test_truncation_detected | |\n"
            "| C2 | Forgetting is planned | README.md | planned | | | | |\n")

    def test_good_claims_pass(self):
        self.assertPasses(dict(CLAIM_FILES, **claims(self.GOOD)), "claims")

    def test_missing_claims_file_fails(self):
        self.assertFails(CLAIM_FILES, "claims", "CLM-1")

    def test_broken_code_reference_fails(self):
        row = ("| C1 | detects truncation | README.md | shipped | src/chain.py::verify_head | src/cli.py: verify( | "
               "tests/test_chain.py::test_truncation_detected | |\n")
        self.assertFails(dict(CLAIM_FILES, **claims(row)), "claims", "has no verify_head")

    def test_stub_fails(self):
        files = dict(CLAIM_FILES, **{"src/chain.py": "def verify(entries, head):\n    raise NotImplementedError\n"})
        self.assertFails(dict(files, **claims(self.GOOD)), "claims", "is a stub")

    def test_not_mounted_fails(self):
        row = ("| C1 | detects truncation | README.md | shipped | src/chain.py::verify | src/cli.py: app.include_router(chain) | "
               "tests/test_chain.py::test_truncation_detected | |\n")
        self.assertFails(dict(CLAIM_FILES, **claims(row)), "claims", "not mounted")

    def test_skipped_test_reference_fails(self):
        files = dict(CLAIM_FILES, **{"tests/test_chain.py": "import pytest\n\n\n@pytest.mark.skip(reason='later')\n"
                                                               "def test_truncation_detected():\n    pass\n"})
        self.assertFails(dict(files, **claims(self.GOOD)), "claims", "skipped or xfailed")

    def test_claim_text_drifted_from_readme_fails(self):
        row = ("| C1 | detects tampering | README.md | shipped | src/chain.py::verify | src/cli.py: verify( | "
               "tests/test_chain.py::test_truncation_detected | |\n")
        self.assertFails(dict(CLAIM_FILES, **claims(row)), "claims", "not found in README.md")

    def test_planned_presented_as_working_fails(self):
        row = "| C1 | It verifies the chain | README.md | planned | | | | |\n"
        self.assertFails(dict(CLAIM_FILES, **claims(row)), "claims", "presents it as working")

    def test_withdrawn_without_correction_note_fails(self):
        row = "| C9 | does not read the text | README.md | withdrawn | | | | 2026-10-22 |\n"
        self.assertFails(dict(CLAIM_FILES, **claims(row)), "claims", "no dated correction note")

    def test_withdrawn_with_correction_note_passes(self):
        readme = CLAIM_FILES["README.md"] + "\n## Corrections\n\n- 2026-10-22 (C9): an earlier README said it does not read the text. It does.\n"
        row = "| C9 | does not read the text | README.md | withdrawn | | | | 2026-10-22 |\n"
        files = dict(CLAIM_FILES, **{"README.md": readme})
        # the withdrawn wording appears only inside the Corrections section, which is allowed
        self.assertPasses(dict(files, **claims(self.GOOD + row)), "claims")


class Packaging(Base):
    UNPUB = "saluca-gate-nonexistent-" + "7f3a9c2e41"

    def readme(self, extra):
        return dict(CLEAN_PY, **{"README.md": CLEAN_PY["README.md"] + "\n## Install\n\n" + extra})

    def test_unpublished_package_claim_fails(self):
        code, out, data = self.run_gate(self.readme(f"```sh\npip install {self.UNPUB}\n```\n"), "--only", "packaging")
        self.assertEqual(code, 1, out)
        self.assertTrue(any("404" in m for m in open_blocks(data, "packaging")), out)

    def test_unpublished_npm_package_fails(self):
        code, out, data = self.run_gate(self.readme(f"`npm install {self.UNPUB}`\n"), "--only", "packaging")
        self.assertEqual(code, 1, out)

    def test_marked_not_yet_published_passes(self):
        code, out, data = self.run_gate(self.readme(f"Not yet published to PyPI; install from a clone.\n\n```sh\npip install "
                                                    f"{self.UNPUB}\n```\n"), "--only", "packaging")
        self.assertEqual(code, 0, out)

    def test_published_package_passes(self):
        code, out, data = self.run_gate(self.readme("```sh\npip install requests\n```\n"), "--only", "packaging")
        self.assertEqual(code, 0, out)

    def test_pep508_direct_reference_is_not_a_registry_claim(self):
        # velamen README, 2026-10-22 dry run: installs from git, never from PyPI
        code, out, data = self.run_gate(self.readme(f'```bash\npip install "{self.UNPUB} @ git+https://github.com/o/r@abc"\n'
                                                    f'pip install "{self.UNPUB}[crypto] @ git+https://github.com/o/r@abc"\n```\n'),
                                        "--only", "packaging")
        self.assertEqual(code, 0, out)
        self.assertEqual(status_of(data, "packaging"), "n/a", out)

    def test_exemption_covers_the_whole_section(self):
        text = (f"It is not published on PyPI; install from a clone.\n\nSome more prose.\n\nAnd more.\n\nStill more.\n\n"
                f"```sh\npip install {self.UNPUB}\n```\n\n```sh\npip install {self.UNPUB}[extra]\n```\n")
        code, out, data = self.run_gate(self.readme(text), "--only", "packaging")
        self.assertEqual(code, 0, out)

    def test_design_notes_under_docs_are_not_install_claims(self):
        files = dict(CLEAN_PY, **{"docs/architecture/attach.md": f"# Attach\n\n`npx {self.UNPUB}` will upload a file.\n"})
        code, out, data = self.run_gate(files, "--only", "packaging")
        self.assertEqual(status_of(data, "packaging"), "n/a", out)

    def test_install_page_under_docs_is_checked(self):
        files = dict(CLEAN_PY, **{"docs/installation.md": f"# Install\n\n`pip install {self.UNPUB}`\n"})
        code, out, data = self.run_gate(files, "--only", "packaging")
        self.assertEqual(code, 1, out)

    def test_offline_is_cannot_tell(self):
        code, out, data = self.run_gate(self.readme("```sh\npip install requests\n```\n"), "--only", "packaging", "--offline")
        self.assertEqual(code, 2, out)


APACHE = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n"


class Licence(Base):
    def test_metadata_disagrees_with_licence_file_fails(self):
        files = dict(CLEAN_PY, **{"package.json": json.dumps({"name": "demo", "license": "Apache-2.0"})})
        self.assertFails(files, "licence", "LIC-2")

    def test_readme_disagrees_fails(self):
        files = dict(CLEAN_PY, **{"README.md": CLEAN_PY["README.md"].replace("MIT, see", "Apache-2.0, see")})
        self.assertFails(files, "licence", "README.md License section says Apache-2.0")

    def test_no_licence_fails(self):
        files = {k: v for k, v in CLEAN_PY.items() if k != "LICENSE"}
        self.assertFails(files, "licence", "LIC-1")

    def test_recent_change_without_note_fails(self):
        self.assertFails(CLEAN_PY, "licence", "LIC-3", extra=[{"LICENSE": APACHE,
                                                                "README.md": CLEAN_PY["README.md"].replace("MIT", "Apache-2.0")}])

    def test_recent_change_with_dated_note_passes(self):
        readme = CLEAN_PY["README.md"].replace("MIT", "Apache-2.0")
        # dated on or after the licence-change commit, which the fixture makes today (a fixed date failed after midnight UTC)
        today = __import__("datetime").date.today().isoformat()
        note = f"# Changelog\n\n- {today}: licence changed from MIT to Apache-2.0 (approved by the owner).\n"
        self.assertPasses(CLEAN_PY, "licence", extra=[{"LICENSE": APACHE, "README.md": readme, "CHANGELOG.md": note}])

    def test_readme_paper_doi_is_not_the_code_record(self):
        # detection-content, 2026-10-22 dry run: the README cites the CC-BY paper; only CITATION.cff's own doi counts
        sys.path.insert(0, str(ROOT))
        from gate.checks import licence
        from gate.core import Repo
        repo = GateRepo(dict(CLEAN_PY, **{"README.md": CLEAN_PY["README.md"] + "\nPaper: https://doi.org/10.5281/zenodo.123\n"}))
        self.addCleanup(repo.close)
        self.assertEqual(licence.zenodo_licences(Repo(repo.path)), [])

    def test_fsl_licence_is_recognised_everywhere(self):
        # elysium and tiresias-core, 2026-10-22 dry run
        fsl = "# Functional Source License, Version 1.1, Apache 2.0 Future License\n\n## Abbreviation\n\nFSL-1.1-ALv2\n"
        readme = CLEAN_PY["README.md"].replace("MIT, see LICENSE.", "FSL-1.1-ALv2 (Functional Source License), which becomes Apache 2.0 after two years.")
        files = dict(CLEAN_PY, **{"LICENSE": fsl, "README.md": readme,
                                  "package.json": json.dumps({"name": "demo", "license": "FSL-1.1-ALv2"}),
                                  "pyproject.toml": '[project]\nname = "demo"\nlicense = "LicenseRef-FSL-1.1-Apache-2.0"\n'})
        self.assertPasses(files, "licence", allow=("pass",))

    def test_fsl_file_is_not_read_as_apache(self):
        # elysium, third dry-run pass: FSL's text quotes the Apache licence it converts to
        fsl = ("# Functional Source License, Version 1.1, Apache 2.0 Future License\n\n... Apache License, Version 2.0 ...\n")
        files = dict(CLEAN_PY, **{"LICENSE": fsl, "README.md": CLEAN_PY["README.md"].replace("MIT, see", "FSL-1.1-ALv2, see")})
        self.assertPasses(files, "licence", allow=("pass",))

    def test_split_licence_needs_reuse_file(self):
        readme = CLEAN_PY["README.md"].replace("MIT, see LICENSE.", "Code: MIT, see LICENSE. The paper text: CC-BY-4.0.")
        out = self.assertFails(dict(CLEAN_PY, **{"README.md": readme}), "licence", "LICENSES/CC-BY-4.0.txt")
        self.assertPasses(dict(CLEAN_PY, **{"README.md": readme, "LICENSES/CC-BY-4.0.txt": "Attribution 4.0 International\n"}),
                          "licence", allow=("pass",))

    def test_busl_file_is_not_read_as_its_change_licence(self):
        # tiresias, 2026-10-22: a BUSL-1.1 LICENSE names "Change License: Apache License, Version 2.0".
        # Fixtures: SPDX license-list-data text/BUSL-1.1.txt (with the template's Parameters block filled in)
        # and text/Apache-2.0.txt
        sys.path.insert(0, str(ROOT))
        from gate.checks import licence
        fx = Path(__file__).resolve().parent / "fixtures"
        busl = (fx / "BUSL-1.1.txt").read_text(encoding="utf-8")
        self.assertEqual(licence.identify(busl), "BUSL-1.1")
        self.assertEqual(licence.identify(busl.split("\n", 1)[1]), "BUSL-1.1")  # header line lost: the parameter block
        self.assertEqual(licence.identify((fx / "Apache-2.0.txt").read_text(encoding="utf-8")), "Apache-2.0")
        fsl = "# Functional Source License, Version 1.1, Apache 2.0 Future License\n\n... Apache License, Version 2.0 ...\n"
        self.assertEqual(licence.identify(fsl), "FSL-1.1-ALv2")
        readme = CLEAN_PY["README.md"].replace("MIT, see LICENSE.", "BUSL-1.1, see LICENSE. Change License Apache-2.0 on 2030-01-01.")
        self.assertPasses(dict(CLEAN_PY, **{"LICENSE": busl, "README.md": readme}), "licence", allow=("pass",))
        # another licence named outside the Change License is still a mismatch
        self.assertFails(dict(CLEAN_PY, **{"LICENSE": busl, "README.md": readme.replace("2030-01-01.", "2030-01-01. The sdk is MIT.")}),
                         "licence", "README.md License section says MIT")

    def test_consistent_passes(self):
        files = dict(CLEAN_PY, **{"package.json": json.dumps({"name": "demo", "license": "MIT"})})
        self.assertPasses(files, "licence", allow=("pass",))


GOOD_CI = """
name: CI
on:
  pull_request:
jobs:
  gate:
    uses: salucallc/ci-shared/.github/workflows/merge-gate.yml@0123456789abcdef0123456789abcdef01234567
    with:
      gate-ref: 0123456789abcdef0123456789abcdef01234567
"""


class CiHygiene(Base):
    def test_no_ci_fails(self):
        self.assertFails(CLEAN_PY, "ci-hygiene", "CI-1")

    def test_continue_on_error_fails(self):
        wf = GOOD_CI + "  lint:\n    runs-on: ubuntu-24.04\n    continue-on-error: true\n    steps:\n      - run: ruff check .\n"
        self.assertFails(dict(CLEAN_PY, **{".github/workflows/ci.yml": wf}), "ci-hygiene", "continue-on-error")

    def test_swallowed_lint_fails(self):
        wf = GOOD_CI + "  lint:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: ruff check . || true\n"
        self.assertFails(dict(CLEAN_PY, **{".github/workflows/ci.yml": wf}), "ci-hygiene", "swallowed")

    def test_gate_adopted_passes(self):
        self.assertPasses(dict(CLEAN_PY, **{".github/workflows/ci.yml": GOOD_CI}), "ci-hygiene")

    def test_private_free_plan_repo_is_unprotectable_not_cannot_tell(self):
        # pantheon, 2026-10-22 dry run: GitHub answers 403 "Upgrade to GitHub Pro" for rulesets on a private Free repo
        sys.path.insert(0, str(ROOT))
        from gate.checks import ci_hygiene
        from gate.core import Repo, Result
        answers = {"/repos/o/r": (200, {"default_branch": "main", "private": True}),
                   "/repos/o/r/branches/main": (200, {"protected": False}),
                   "/repos/o/r/rules/branches/main": (403, {"message": "Upgrade to GitHub Pro or make this repository public"})}
        real = ci_hygiene.api
        ci_hygiene.api = lambda path, token: answers[path]
        self.addCleanup(setattr, ci_hygiene, "api", real)
        repo = GateRepo(CLEAN_PY)
        self.addCleanup(repo.close)
        r = Result("branch-protection", "")
        ci_hygiene.protection(Repo(repo.path), r, "o/r", None)
        self.assertEqual(r.status, "fail")
        self.assertTrue(any("cannot require the gate" in f.message for f in r.findings))

    def test_unprotected_public_repo_fails(self):
        sys.path.insert(0, str(ROOT))
        from gate.checks import ci_hygiene
        from gate.core import Repo, Result
        answers = {"/repos/o/r": (200, {"default_branch": "main", "private": False}),
                   "/repos/o/r/branches/main": (200, {"protected": False, "protection": {"enabled": False}}),
                   "/repos/o/r/rules/branches/main": (200, [])}
        real = ci_hygiene.api
        ci_hygiene.api = lambda path, token: answers[path]
        self.addCleanup(setattr, ci_hygiene, "api", real)
        repo = GateRepo(CLEAN_PY)
        self.addCleanup(repo.close)
        r = Result("branch-protection", "")
        ci_hygiene.protection(Repo(repo.path), r, "o/r", None)
        self.assertTrue(any("is not protected" in f.message for f in r.findings))

    def test_protected_with_gate_required_passes(self):
        sys.path.insert(0, str(ROOT))
        from gate.checks import ci_hygiene
        from gate.core import Repo, Result
        answers = {"/repos/o/r": (200, {"default_branch": "main", "private": False}),
                   "/repos/o/r/branches/main": (200, {"protected": True, "protection": {
                       "enabled": True, "required_status_checks": {"contexts": ["gate / Merge gate all"]}}}),
                   "/repos/o/r/rules/branches/main": (200, [{"type": "pull_request"}])}
        real = ci_hygiene.api
        ci_hygiene.api = lambda path, token: answers[path]
        self.addCleanup(setattr, ci_hygiene, "api", real)
        repo = GateRepo(CLEAN_PY)
        self.addCleanup(repo.close)
        r = Result("branch-protection", "")
        ci_hygiene.protection(Repo(repo.path), r, "o/r", None)
        self.assertEqual(r.status, "pass", [f.message for f in r.findings])


class Deps(Base):
    def test_node_without_lockfile_fails(self):
        pj = json.dumps({"name": "demo", "license": "MIT", "dependencies": {"left-pad": "^1.3.0"}})
        self.assertFails(dict(CLEAN_PY, **{"package.json": pj}), "deps", "no lockfile")

    def test_unpinned_requirement_is_warning(self):
        self.assertPasses(dict(CLEAN_PY, **{"requirements.txt": "requests\n"}), "deps", allow=("warn",))

    def test_audit_without_auditor_is_cannot_tell(self):
        home = tempfile.mkdtemp(prefix="repogate-home-")
        env = {"HOME": home, "USERPROFILE": home,
               "PATH": os.path.dirname(sys.executable) + os.pathsep + os.path.dirname(_git_exe())}
        code, out, data = self.run_gate(dict(CLEAN_PY, **{"requirements.txt": "requests==2.32.3\n"}), "--only", "deps",
                                        "--offline", env=env)
        self.assertEqual(code, 2, out)


class Security(Base):
    def test_proxy_forwards_incoming_headers_fails(self):
        code = ("import httpx\n\n\nasync def proxy(request):\n"
                "    return await httpx.AsyncClient().get('https://up.example', headers=dict(request.headers))\n")
        self.assertFails(dict(CLEAN_PY, **{"src/proxy.py": code}), "security", "SEC-5")

    def test_proxy_with_allowlist_passes(self):
        code = ("import httpx\nALLOWED = {'accept', 'content-type'}\n\n\nasync def proxy(request):\n"
                "    h = {k: v for k, v in request.headers.items() if k.lower() in ALLOWED}\n"
                "    return await httpx.AsyncClient().get('https://up.example', headers=h)\n")
        self.assertPasses(dict(CLEAN_PY, **{"src/proxy.py": code}), "security", allow=("pass",))

    def test_logged_key_fails(self):
        code = "import logging\nlog = logging.getLogger(__name__)\n\n\ndef issue(api_key):\n    log.info(f'issued {api_key}')\n"
        self.assertFails(dict(CLEAN_PY, **{"src/keys.py": code}), "security", "SEC-6")

    def test_logged_fingerprint_passes(self):
        code = ("import hashlib, logging\nlog = logging.getLogger(__name__)\n\n\ndef issue(api_key):\n"
                "    log.info('issued %s', hashlib.sha256(api_key.encode()).hexdigest()[:12])\n")
        self.assertPasses(dict(CLEAN_PY, **{"src/keys.py": code}), "security", allow=("pass",))

    def test_printing_a_verify_result_passes(self):
        # soulguard examples/quickstart.py, 2026-10-22 dry run: the verdict of verify_token, not a token
        code = ("from soul import issue_token, verify_token\n\n\ndef main(secret_bytes, tok):\n"
                "    ok = verify_token(secret_bytes, tok, 'memory:read')\n    print('grants ->', verify_token(secret_bytes, tok, 'x'))\n")
        self.assertPasses(dict(CLEAN_PY, **{"src/demo.py": code}), "security", allow=("pass",))

    def test_printing_a_generated_key_fails(self):
        code = "from keys import generate_api_key\n\n\ndef main():\n    print('key:', generate_api_key())\n"
        self.assertFails(dict(CLEAN_PY, **{"src/demo.py": code}), "security", "SEC-6")

    def test_secret_printed_in_examples_is_warning(self):
        code = "def main(secret):\n    print('recovered', secret)\n"
        self.assertPasses(dict(CLEAN_PY, **{"examples/basic.py": code}), "security", allow=("warn",))

    def test_secret_word_inside_an_id_or_counter_passes(self):
        # pantheon playbooks.py and cli.py, 2026-10-22 dry run
        code = ("import logging, click\nlogger = logging.getLogger(__name__)\n\n\ndef f(soulkey_id_str, tokens_today):\n"
                "    logger.info('quarantine.off', soulkey_id=soulkey_id_str)\n    click.echo(f'{tokens_today} issued')\n")
        self.assertPasses(dict(CLEAN_PY, **{"src/p.py": code}), "security", allow=("pass",))

    def test_secret_word_inside_a_js_string_passes(self):
        code = "export function f(err) {\n  console.error('[forgot-password] error:', err);\n}\n"
        self.assertPasses(dict(CLEAN_PY, **{"web/route.ts": code}), "security", allow=("pass",))

    def test_js_template_literal_secret_fails(self):
        code = "export function f(apiKey) {\n  console.log(`issued ${apiKey}`);\n}\n"
        self.assertFails(dict(CLEAN_PY, **{"web/keys.ts": code}), "security", "SEC-6")

    def test_auth_default_off_fails(self):
        code = "import os\nAUTH_ENABLED = os.getenv('AUTH_ENABLED', 'false') == 'true'\n"
        self.assertFails(dict(CLEAN_PY, **{"src/settings.py": code}), "security", "SEC-7")

    def test_untested_disable_auth_flag_fails(self):
        code = "import os\nDISABLE_AUTH = os.getenv('DISABLE_AUTH') == '1'\n"
        self.assertFails(dict(CLEAN_PY, **{"src/settings.py": code}), "security", "no test names it")

    def test_tested_disable_auth_flag_passes(self):
        code = "import os\nDISABLE_AUTH = os.getenv('DISABLE_AUTH') == '1'\n"
        test = "def test_auth_on_unless_disable_auth_set(monkeypatch):\n    monkeypatch.delenv('DISABLE_AUTH', raising=False)\n"
        self.assertPasses(dict(CLEAN_PY, **{"src/settings.py": code, "tests/test_auth.py": test}), "security")

    def test_installer_writes_claude_config_without_consent_fails(self):
        code = ("import json, os\n\n\ndef main():\n    path = os.path.expanduser('~/.claude/settings.json')\n"
                "    with open(path, 'w') as f:\n        json.dump({'mcp': 1}, f)\n")
        self.assertFails(dict(CLEAN_PY, **{"install.py": code}), "security", "SEC-8")

    def test_installer_with_consent_and_backup_is_warning(self):
        code = ("import json, os, shutil\n\n\ndef main():\n    path = os.path.expanduser('~/.claude/settings.json')\n"
                "    if input('Write MCP config? [y/N] ') != 'y':\n        return\n    shutil.copy2(path, path + '.bak')\n"
                "    with open(path, 'w') as f:\n        json.dump({'mcp': 1}, f)\n")
        self.assertPasses(dict(CLEAN_PY, **{"install.py": code}), "security", allow=("warn",))


class LogRedaction(Base):
    KEYGEN = "import secrets\n\n\ndef create_api_key():\n    api_key = secrets.token_urlsafe(32)\n    return api_key\n"

    def test_keygen_without_redaction_test_fails(self):
        self.assertFails(dict(CLEAN_PY, **{"src/keys.py": self.KEYGEN}), "log-redaction", "SEC-9")

    def test_keygen_with_redaction_test_passes(self):
        test = "def test_key_not_logged(caplog):\n    pass\n"
        self.assertPasses(dict(CLEAN_PY, **{"src/keys.py": self.KEYGEN, "tests/test_keys.py": test}), "log-redaction")


class Consistency(Base):
    def test_chain_is_warning_not_block(self):
        code = "def append(chain, entry):\n    entry['prev_hash'] = chain[-1]['hash']\n    chain.append(entry)\n"
        data = self.assertPasses(dict(CLEAN_PY, **{"src/chain.py": code}), "consistency", allow=("warn",))
        self.assertEqual(status_of(data, "consistency"), "warn")


class Docs(Base):
    def test_missing_llms_txt_fails(self):
        self.assertFails(CLEAN_PY, "docs", "llms.txt is missing", "--visibility", "public")

    def test_private_repo_is_na(self):
        self.assertPasses(CLEAN_PY, "docs", "--visibility", "private", allow=("n/a",))


class Mutation(Base):
    def test_tests_that_cannot_fail_fail(self):
        files = dict(CLEAN_PY, **{"tests/test_calc.py": "def test_add():\n    assert True\n",
                                  ".gate.toml": f'[mutation]\ntargets = ["src/calc.py"]\ntest-command = "{_py()} -m pytest -q"\n'})
        self.assertFails(files, "mutation", "no mutant of src/calc.py was caught")

    def test_tests_that_catch_mutants_pass(self):
        files = dict(CLEAN_PY, **{".gate.toml": f'[mutation]\ntargets = ["src/calc.py"]\ntest-command = "{_py()} -m pytest -q"\n',
                                  "src/__init__.py": ""})
        self.assertPasses(files, "mutation")


def _py() -> str:
    return sys.executable.replace("\\", "/")


class GateConfig(Base):
    def test_waiver_without_issue_fails(self):
        cfg = '[[waive]]\ncheck = "paths"\npath = "src/io.py"\nreason = "a long enough reason here"\nexpires = "2026-12-01"\n'
        code, out, data = self.run_gate(dict(CLEAN_PY, **{".gate.toml": cfg, "src/io.py": 'P = "D:/x/y"\n'}),
                                        "--only", "paths", "--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("issue must be a full GitHub issue", out)

    def test_valid_waiver_is_shown_and_passes(self):
        cfg = ('[[waive]]\ncheck = "paths"\npath = "src/io.py"\nreason = "Windows path-handling demo, see issue"\n'
               'issue = "https://github.com/o/r/issues/3"\nexpires = "2026-12-01"\n')
        code, out, data = self.run_gate(dict(CLEAN_PY, **{".gate.toml": cfg, "src/io.py": 'P = "D:/x/y"\n'}),
                                        "--only", "paths", "--offline")
        self.assertEqual(code, 0, out)
        self.assertIn("WAIVED", out)

    def test_secrets_cannot_be_waived(self):
        cfg = ('[[waive]]\ncheck = "secrets"\npath = "*"\nreason = "please let this one through"\n'
               'issue = "https://github.com/o/r/issues/3"\nexpires = "2026-12-01"\n')
        code, out, data = self.run_gate(dict(CLEAN_PY, **{".gate.toml": cfg}), "--only", "paths", "--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("cannot be waived", out)

    def test_unknown_config_section_fails(self):
        code, out, data = self.run_gate(dict(CLEAN_PY, **{".gate.toml": "[checks]\npaths = false\n"}), "--only", "paths",
                                        "--offline")
        self.assertEqual(code, 1, out)
        self.assertIn("unknown .gate.toml section", out)

    def test_baseline_file_does_not_republish_findings(self):
        # adoption PRs commit the baseline to public repos; it must not quote a path or host it found
        home = "/Users/" + "mkowalski"
        repo = GateRepo(dict(CLEAN_PY, **{"src/io.py": f'P = "{home}/data"\n'}))
        self.addCleanup(repo.close)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths", "--offline"],
                       cwd=ROOT, check=True, capture_output=True)
        text = (repo.path / ".gate-baseline.json").read_text(encoding="utf-8")
        self.assertNotIn("mkowalski", text)
        self.assertEqual(len(json.loads(text)["entries"]), 1)
        repo.commit("baseline")
        code, out, _ = repo.gate("--only", "paths", "--offline")
        self.assertEqual(code, 0, out)

    def test_a_check_that_did_not_run_cannot_call_an_entry_fixed(self):
        """THE FOURTEEN FALSE WARNINGS.

        merge-gate.yml gives every check its own job and runs `--only <check>`, so the
        findings in a baseline that belong to other checks are never loaded. Treating
        them as "fixed" told every consumer repo, on every run, that debt it still owed
        had been paid. The twin below is the case the warning exists for.
        """
        repo = GateRepo(dict(CLEAN_PY, **{"src/io.py": 'P = "D:/x/y"\n'}))
        self.addCleanup(repo.close)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths",
                        "--offline"], cwd=ROOT, check=True, capture_output=True)
        repo.commit("baseline")
        code, out, _ = repo.gate("--only", "control-chars", "--offline")
        self.assertEqual(code, 0, out)
        self.assertNotIn("fixed", out)

    def test_a_check_that_did_run_reports_its_debt_as_paid(self):
        """ANTI-VACUITY for the rule above: the warning must still fire for the one check
        that ran, or scoping it to the checks that ran would have silenced it entirely."""
        repo = GateRepo(dict(CLEAN_PY, **{"src/io.py": 'P = "D:/x/y"\n'}))
        self.addCleanup(repo.close)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths",
                        "--offline"], cwd=ROOT, check=True, capture_output=True)
        repo.commit("baseline")
        repo.write({"src/io.py": "P = 'relative/path'\n"})
        repo.commit("fix it")
        code, out, _ = repo.gate("--only", "paths", "--offline")
        self.assertEqual(code, 0, out)
        self.assertIn("1 baseline entry is fixed", out)

    def test_baseline_writes_one_entry_per_finding(self):
        """A finding's id is a hash of check|path|message, so the same defect written
        twice in one file hashes the same. The file used to carry it twice: the second
        copy was debt nothing could ever pay off, and it inflated every count."""
        repo = GateRepo(dict(CLEAN_PY, **{"src/io.py": 'P = "D:/x/y"\nQ = "D:/x/y"\n'}))
        self.addCleanup(repo.close)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths",
                        "--offline"], cwd=ROOT, check=True, capture_output=True)
        entries = json.loads((repo.path / ".gate-baseline.json").read_text(encoding="utf-8"))["entries"]
        self.assertEqual(len(entries), 1, entries)

    def test_baseline_absorbs_debt_and_may_only_shrink(self):
        files = dict(CLEAN_PY, **{"src/io.py": 'P = "D:/x/y"\n'})
        repo = GateRepo(files)
        self.addCleanup(repo.close)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths", "--offline"],
                       cwd=ROOT, check=True, capture_output=True)
        repo.commit("baseline")
        code, out, _ = repo.gate("--only", "paths", "--offline")
        self.assertEqual(code, 0, out)  # pre-existing debt does not block
        repo.write({"src/io2.py": 'Q = "E:/new/debt"\n'})
        repo.commit("new debt")
        code, out, _ = repo.gate("--only", "paths", "--offline")
        self.assertEqual(code, 1, out)  # new debt does block
        subprocess.run(["git", *GIT_ID, "-C", str(repo.path), "branch", "base", "HEAD~1"], check=True)
        subprocess.run([sys.executable, "-m", "gate", "baseline", "--repo", str(repo.path), "--only", "paths", "--offline"],
                       cwd=ROOT, check=True, capture_output=True)
        repo.commit("grow baseline")
        code, out, _ = repo.gate("--only", "paths", "--offline", "--base-ref", "base")
        self.assertEqual(code, 1, out)
        self.assertIn("the baseline grew", out)


if __name__ == "__main__":
    unittest.main()
