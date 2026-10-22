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


class Secrets(Base):
    @classmethod
    def setUpClass(cls):
        cls.env = {}
        if not os.environ.get("GATE_GITLEAKS"):
            exe = Path.home() / ".cache" / "saluca-gate" / "gitleaks-8.30.1" / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
            if exe.is_file():
                cls.env["GATE_GITLEAKS"] = str(exe)

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

    def test_committed_env_file_fails(self):
        self.assertFails(dict(CLEAN_PY, **{".env": "DEBUG=1\n"}), "secrets", "secrets file committed", env=self.env)

    def test_unreasoned_gitleaksignore_fails(self):
        self.assertFails(dict(CLEAN_PY, **{".gitleaksignore": "abc123:src/x.py:generic-api-key:3\n"}), "secrets",
                         ".gitleaksignore entry with no reason", env=self.env)

    def test_missing_gitleaks_is_cannot_tell(self):
        home = tempfile.mkdtemp(prefix="repogate-home-")
        env = {"GATE_GITLEAKS": str(Path(home) / "nope"), "HOME": home, "USERPROFILE": home,
               "PATH": os.path.dirname(sys.executable) + os.pathsep + os.path.dirname(_git_exe())}
        code, out, data = self.run_gate(CLEAN_PY, "--only", "secrets", "--offline", env=env)
        self.assertEqual(code, 2, out)
        self.assertEqual(status_of(data, "secrets"), "cannot-tell", out)

    def test_clean_repo_passes(self):
        self.assertPasses(CLEAN_PY, "secrets", env=self.env, allow=("pass",))


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

    def test_relative_paths_pass(self):
        self.assertPasses(dict(CLEAN_PY, **{"src/io.py": 'from pathlib import Path\nDATA = Path(__file__).parent / "data"\n'
                                                         'URL = "https://example.com/a:b"\n'}), "paths", allow=("pass",))


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
        note = "# Changelog\n\n- 2026-10-22: licence changed from MIT to Apache-2.0 (approved by the owner).\n"
        self.assertPasses(CLEAN_PY, "licence", extra=[{"LICENSE": APACHE, "README.md": readme, "CHANGELOG.md": note}])

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
