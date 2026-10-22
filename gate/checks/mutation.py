"""TST-5: "a test that cannot fail tests nothing" (verification rule 2). Opt-in mutation smoke.

A repo lists files in .gate.toml:

    [mutation]
    targets = ["src/chain.py"]
    test-command = "python -m pytest -q"
    install-command = "python -m pip install -e .[test]"   # optional, run first (CI has a clean runner)
    max-mutants = 8

For each target, the gate applies one small AST mutation at a time (flip a comparison, swap
and/or, flip a boolean constant, make a return return None), runs the test command, and restores
the file. A mutant the tests do not catch is a warning; a target where NO mutant is caught is
blocking: those tests would pass whatever the code did.
"""
from __future__ import annotations

import ast
import shlex
import subprocess
from pathlib import Path

from ..core import BLOCK, WARN, Repo, Result

FLIP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE, ast.LtE: ast.Gt,
        ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}


def _sites(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    out = []
    for node in ast.walk(tree):  # ast.walk order is deterministic for the same source
        if isinstance(node, ast.Compare) and type(node.ops[0]) in FLIP:
            out.append(("compare", node))
        elif isinstance(node, ast.BoolOp):
            out.append(("boolop", node))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            out.append(("bool", node))
        elif isinstance(node, ast.Return) and node.value is not None:
            out.append(("return", node))
    return out


def mutants(src: str, limit: int):
    count = len(_sites(ast.parse(src)))
    for i in range(min(count, limit)):
        t = ast.parse(src)  # a fresh tree per mutant, so mutations never stack
        kind, n = _sites(t)[i]
        if kind == "compare":
            n.ops[0] = FLIP[type(n.ops[0])]()
        elif kind == "boolop":
            n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
        elif kind == "bool":
            n.value = not n.value
        else:
            n.value = ast.Constant(value=None)
        yield f"{kind} at line {getattr(n, 'lineno', 0)}", ast.unparse(t)


def run(repo: Repo, opts) -> Result:
    r = Result("mutation", "Mutation smoke on declared targets: the tests can fail")
    cfg = repo.config.get("mutation") or {}
    targets = cfg.get("targets") or []
    if not targets:
        return r.na("no [mutation] targets in .gate.toml (opt-in; the PR checklist asks for a failing-first test instead)")
    if getattr(opts, "fast", False):
        return r.na("skipped in fast mode")
    cmd = shlex.split(cfg.get("test-command", "python -m pytest -q -x"))
    limit = int(cfg.get("max-mutants", 8))
    if cfg.get("install-command"):
        inst = subprocess.run(shlex.split(cfg["install-command"]), cwd=repo.root, capture_output=True, timeout=1800)
        if inst.returncode != 0:
            return r.cannot(f"install-command failed (exit {inst.returncode})")
    base = subprocess.run(cmd, cwd=repo.root, capture_output=True, timeout=900)
    if base.returncode != 0:
        return r.cannot(f"the test command fails on unmutated code (exit {base.returncode}); fix that first")
    for rel in targets:
        p = repo.root / rel
        if not p.is_file():
            r.add(BLOCK, f"TST-5: mutation target {rel} does not exist", rel, key=f"{rel}|missing")
            continue
        original = p.read_bytes()
        killed, survived = 0, []
        try:
            for label, code in mutants(original.decode("utf-8"), limit):
                p.write_text(code, encoding="utf-8", newline="\n")
                res = subprocess.run(cmd, cwd=repo.root, capture_output=True, timeout=900)
                if res.returncode != 0:
                    killed += 1
                else:
                    survived.append(label)
        finally:
            p.write_bytes(original)
        total = killed + len(survived)
        if total and killed == 0:
            r.add(BLOCK, f"TST-5: no mutant of {rel} was caught ({total} tried); these tests pass whatever the code does",
                  rel, key=f"{rel}|none-killed")
        for label in survived:
            r.add(WARN, f"TST-5: mutant survived ({label})", rel, key=f"{rel}|{label}")
        r.notes.append(f"{rel}: {killed}/{total} mutants caught")
    return r
