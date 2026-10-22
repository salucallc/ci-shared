"""Run the merge gate in dry run over many clones and print a pass/fail matrix (read-only).

    python tools/gate_matrix.py --out DIR  owner/name=CLONE_DIR [owner/name=CLONE_DIR ...]

Each clone is judged exactly as CI would judge it (`python -m gate run --json`), with the slug
passed so the live checks (branch protection, visibility) read the right repo. Nothing is
written into the clones. DIR gets one <owner>__<name>.json per repo, matrix.json and matrix.md.
Exit 0 always: this is a measurement, not a gate.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHORT = {"pass": "pass", "warn": "warn", "fail": "FAIL", "cannot-tell": "CANNOT", "n/a": "n/a", "ci-only": "ci", "absent": "-"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--extra", default="", help="extra args for gate run, e.g. '--no-audit'")
    ap.add_argument("repos", nargs="+")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for spec in a.repos:
        slug, _, path = spec.partition("=")
        dest = out / (slug.replace("/", "__") + ".json")
        t0 = time.time()
        res = subprocess.run([sys.executable, "-m", "gate", "run", "--repo", path, "--repo-slug", slug, "--json", str(dest),
                              *a.extra.split()], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        data = json.loads(dest.read_text(encoding="utf-8")) if dest.exists() else {"checks": [], "exit": res.returncode}
        checks = {c["check"]: c for c in data["checks"]}
        rows.append({"repo": slug, "exit": res.returncode, "seconds": round(time.time() - t0),
                     "status": {k: v["status"] for k, v in checks.items()},
                     "blocking": {k: sum(1 for f in v["findings"] if f["severity"] == "block" and f["state"] == "open")
                                  for k, v in checks.items()},
                     "warnings": {k: sum(1 for f in v["findings"] if f["severity"] == "warn") for k, v in checks.items()}})
        print(f"{slug}: exit {res.returncode} ({rows[-1]['seconds']}s)", flush=True)
    names = []
    for r in rows:
        for k in r["status"]:
            if k not in names and k != "gate-config":
                names.append(k)
    (out / "matrix.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    lines = ["| repo | verdict | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    for r in rows:
        verdict = {0: "GREEN", 1: "RED", 2: "RED (cannot tell)"}.get(r["exit"], f"exit {r['exit']}")
        cells = []
        for k in names:
            st = r["status"].get(k, "absent")
            n = r["blocking"].get(k, 0)
            cells.append(SHORT.get(st, st) + (f" {n}" if st == "fail" and n else ""))
        lines.append(f"| {r['repo']} | {verdict} | " + " | ".join(cells) + " |")
    totals = ["| **repos failing** | | " + " | ".join(str(sum(1 for r in rows if r["status"].get(k) in ("fail", "cannot-tell")))
                                                for k in names) + " |"]
    (out / "matrix.md").write_text("\n".join(lines + totals) + "\n", encoding="utf-8")
    print("\n".join(lines + totals))
    return 0


if __name__ == "__main__":
    sys.exit(main())
