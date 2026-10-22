"""Run the merge gate from a ci-shared checkout against any repo, from any directory.

    python <ci-shared>/tools/gate.py run --repo <your repo>
    python <ci-shared>/tools/gate.py bootstrap        # once: pinned gitleaks + pip-audit venv

The same code CI runs (merge-gate.yml checks out this repo and calls `python -m gate`). Agents
run it before every push; a red gate is never pushed. Exit 0 green, 1 blocking finding, 2 cannot
tell. See `python tools/gate.py --help`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gate.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
