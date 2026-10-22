# AGENTS.md

Instructions for AI coding agents working in this repository.

## Setup

Nothing to install for the workflows. To lint locally, install yamllint 1.35.1
(`python -m pip install yamllint==1.35.1`) and actionlint 1.7.12 from its release page, checking the
SHA-256 against the release's checksums file. actionlint runs shellcheck on `run:` blocks when
shellcheck is on PATH; CI runners have it.

## Test

```sh
yamllint --strict -c .yamllint.yml .github/
actionlint
python tools/write_caller.py --help
python -m gate bootstrap --no-audit          # once: pinned gitleaks into ~/.cache/saluca-gate
python -m pip install pytest==9.1.1           # in a venv; the mutation fixtures run pytest
python -m unittest discover -s gate/tests -v  # the merge gate's own tests
python tools/gate.py run --repo .             # the gate on this repo
```

Passing: yamllint and actionlint print nothing and exit 0. On a PR, `Self-validate` (actionlint,
yamllint, `CI all`) and `Self-test` (Python fixture, Node fixture, repo-docs on this repo, the gate's unit
tests, and the merge gate on this repo) must be green.

## Conventions

- Reusable workflows are named `reusable-<what>.yml` with `name: Reusable - <What>` (`repo-docs.yml`
  keeps its shorter path because the docs standard's caller references it).
- Top-level `permissions: {}`; each job grants only what it needs (normally `contents: read`).
- Every third-party action is pinned to a full commit SHA with the version in a trailing comment
  (`uses: actions/checkout@<sha>  # v6.0.2`). Use the same pin as the other workflows.
- Release binaries fetched in a workflow (actionlint, gitleaks) are pinned by version and SHA-256 and
  downloaded to `${RUNNER_TEMP}`, not into the checkout.
- Inputs are kebab-case, have a `description`, `required: false` and a default, and every workflow
  takes `runs-on` (default `ubuntu-24.04`).
- `tools/` and `gate/` are Python standard library only (3.11+ for tomllib).
- Every gate check has a fixture in `gate/tests/test_gate.py` that must fail and one that must pass. A
  new check, or a new rule in one, adds both. Secret-shaped test strings are built at run time.
- Severities and caps are constants in the gate code. Never add a config key that lowers one. LF line endings (`.gitattributes`).
- When a workflow's inputs change, update the README table in the same PR, and regenerate
  `llms-full.txt` (the `llms.txt` header, then `## README.md` and the README text).
- No em-dashes in README.md, llms.txt or AGENTS.md (`repo-docs.yml` fails on them).

## Do not

- Pin anything by tag or branch, or widen `permissions` beyond what a job uses.
- Rename or remove an input without a note in the README: consumers pin SHAs and break silently on re-pin.
- Commit secrets, hostnames, internal paths or personal emails.
- Commit `__pycache__` or `.pyc` files.

## Done means

`Self-validate` and `Self-test` are green on the PR, and the README describes every input that changed.
