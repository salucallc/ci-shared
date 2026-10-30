# AGENTS.md

Instructions for AI coding agents working in this repository.

## What this is

Reusable GitHub Actions workflows (`on: workflow_call`) that other repos call by full commit SHA, plus two
standard-library Python helpers in `tools/`. It is not a library, an action or a service.

## Read in this order

1. `README.md`, "How it works" (the call graph) and the Reusable workflows table (every input).
2. The workflow you are changing, in `.github/workflows/`.
3. `.github/workflows/self-test.yml` and `self-validate.yml`: what proves a change works.
4. `tools/write_caller.py`, if the change affects what a consumer's `ci.yml` should contain.

## What you can and cannot see

- You can see every workflow, the fixtures they are tested on, and the helpers.
- You cannot see the consumer repos. Some are private. A change to an input breaks a consumer only
  when it re-pins to the new SHA, so nothing in this repo's CI will tell you.
- Only `reusable-python-ci.yml`, `reusable-node-ci.yml` and `repo-docs.yml` are run by this repo's
  CI (`self-test.yml`). The other reusable workflows are linted here but only run in consumers.

## The only numbers to trust

- Pinned tool versions: actionlint and yamllint in `.github/workflows/self-validate.yml`, gitleaks in
  `.github/workflows/repo-docs.yml`, bandit and semgrep for the merge gate in `gate/checks/sast.py`
  (the standalone `reusable-sast-python.yml` and `reusable-semgrep.yml` defaults must equal them; a
  test checks). Read them from those files, not from prose.
- Action pins: the `uses: ...@<sha>  # vX.Y.Z` lines in each workflow file.
- The list of workflows: `ls .github/workflows/`.

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
python -m pip install bandit==1.9.4 semgrep==1.160.0   # in the venv; the SAST tests run them (Windows: Docker for semgrep)
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
  `llms-full.txt` (the `llms.txt` header, then README.md and AGENTS.md, each under its path).
- No em-dashes in README.md, llms.txt or AGENTS.md (`repo-docs.yml` fails on them).

## Do not

- Pin anything by tag or branch, or widen `permissions` beyond what a job uses.
- Rename or remove an input without a note in the README: consumers pin SHAs and break silently on re-pin.
- Commit secrets, hostnames, internal paths or personal emails.
- Commit `__pycache__` or `.pyc` files.

## Done means

`Self-validate` and `Self-test` are green on the PR, and the README describes every input that changed.
