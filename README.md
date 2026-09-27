# salucallc/ci-shared

Reusable GitHub Actions workflows for [salucallc](https://github.com/salucallc) repositories. Derived from the `salucallc/gmail-mcp` CI template (Python + Docker security baseline) and generalized so multiple repos can adopt the same gates with a one-line `uses:` reference.

## Call surface

All workflows live in `.github/workflows/` and are invoked with `workflow_call`. Consuming repos reference them by SHA, not tag, to avoid tag-force-push supply-chain risk. Dependabot in this repo bumps pinned third-party action SHAs; consumers should run their own Dependabot to bump the pinned SHA of THIS repo they consume.

### Reusable workflows

| Workflow | Purpose | Key inputs |
|---|---|---|
| `reusable-lint-dockerfile.yml` | Hadolint Dockerfile lint | `dockerfile` (default `Dockerfile`), `failure-threshold` (default `warning`) |
| `reusable-dep-scan-python.yml` | pip-audit + safety CVE matrix | `requirements-file` (default `requirements.txt`), `python-version` (default `3.12`) |
| `reusable-sast-python.yml` | Bandit SAST | `target-paths` (default `.`), `severity-level` (default `medium`), `confidence-level` (default `medium`) |
| `reusable-semgrep.yml` | Semgrep OWASP/Python/secrets/CI rulepacks | `configs` (default set), `severity` (default `ERROR`), `semgrep-version` (default `1.160.0`) |
| `reusable-secret-scan.yml` | TruffleHog verified-only secret scan | `only-verified` (default `true`) |
| `reusable-build-smoke-docker.yml` | Buildx smoke build of a Dockerfile | `context`, `dockerfile`, `image-tag` |
| `reusable-image-cve-scan.yml` | Trivy scan of a locally built image | `image-ref`, `severity` (default `HIGH,CRITICAL`), `ignore-unfixed` (default `true`) |
| `reusable-release-on-tag.yml` | Release + changelog on `v*` tag push | `changelog-path` (default `CHANGELOG.md`) |
| `reusable-python-ci.yml` | Install (uv / poetry / pip, from the lockfile), `compileall`, `pytest` when tests exist | `python-version` (default `3.12`), `working-directory`, `install-command`, `compile-command`, `test-command`, `extra-packages`, `apt-packages` |
| `reusable-node-ci.yml` | Install (npm / pnpm / yarn, frozen lockfile), typecheck, build, test | `node-version` (default `22`), `working-directory`, `install-command`, `typecheck-command`, `build-command`, `test-command` |

The two stack workflows take `auto`, `skip` or a shell command for each step. `auto` detects from
the repo; `skip` logs that the step did not run. A step that found nothing to run says so with a
notice rather than passing silently. `self-test.yml` runs both against `fixtures/` on every PR.

### Adopting the stack CI (the estate's default)

```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  python:
    uses: salucallc/ci-shared/.github/workflows/reusable-python-ci.yml@<commit-sha>
  secret-scan:
    uses: salucallc/ci-shared/.github/workflows/reusable-secret-scan.yml@<commit-sha>
```

This repo is public, so private repos in both `salucallc` and `saluca-labs` can call it (a private
reusable workflow could only be shared inside its own org).

`tools/write_caller.py` writes that caller file for a repo (`--node DIR[:k=v,...]`, `--python DIR[:k=v,...]`, `--branch`, `--sha`); it refuses a SHA that is not a full 40-character commit.

`tools/ci_inventory.py` lists every repo in both orgs with its stack, workflows, default-branch CI
state and open dependency PRs (read-only, through `gh`).

## Example consumer workflow

```yaml
# .github/workflows/ci.yml in a consuming repo
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
permissions: read-all
jobs:
  lint-dockerfile:
    uses: salucallc/ci-shared/.github/workflows/reusable-lint-dockerfile.yml@<commit-sha>
  dep-scan:
    uses: salucallc/ci-shared/.github/workflows/reusable-dep-scan-python.yml@<commit-sha>
  sast:
    uses: salucallc/ci-shared/.github/workflows/reusable-sast-python.yml@<commit-sha>
  semgrep:
    uses: salucallc/ci-shared/.github/workflows/reusable-semgrep.yml@<commit-sha>
  secret-scan:
    uses: salucallc/ci-shared/.github/workflows/reusable-secret-scan.yml@<commit-sha>
  build-smoke:
    uses: salucallc/ci-shared/.github/workflows/reusable-build-smoke-docker.yml@<commit-sha>
  image-cve-scan:
    uses: salucallc/ci-shared/.github/workflows/reusable-image-cve-scan.yml@<commit-sha>
    needs: build-smoke
  ci-all:
    needs: [lint-dockerfile, dep-scan, sast, semgrep, secret-scan, build-smoke, image-cve-scan]
    runs-on: ubuntu-24.04
    steps:
      - run: echo "All required CI jobs succeeded."
```

Make `ci-all` the single required status check in branch protection; adding or renaming reusable workflows will not require touching branch protection.

## Pinning policy

- Third-party actions pinned to a **commit SHA**, never a tag.
- Pinned Python tools (e.g. `semgrep==1.160.0`) bumped in follow-up PRs alongside rulepack review.
- Dependabot configured for `github-actions` and `pip` ecosystems.

## Licensing

MIT. See `LICENSE`.
