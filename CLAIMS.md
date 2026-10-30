# Claims

What this repo's README says the merge gate does, mapped to the code that does it, where it is
wired in, and the test that proves it. The merge gate's `claims` check reads this table on every
pull request (template: `examples/CLAIMS.md`). The reusable workflows' behaviour is proven by
`self-test.yml` runs rather than by rows here.

| id | claim | source | status | code | wired | test | note |
|---|---|---|---|---|---|---|---|
| C1 | finds a secret in any commit of any ref | README.md | shipped | gate/checks/secrets.py::run_gitleaks | gate/checks/secrets.py: run_gitleaks(repo, r) | gate/tests/test_gate.py::Secrets::test_secret_removed_later_still_fails_from_history | |
| C2 | a k8s Secret data: value that decodes to a real value | README.md | shipped | gate/checks/secrets.py::_k8s | gate/checks/secrets.py: yield from _k8s(text) | gate/tests/test_gate.py::Secrets::test_k8s_secret_base64_value_fails | |
| C3 | a database URL with a real password | README.md | shipped | gate/checks/secrets.py::judge_text | gate/checks/secrets.py: judge_text(path, text, "history") | gate/tests/test_gate.py::Secrets::test_dsn_password_in_env_example_fails | |
| C4 | a README install line names a package its registry does not have | README.md | shipped | gate/checks/packaging.py::lookup | gate/cli.py: "packaging": (packaging.run | gate/tests/test_gate.py::Packaging::test_unpublished_package_claim_fails | |
| C5 | whose code or test does not exist | README.md | shipped | gate/checks/claims.py::resolve | gate/checks/claims.py: sev, msg = resolve(repo, ref) | gate/tests/test_gate.py::Claims::test_broken_code_reference_fails | |
| C6 | whose mount point does not contain the named text | README.md | shipped | gate/checks/claims.py::resolve_wired | gate/checks/claims.py: resolve_wired(repo, row.get("wired", "")) | gate/tests/test_gate.py::Claims::test_not_mounted_fails | |
| C7 | proxy code forwards the incoming headers upstream | README.md | shipped | gate/checks/security.py::PyScan::visit_Call | gate/checks/security.py: py_scan(rel, text) | gate/tests/test_gate.py::Security::test_proxy_forwards_incoming_headers_fails | |
| C8 | a skip or xfail without a reason and an issue link | README.md | shipped | gate/checks/test_markers.py::judge | gate/checks/test_markers.py: judge(rel, text) | gate/tests/test_gate.py::TestMarkers::test_xfail_without_reason_fails | |
| C9 | is cannot-tell (exit 2), which fails the gate, never a pass | README.md | shipped | gate/cli.py::verdict | gate/cli.py: code = verdict(results) | gate/tests/test_gate.py::Secrets::test_missing_gitleaks_is_cannot_tell | |
| C10 | Secrets cannot be waived | README.md | shipped | gate/cli.py::waivers | gate/cli.py: ws = waivers(repo, cfg, today) | gate/tests/test_gate.py::GateConfig::test_secrets_cannot_be_waived | |
| C11 | on a pull request the baseline may only shrink | README.md | shipped | gate/cli.py::apply_baseline | gate/cli.py: apply_baseline(repo, results, cfg, a.base_ref) | gate/tests/test_gate.py::GateConfig::test_baseline_absorbs_debt_and_may_only_shrink | |
| C12 | no mutant of a declared target is caught | README.md | shipped | gate/checks/mutation.py::mutants | gate/checks/mutation.py: mutants(original.decode("utf-8"), limit) | gate/tests/test_gate.py::Mutation::test_tests_that_cannot_fail_fail | |
| C13 | A secret already in history does not block an unrelated push | README.md | shipped | gate/checks/secrets.py::sweep_change | gate/checks/secrets.py: run_gitleaks(repo, r, change=change, label=label) | gate/tests/test_gate.py::SecretsScope::test_secret_only_in_an_old_commit_does_not_block | |
| C14 | Touching the line of an old secret blocks | README.md | shipped | gate/checks/secrets_scope.py::blocks | gate/checks/secrets.py: if scope.blocks(rule, f, ln, added, base_fps): | gate/tests/test_gate.py::SecretsScope::test_touching_the_line_of_an_old_secret_blocks | |
| C15 | No base that resolves is cannot tell | README.md | shipped | gate/checks/secrets_scope.py::resolve_base | gate/checks/secrets.py: scope.resolve_base(repo, getattr(opts, "base_ref", None)) | gate/tests/test_gate.py::SecretsScope::test_no_resolvable_base_is_cannot_tell | |
| C16 | the same code, the same pins and the same baseline as a local run | README.md | shipped | gate/checks/sast.py::run_bandit | .github/workflows/merge-gate.yml: log-redaction, consistency, mutation, bandit, semgrep, branch-protection | gate/tests/test_gate.py::SastCiParity::test_merge_gate_runs_bandit_and_semgrep_through_the_gate | |
| C17 | Moving code keeps its baseline entry | README.md | shipped | gate/checks/sast.py::snippet_hash | gate/checks/sast.py: h = snippet_hash(repo, rel, int(min(rng)), int(max(rng))) | gate/tests/test_gate.py::Bandit::test_baselined_finding_does_not_block_and_survives_a_line_move | |
| C18 | editing a flagged line makes it a new finding, which blocks | README.md | shipped | gate/checks/sast.py::snippet_hash | gate/checks/sast.py: h = snippet_hash(repo, rel, start, end) | gate/tests/test_gate.py::Bandit::test_editing_a_baselined_line_makes_it_new | |
| C19 | Missing, wrong version, or unable to run is cannot tell | README.md | shipped | gate/checks/sast.py::bandit_command | gate/checks/sast.py: cmd, why = bandit_command() | gate/tests/test_gate.py::Bandit::test_missing_bandit_is_cannot_tell | |
| C20 | `gate baseline` refuses while any check it runs cannot tell | README.md | shipped | gate/cli.py::write_baseline | gate/cli.py: return write_baseline(repo, results, cfg, today) | gate/tests/test_gate.py::BaselineAdoption::test_baseline_is_refused_while_sast_cannot_run | |
| C21 | is measured per covered check | README.md | shipped | gate/cli.py::covered | gate/cli.py: old_cov = covered(old) | gate/tests/test_gate.py::BaselineAdoption::test_sast_entries_against_a_v2_base_are_adoption_not_growth | |
