# Claims

Every capability that this repo's README, llms.txt, docs or marketing states, mapped to the code
that does it, where it is mounted, and the test that proves it. The merge gate checks every row
(CLM-1 to CLM-5): the claim text must appear in the source file, the code and test must exist,
the code must not be a stub, the mount point must contain the named text, and the test must not
be skipped. A capability that does not exist yet is `planned`, and its source says so next to it.
A withdrawn or changed claim carries a date and a correction note in the README.

| id | claim | source | status | code | wired | test | note |
|---|---|---|---|---|---|---|---|
| C1 | detects truncation of the audit chain | README.md | shipped | src/chain.py::verify | src/cli.py: verify( | tests/test_chain.py::test_truncation_detected | |
| C2 | forgets memories after 30 days | README.md | planned | | | | |
| C3 | does not read the message text | README.md | withdrawn | | | | 2026-10-22: it does read the text; see README Corrections |
