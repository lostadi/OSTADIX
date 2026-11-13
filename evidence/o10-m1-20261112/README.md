# O10 M1 candidate evidence

This is an M1 implementation candidate on `work/o10-m1-20261112`, based on
`5fb254ae13c978ce2e6010bb3080c3d1c32caa5c`. Full M1 is **not qualified**.

The [current resident result](resident-r3/result.json) records an actual QEMU AArch64
run with 195 repeated Tstat pairs over 60.190170 seconds while Linux was
FAULTED and Plan 9 WITHDRAWN, with zero live guests. Plan 9 was then restored
under a higher generation, rebound, and its fresh original provider marker
validated. A new private state fork was used; the preserved source was not
changed or saved by this gate.

[Build request](build-r3/request.json), build status/output, and the captured
monitor manifest named in [summary.json](summary.json) identify the actual
qualification image. Production fault injection remains disabled by default.
The [unit result](unit-r3/result.json) contains 69 passing tests with no skips,
including actual native codec/journal/platform execution, classified resident
paths in 20 scenarios across production/qualification profiles in an explicit host register model, and four QEMU EL2 context tests.
These checks have their stated bounded scopes; they do not replace the full
same-build guest regression set.

The separate fresh bridge's environment, capabilities, doctor, runtimes and
kernel-owner help are retained here. Its executable was built at the base
revision from the M0 root; its runtime root is the dirty M1 worktree. This is
disclosed provenance, not a claim of a final aligned M1 release.

The candidate awaits independent source review, commit/release alignment and
the complete regression set. No merge, push, physical boot or physical-media
write was performed for M1.

The first two runs remain preserved at their original source snapshots. The
current r3 run includes the M0 shared legacy-restore generation/capacity fix
and lease-generation advance, and verifies every captured build source
remained byte-identical through recovery.

R4 is now frozen separately: [candidate receipt](r4-candidate.json). Its
69 focused tests pass without skips, including 76 resident native scenarios.
The fresh R4 ELF and runtime capture pass their source/inventory checks. The
R3 resident result above remains historical; R4 guest gates are pending and
full M1 remains unqualified.

Integration checkpoint: these historical R2–R5 probes remain unqualified and
precede the committed-source M1 release. The later codec bounds/parity guards
and final M0 inheritance require a fresh build, aligned MCP and complete M1
same-build acceptance. No historical candidate result qualifies that build.
